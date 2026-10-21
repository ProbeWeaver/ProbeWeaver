#!/usr/bin/env python3
"""Freeze full-fleet probes and the T1 -> T2 -> T3 identification artifact.

This builder is deliberately separate from the held-out evaluator.  The full
candidate library contributed responses to rule/RF construction, so these
predictions are valid *selection evidence* but are not accuracy evidence.  A
fresh end-to-end scan must evaluate the frozen output.

The script produces two ranked probe universes per transport:

``strict``
    Formal multi-probe plus target-reachability candidates.

``deployment-expanded``
    Strict plus exploratory candidates whose target and at least one claimed
    extra active cluster are stable in >=2/3 reprobes and whose stable response
    is correctly classified by the frozen cascade.  This is not called
    ``validated-expanded`` because candidate-specific held-out response
    evidence is unavailable for the construction library.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
import sys

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.candidate_stability import (  # noqa: E402
    candidate_identity_digest,
    load_stability_artifact,
)
from core.rule_bundle_provenance import (  # noqa: E402
    load_rule_bundle_provenance,
)
from core.rule_corpus import canonical_sha256, load_rule_corpus  # noqa: E402
from fingerprint.tier2_rf import load_tier2_rf_artifact  # noqa: E402
from scripts.evaluate_distinguishability import (  # noqa: E402
    GoCascadeHarness,
    _load_rules_json,
    _runtime_4form_rules,
)
from scripts.evaluate_e0_tier_cascade import (  # noqa: E402
    apply_tier_cascade,
    response_samples,
)
from scripts.select_packets import (  # noqa: E402
    CANDIDATE_ADMISSION_STRICT,
    CANDIDATE_ADMISSION_VALIDATED_EXPANDED,
    CANDIDATE_EXPLORATORY_MULTI_PROBE,
    CANDIDATE_MULTI_PROBE,
    CANDIDATE_TARGET_REACHABILITY,
    PacketSelector,
    _identification_coverage_report,
    compute_cluster_weights,
    load_censys_counts,
    load_nested_packets,
    weight_config_hash,
)
from services_config import cluster_of, identification_cluster_of  # noqa: E402


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "probeweaver_full_deployment_artifact"
K_GRID = (1, 2, 3, 5, 10, 15, 20)
STRICT_TYPES = frozenset({
    CANDIDATE_MULTI_PROBE,
    CANDIDATE_TARGET_REACHABILITY,
})


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2,
                      sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _atomic_jsonl(path: Path, rows: Iterable[Mapping]) -> tuple[int, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    count = 0
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(
                    row, ensure_ascii=False, sort_keys=True) + "\n")
                count += 1
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return count, _sha256_file(path)


def _load_candidate_records(path: str, transport: str) -> dict[str, dict]:
    records: dict[str, dict] = {}
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if str(record.get("transport") or "") != transport:
                raise ValueError(
                    f"candidate input {path} contains non-{transport} record")
            candidate_id = candidate_identity_digest(record)
            if candidate_id in records:
                raise ValueError(f"duplicate candidate identity {candidate_id}")
            records[candidate_id] = record
    if not records:
        raise ValueError(f"candidate input {path} is empty")
    return records


def _pseudo_stability(records: Mapping[str, Mapping], transport: str) -> dict:
    """Adapt one-shot candidate responses to response_samples()."""
    candidate_results = []
    for candidate_id, record in records.items():
        members = []
        for response in record.get("responses") or []:
            member = str(response.get("service") or "")
            if not member:
                continue
            members.append({
                "member": member,
                "cluster": cluster_of(member),
                "response_hex": str(response.get("response_hex") or ""),
                "banner_hex": str(response.get("banner_hex") or ""),
                "response_phase": str(
                    response.get("response_phase") or "legacy_unknown"),
            })
        candidate_results.append({
            "candidate_id": candidate_id,
            "identity": {
                "transport": transport,
                "mutation_target": str(
                    record.get("mutation_target") or ""),
                "candidate_type": str(
                    record.get("candidate_type") or CANDIDATE_MULTI_PROBE),
                "packet_hex": str(record.get("packet_hex") or ""),
            },
            "repetition_observations": [{"members": members}],
        })
    return {"candidate_results": candidate_results}


def _classify_samples(
    samples: list[dict],
    *,
    cluster_rules: Sequence[Mapping],
    model,
    encoder,
    rf_manifest: Mapping,
    zgrab_dir: str,
    go_bin: str,
    harness_timeout: float,
    chunk_size: int,
) -> tuple[list[dict], dict]:
    runtime_rules = _runtime_4form_rules(cluster_rules)
    work_dir = tempfile.mkdtemp(prefix="full_deployment_cascade_")
    try:
        rules_path = ""
        if runtime_rules:
            rules_file = Path(work_dir) / "rules_4form.json"
            rules_file.write_text(
                json.dumps(runtime_rules, sort_keys=True), encoding="utf-8")
            rules_path = str(rules_file)
        harness = GoCascadeHarness(
            go_bin, zgrab_dir, timeout=harness_timeout)
        if not harness.available():
            raise ValueError("Go cascade harness is unavailable")
        predictions = {}
        engine_meta = {}
        for start in range(0, len(samples), chunk_size):
            batch = samples[start:start + chunk_size]
            harness_samples = [{
                "key": sample["key"],
                "response": sample["response"],
            } for sample in batch]
            batch_predictions, meta, error = harness.run(
                harness_samples, rules_path, work_dir)
            if error:
                raise ValueError(error)
            predictions.update(batch_predictions)
            if meta:
                engine_meta = meta
        records = apply_tier_cascade(
            samples,
            predictions,
            model=model,
            encoder=encoder,
            threshold=float(
                rf_manifest["training_contract"]["deployment_threshold"]),
            feature_names=rf_manifest["feature_names"],
        )
        return records, engine_meta
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _pair_evidence(
    predictions: Sequence[Mapping],
    repetitions_required: int,
) -> dict[str, dict]:
    """Aggregate raw/correct pair evidence at candidate and phase levels."""
    raw_reps = defaultdict(lambda: defaultdict(set))
    correct_reps = defaultdict(lambda: defaultdict(set))
    outcome_counts = defaultdict(Counter)
    for row in predictions:
        candidate_id = str(row["candidate_id"])
        pair = (
            identification_cluster_of(str(row["truth"])),
            str(row["member"]),
        )
        phase = str(row["phase"])
        repetition = int(row.get("repetition", 0))
        raw_reps[candidate_id][(pair, phase)].add(repetition)
        if row.get("correct"):
            correct_reps[candidate_id][(pair, phase)].add(repetition)
            outcome = "correct"
        elif row.get("prediction"):
            outcome = "wrong"
        else:
            outcome = "unknown"
        outcome_counts[candidate_id][outcome] += 1
        outcome_counts[candidate_id][f"tier_{int(row.get('tier', 0))}"] += 1

    result = {}
    for candidate_id in set(raw_reps) | set(correct_reps):
        raw_observed, raw_active, raw_banner = set(), set(), set()
        correct_observed, correct_active, correct_banner = set(), set(), set()
        for (pair, phase), repetitions in raw_reps[candidate_id].items():
            if len(repetitions) < repetitions_required:
                continue
            raw_observed.add(pair)
            if phase == "post_payload":
                raw_active.add(pair)
            elif phase == "pre_payload_banner":
                raw_banner.add(pair)
        for (pair, phase), repetitions in correct_reps[candidate_id].items():
            if len(repetitions) < repetitions_required:
                continue
            correct_observed.add(pair)
            if phase == "post_payload":
                correct_active.add(pair)
            elif phase == "pre_payload_banner":
                correct_banner.add(pair)
        result[candidate_id] = {
            "raw_observed": raw_observed,
            "raw_active": raw_active,
            "raw_banner": raw_banner,
            "correct_observed": correct_observed,
            "correct_active": correct_active,
            "correct_banner": correct_banner,
            "outcomes": outcome_counts[candidate_id],
        }
    return result


def _eligible_exploratory(
    stability: Mapping,
    stable_evidence: Mapping[str, Mapping],
) -> tuple[set[str], dict[str, dict]]:
    eligible = set()
    decisions = {}
    for candidate in stability.get("candidate_results") or []:
        identity = candidate.get("identity") or {}
        if identity.get("candidate_type") != CANDIDATE_EXPLORATORY_MULTI_PROBE:
            continue
        candidate_id = str(candidate.get("candidate_id") or "")
        evidence = stable_evidence.get(candidate_id) or {}
        correctly_identified_extra = sorted(
            set(candidate.get("stable_extra_active_clusters") or ())
            & {cluster for cluster, _member in
               evidence.get("correct_active", set())}
        )
        passed = bool(
            candidate.get("target_stable") and correctly_identified_extra)
        if passed:
            eligible.add(candidate_id)
        decisions[candidate_id] = {
            "candidate_id": candidate_id,
            "packet_hex": identity.get("packet_hex", ""),
            "mutation_target": identity.get("mutation_target", ""),
            "target_stable": bool(candidate.get("target_stable")),
            "network_stable": bool(candidate.get("network_stable")),
            "stable_extra_active_clusters": sorted(
                candidate.get("stable_extra_active_clusters") or ()),
            "correctly_identified_stable_extra_clusters": (
                correctly_identified_extra),
            "deployment_expanded_eligible": passed,
        }
    return eligible, decisions


def _candidate_ids_by_packet(
    records: Mapping[str, Mapping],
    admitted_types: set[str],
    eligible_exploratory: set[str],
) -> dict[str, set[str]]:
    result = defaultdict(set)
    for candidate_id, record in records.items():
        candidate_type = str(
            record.get("candidate_type") or CANDIDATE_MULTI_PROBE)
        admitted = candidate_type in admitted_types
        if (candidate_type == CANDIDATE_EXPLORATORY_MULTI_PROBE
                and candidate_id in eligible_exploratory):
            admitted = True
        if admitted:
            result[str(record.get("packet_hex") or "").lower()].add(candidate_id)
    return result


def _annotate_packets(
    packets: list[dict],
    *,
    records: Mapping[str, Mapping],
    construction_evidence: Mapping[str, Mapping],
    stable_evidence: Mapping[str, Mapping],
    stability_candidates: Mapping[str, Mapping],
    eligible_exploratory: set[str],
    expanded: bool,
) -> list[dict]:
    admitted_types = set(STRICT_TYPES)
    ids_by_packet = _candidate_ids_by_packet(
        records,
        admitted_types,
        eligible_exploratory if expanded else set(),
    )
    annotated = []
    for packet in packets:
        packet_hex = packet["packet_hex"]
        candidate_ids = ids_by_packet.get(packet_hex, set())
        aggregate = {
            "raw_observed": set(), "raw_active": set(), "raw_banner": set(),
            "correct_observed": set(), "correct_active": set(),
            "correct_banner": set(), "outcomes": Counter(),
        }
        stable_ids, single_ids = [], []
        for candidate_id in sorted(candidate_ids):
            if candidate_id in stable_evidence:
                evidence = stable_evidence[candidate_id]
                stable_ids.append(candidate_id)
            else:
                evidence = construction_evidence.get(candidate_id) or {}
                single_ids.append(candidate_id)
            for key in (
                    "raw_observed", "raw_active", "raw_banner",
                    "correct_observed", "correct_active", "correct_banner"):
                aggregate[key].update(evidence.get(key, set()))
            aggregate["outcomes"].update(evidence.get("outcomes") or {})
        if not aggregate["raw_observed"]:
            continue
        packet["pairs"] = aggregate["raw_observed"]
        packet["observed_pairs"] = aggregate["raw_observed"]
        packet["active_pairs"] = aggregate["raw_active"]
        packet["banner_pairs"] = aggregate["raw_banner"]
        packet["identifiable_pairs"] = aggregate["correct_observed"]
        packet["identifiable_observed_pairs"] = aggregate["correct_observed"]
        packet["identifiable_active_pairs"] = aggregate["correct_active"]
        packet["banner_identifiable_pairs"] = aggregate["correct_banner"]
        packet["exact_identifiable_pairs"] = aggregate["correct_observed"]
        packet["ambiguous_identifiable_pairs"] = set()
        packet["effective_pairs"] = aggregate["correct_observed"]
        packet["member_code_pairs"] = set()
        packet["response_outcome_counts"] = aggregate["outcomes"]
        packet["selection_evidence"] = {
            "candidate_ids": sorted(candidate_ids),
            "stable_2_of_3_candidate_ids": stable_ids,
            "single_observation_candidate_ids": single_ids,
            "has_single_observation_fallback": bool(single_ids),
        }
        annotated.append(packet)
    return annotated


def _selection_result(
    packets: list[dict],
    *,
    counts: Mapping[str, int],
    alpha: float,
    gamma: float,
    k: int,
    min_new_coverage: float,
    objective: str,
    quota: int,
    transport: str,
    admission: str,
) -> dict:
    universe_by_cluster = defaultdict(set)
    for packet in packets:
        for cluster, member in packet["pairs"]:
            universe_by_cluster[cluster].add(member)
    weights = compute_cluster_weights(
        set(universe_by_cluster), prevalence_alpha=alpha, counts=counts)
    selector = PacketSelector(
        packets,
        weights,
        {cluster: len(members)
         for cluster, members in universe_by_cluster.items()},
        gamma=gamma,
        objective=objective,
        quota=quota,
        distinguishability_mode="rule-confirmed",
    )
    selected = selector.select(k=k, min_new_coverage=min_new_coverage)
    packets_by_hex = {packet["packet_hex"]: packet for packet in packets}
    for selected_packet in selected:
        evidence = packets_by_hex[selected_packet["packet_hex"]].get(
            "selection_evidence") or {}
        selected_packet["selection_evidence"] = evidence
    coverage = selector.coverage_report(selected)
    coverage["identification_coverage"] = _identification_coverage_report(
        packets, selected, weights)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "probeweaver_rule_confirmed_probe_selection",
        "transport": transport,
        "candidate_admission": admission,
        "evidence_scope": "construction_aware_deployment_selection",
        "accuracy_claim_allowed": False,
        "parameters": {
            "k": k,
            "alpha": alpha,
            "gamma": gamma,
            "objective": objective,
            "quota": quota,
            "min_new_coverage": min_new_coverage,
        },
        "cluster_weights": weights,
        "coverage": coverage,
        "selected_packets": selected,
    }


def _write_prefixes(
    output_dir: Path,
    selection: Mapping,
    mode: str,
) -> list[dict]:
    written = []
    transport = str(selection["transport"])
    selected = list(selection["selected_packets"])
    for requested_k in K_GRID:
        prefix = selected[:requested_k]
        payload = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": "probeweaver_scanner_probe_prefix",
            "transport": transport,
            "selection_mode": mode,
            "evidence_scope": selection["evidence_scope"],
            "accuracy_claim_allowed": False,
            "parameters": dict(selection["parameters"], k=requested_k),
            "actual_selected_packets": len(prefix),
            "selected_packets": prefix,
        }
        path = output_dir / (
            f"selected_packets_{mode}_lex_k{requested_k}_{transport}.json")
        _atomic_json(path, payload)
        written.append({
            "path": str(path.resolve()),
            "sha256": _sha256_file(path),
            "requested_k": requested_k,
            "actual_k": len(prefix),
        })
    return written


def _copy_frozen_artifacts(args: argparse.Namespace, output: Path) -> list[dict]:
    destinations = {
        "rules/code_rules.json": args.cluster_rules,
        "rules/rule_bundle_provenance.json": args.rule_bundle,
        "rules/code_rules.go": str(
            Path(args.zgrab_dir) / "lib/fingerprint/code_rules.go"),
        "rules/member_code_rules.go": str(
            Path(args.zgrab_dir) / "lib/fingerprint/member_code_rules.go"),
        "rules/rule_engine.go": str(
            Path(args.zgrab_dir) / "lib/fingerprint/rule_engine.go"),
        "random_forest/fingerprint_model.joblib": str(
            Path(args.rf_manifest).parent / "fingerprint_model.joblib"),
        "random_forest/label_encoder.joblib": str(
            Path(args.rf_manifest).parent / "label_encoder.joblib"),
        "random_forest/training_meta.json": args.rf_manifest,
        "random_forest/fingerprint_model.go": str(
            Path(args.zgrab_dir) / "lib/fingerprint/fingerprint_model.go"),
    }
    files = []
    for relative, source in destinations.items():
        source_path = Path(source)
        if not source_path.is_file():
            raise ValueError(f"required frozen artifact missing: {source_path}")
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)
        files.append({
            "path": relative,
            "source": str(source_path.resolve()),
            "size": destination.stat().st_size,
            "sha256": _sha256_file(destination),
        })
    return files


def run(args: argparse.Namespace) -> dict:
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    cluster_rules = _load_rules_json(args.cluster_rules)
    rule_bundle = load_rule_bundle_provenance(
        args.rule_bundle,
        cluster_rules_path=args.cluster_rules,
        member_rules_path=None,
        corpus_path=args.rule_corpus,
        corpus_provenance_path=args.rule_corpus_provenance,
        agent_state_paths=args.agent_state,
        zgrab_dir=args.zgrab_dir,
    )
    _atoms, corpus_provenance = load_rule_corpus(
        args.rule_corpus, args.rule_corpus_provenance)
    rf_manifest, model, encoder = load_tier2_rf_artifact(args.rf_manifest)
    if (rule_bundle["corpus"]["objective_version"]
            != corpus_provenance["objective_version"]):
        raise ValueError("rule bundle/corpus objective mismatch")

    counts = load_censys_counts(args.censys_summary or None)
    transports = {
        "tcp": (args.tcp_candidates, args.tcp_stability),
        "udp": (args.udp_candidates, args.udp_stability),
    }
    transport_results = {}
    for transport, (candidate_path, stability_path) in transports.items():
        records = _load_candidate_records(candidate_path, transport)
        construction_samples = response_samples(
            _pseudo_stability(records, transport), transport)
        construction_predictions, engine_meta = _classify_samples(
            construction_samples,
            cluster_rules=cluster_rules,
            model=model,
            encoder=encoder,
            rf_manifest=rf_manifest,
            zgrab_dir=args.zgrab_dir,
            go_bin=args.go_bin,
            harness_timeout=args.harness_timeout,
            chunk_size=args.chunk_size,
        )
        prediction_dir = output / "classification" / transport
        construction_path = prediction_dir / "construction_predictions.jsonl"
        construction_count, construction_sha = _atomic_jsonl(
            construction_path, construction_predictions)
        construction_evidence = _pair_evidence(
            construction_predictions, repetitions_required=1)

        stability = load_stability_artifact(stability_path)
        stability_samples = response_samples(stability, transport)
        stability_predictions, stability_engine_meta = _classify_samples(
            stability_samples,
            cluster_rules=cluster_rules,
            model=model,
            encoder=encoder,
            rf_manifest=rf_manifest,
            zgrab_dir=args.zgrab_dir,
            go_bin=args.go_bin,
            harness_timeout=args.harness_timeout,
            chunk_size=args.chunk_size,
        )
        stability_prediction_path = (
            prediction_dir / "stability_predictions.jsonl")
        stability_count, stability_sha = _atomic_jsonl(
            stability_prediction_path, stability_predictions)
        stable_evidence = _pair_evidence(
            stability_predictions, repetitions_required=2)
        stability_candidates = {
            str(candidate.get("candidate_id") or ""): candidate
            for candidate in stability.get("candidate_results") or []
        }
        eligible, promotion_decisions = _eligible_exploratory(
            stability, stable_evidence)
        promotion_path = output / "promotion" / (
            f"deployment_expanded_{transport}.json")
        _atomic_json(promotion_path, {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": "probeweaver_deployment_exploratory_promotion",
            "transport": transport,
            "claim_scope": "deployment_selection_only",
            "formal_validated_exploratory": False,
            "reason": (
                "network stability and frozen-cascade correctness are checked, "
                "but candidate-specific responses are construction evidence, "
                "not held-out eval evidence"),
            "eligible_count": len(eligible),
            "candidate_results": [
                promotion_decisions[key]
                for key in sorted(promotion_decisions)],
        })

        strict_packets = load_nested_packets(
            [candidate_path], candidate_admission=CANDIDATE_ADMISSION_STRICT)
        strict_packets = _annotate_packets(
            strict_packets,
            records=records,
            construction_evidence=construction_evidence,
            stable_evidence=stable_evidence,
            stability_candidates=stability_candidates,
            eligible_exploratory=set(),
            expanded=False,
        )
        expanded_packets = load_nested_packets(
            [candidate_path],
            candidate_admission=CANDIDATE_ADMISSION_VALIDATED_EXPANDED,
            validated_exploratory_ids=eligible,
        )
        expanded_packets = _annotate_packets(
            expanded_packets,
            records=records,
            construction_evidence=construction_evidence,
            stable_evidence=stable_evidence,
            stability_candidates=stability_candidates,
            eligible_exploratory=eligible,
            expanded=True,
        )

        selections = {}
        for mode, packets in (
                ("strict", strict_packets),
                ("deployment_expanded", expanded_packets)):
            selection = _selection_result(
                packets,
                counts=counts,
                alpha=args.alpha,
                gamma=args.gamma,
                k=args.k,
                min_new_coverage=args.min_new_coverage,
                objective=args.objective,
                quota=args.quota,
                transport=transport,
                admission=mode,
            )
            selection_path = output / "selection" / (
                f"selection_{mode}_{transport}.json")
            _atomic_json(selection_path, selection)
            prefixes = _write_prefixes(
                output / "scanner_inputs", selection, mode)
            selections[mode] = {
                "path": str(selection_path),
                "sha256": _sha256_file(selection_path),
                "candidate_count": len(packets),
                "selected_count": len(selection["selected_packets"]),
                "prefixes": prefixes,
                "final_identification_coverage": (
                    selection["coverage"]["identification_coverage"]["final"]),
            }

        transport_results[transport] = {
            "candidate_input": {
                "path": str(Path(candidate_path).resolve()),
                "sha256": _sha256_file(candidate_path),
                "records": len(records),
            },
            "stability_input": {
                "path": str(Path(stability_path).resolve()),
                "artifact_hash": stability["artifact_hash"],
                "sha256": _sha256_file(stability_path),
                "candidate_results": len(stability_candidates),
            },
            "construction_predictions": {
                "path": str(construction_path),
                "count": construction_count,
                "sha256": construction_sha,
            },
            "stability_predictions": {
                "path": str(stability_prediction_path),
                "count": stability_count,
                "sha256": stability_sha,
            },
            "engine_meta": engine_meta,
            "stability_engine_meta": stability_engine_meta,
            "deployment_expanded_eligible": len(eligible),
            "selections": selections,
        }

    copied_files = _copy_frozen_artifacts(args, output)
    git_commit = os.popen(
        f"git -C {str(ROOT)!r} rev-parse HEAD").read().strip()
    core = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "claim_scope": "artifact_construction_and_deployment_selection",
        "selection_evidence": "construction_aware",
        "accuracy_claim_allowed": False,
        "required_accuracy_evidence": (
            "fresh end-to-end network scans after this bundle is frozen"),
        "git_commit": git_commit,
        "objective_version": rule_bundle["corpus"]["objective_version"],
        "rule_bundle_artifact_hash": rule_bundle["artifact_hash"],
        "rules_digest": rule_bundle["rules"]["digest"],
        "runtime_registry_digest": rule_bundle["runtime"]["digest"],
        "rf_artifact_hash": rf_manifest["artifact_hash"],
        "rf_corpus_digest": rf_manifest["corpus"]["corpus_digest"],
        "weight_config_hash": weight_config_hash(
            prevalence_alpha=args.alpha, counts=counts),
        "selection_parameters": {
            "k_grid": list(K_GRID),
            "k_max": args.k,
            "alpha": args.alpha,
            "gamma": args.gamma,
            "objective": args.objective,
            "quota": args.quota,
            "min_new_coverage": args.min_new_coverage,
        },
        "transports": transport_results,
        "frozen_files": copied_files,
    }
    manifest = dict(core)
    manifest["artifact_hash"] = canonical_sha256(core)
    manifest["created_at"] = datetime.now(
        timezone.utc).isoformat(timespec="seconds")
    _atomic_json(output / "artifact_manifest.json", manifest)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tcp-candidates", required=True)
    parser.add_argument("--udp-candidates", required=True)
    parser.add_argument("--tcp-stability", required=True)
    parser.add_argument("--udp-stability", required=True)
    parser.add_argument("--cluster-rules", required=True)
    parser.add_argument("--rule-bundle", required=True)
    parser.add_argument("--rule-corpus", required=True)
    parser.add_argument("--rule-corpus-provenance", required=True)
    parser.add_argument("--agent-state", action="append", required=True)
    parser.add_argument("--rf-manifest", required=True)
    parser.add_argument("--zgrab-dir", default=str(ROOT / "PW_Scanner"))
    parser.add_argument("--go-bin", default="go")
    parser.add_argument("--harness-timeout", type=float, default=600.0)
    parser.add_argument("--chunk-size", type=int, default=2000)
    parser.add_argument("--censys-summary", default=str(
        ROOT / "data/service_counts.txt"))
    parser.add_argument("--alpha", type=float, default=0.7)
    parser.add_argument("--gamma", type=float, default=1.0)
    parser.add_argument("--objective", choices=(
        "weighted", "lexicographic", "quota"), default="lexicographic")
    parser.add_argument("--quota", type=int, default=1)
    parser.add_argument("--min-new-coverage", type=float, default=0.0)
    parser.add_argument("-k", type=int, default=20)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = run(args)
    except (OSError, ValueError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "artifact_hash": manifest["artifact_hash"],
        "output": str(Path(args.output).resolve()),
        "transports": {
            transport: {
                mode: data["selected_count"]
                for mode, data in result["selections"].items()
            }
            for transport, result in manifest["transports"].items()
        },
    }, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
