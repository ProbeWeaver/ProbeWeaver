#!/usr/bin/env python3
"""Evaluate the complete Tier-1 rules -> Tier-2 RF -> Tier-3 cascade on E0.

The response source must be a fresh candidate-stability artifact.  Tier-1 and
Tier-3 decisions come from the same Go harness used by the scanner; Python
only inserts the trained RF when the harness reports no Tier-1 match.  The
manifest binds the rule validation round, RF artifact, construction corpora,
runtime registry and every emitted prediction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Optional

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.candidate_stability import load_stability_artifact  # noqa: E402
from core.rule_bundle_provenance import (  # noqa: E402
    load_rule_bundle_provenance,
)
from core.rule_corpus import (  # noqa: E402
    canonical_sha256,
    load_rule_corpus,
    packet_identity,
    probe_family_identity,
)
from core.rule_validation import load_rule_validation_round  # noqa: E402
from fingerprint.feature_extractor import ResponseFeatureExtractor  # noqa: E402
from fingerprint.tier2_rf import load_tier2_rf_artifact  # noqa: E402
from scripts.evaluate_distinguishability import (  # noqa: E402
    GoCascadeHarness,
    _load_rules_json,
    _runtime_4form_rules,
)
from services_config import cluster_of, identification_cluster_of  # noqa: E402


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "e0_full_identification_cascade_evaluation"


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2,
                      sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def _atomic_jsonl(path: Path, records: Iterable[Mapping]) -> tuple[int, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    count = 0
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(
                    record, ensure_ascii=False, sort_keys=True) + "\n")
                count += 1
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
    return count, _sha256_file(path)


def response_samples(stability: Mapping, transport: str) -> list[dict]:
    """Expand phase-aware repetitions into one sample per response fact."""
    samples: list[dict] = []
    sequence = 0
    for candidate in stability.get("candidate_results", []):
        identity = candidate.get("identity") or {}
        if identity.get("transport") != transport:
            continue
        packet_hex = str(identity.get("packet_hex") or "")
        for repetition_index, repetition in enumerate(
                candidate.get("repetition_observations") or []):
            for observation in repetition.get("members") or []:
                member = str(observation.get("member") or "")
                truth = identification_cluster_of(cluster_of(member))
                response_hex = str(observation.get("response_hex") or "")
                banner_hex = str(observation.get("banner_hex") or "")
                declared_phase = str(
                    observation.get("response_phase") or "")
                facts: list[tuple[str, str]] = []
                banner_is_response = (
                    declared_phase == "pre_payload_banner"
                    and bool(response_hex) and response_hex == banner_hex)
                if banner_hex and not banner_is_response:
                    facts.append(("pre_payload_banner", banner_hex))
                if response_hex:
                    facts.append((
                        "pre_payload_banner" if banner_is_response
                        else "post_payload",
                        response_hex,
                    ))
                for phase, fact_hex in facts:
                    try:
                        response = bytes.fromhex(fact_hex)
                        bytes.fromhex(packet_hex)
                    except ValueError as exc:
                        raise ValueError(
                            "E0 stability artifact contains invalid hex") from exc
                    if not response:
                        continue
                    samples.append({
                        "key": f"e0-{sequence}",
                        "candidate_id": candidate.get("candidate_id", ""),
                        "transport": transport,
                        "packet_hex": packet_hex,
                        "request_hex": packet_hex,
                        "response_hex": fact_hex,
                        "response": response,
                        "member": member,
                        "truth": truth,
                        "phase": phase,
                        "repetition": repetition_index,
                    })
                    sequence += 1
    if not samples:
        raise ValueError(f"stability artifact has no {transport} response facts")
    return samples


def apply_tier_cascade(
    samples: list[dict],
    harness_predictions: Mapping[str, Mapping],
    *,
    model,
    encoder,
    threshold: float,
    feature_names: Optional[list[str]] = None,
) -> list[dict]:
    """Apply scanner ordering without duplicating Tier-1/Tier-3 rule logic."""
    extractor = ResponseFeatureExtractor()
    extracted = [extractor.extract(
        sample["response_hex"], sample["request_hex"]) for sample in samples]
    expected_names = feature_names or list(extracted[0])
    if list(extracted[0]) != list(expected_names):
        raise ValueError("runtime feature schema differs from RF manifest")
    feature_rows = [[features[name] for name in expected_names]
                    for features in extracted]
    probabilities = model.predict_proba(np.asarray(feature_rows, dtype=float))
    rf_indices = probabilities.argmax(axis=1)
    records = []
    for index, sample in enumerate(samples):
        go_result = dict(harness_predictions.get(sample["key"]) or {})
        go_tier = int(go_result.get("tier", 0) or 0)
        go_prediction = identification_cluster_of(
            str(go_result.get("pred") or ""))
        confidence = float(probabilities[index, rf_indices[index]])
        rf_prediction = identification_cluster_of(str(
            encoder.inverse_transform([rf_indices[index]])[0]))
        if go_tier == 1 and go_prediction:
            prediction, tier, source = go_prediction, 1, str(
                go_result.get("source") or "rule")
        elif confidence >= threshold:
            prediction, tier, source = rf_prediction, 2, "random_forest"
        elif go_tier == 3 and go_prediction:
            prediction, tier, source = go_prediction, 3, str(
                go_result.get("source") or "baseline")
        else:
            prediction, tier, source = "", 0, "unknown"
        records.append({
            "key": sample["key"],
            "candidate_id": sample["candidate_id"],
            "transport": sample["transport"],
            "member": sample["member"],
            "truth": sample["truth"],
            "phase": sample["phase"],
            "repetition": sample["repetition"],
            "packet_identity": packet_identity(sample["packet_hex"]),
            "response_sha256": hashlib.sha256(sample["response"]).hexdigest(),
            "prediction": prediction,
            "correct": prediction == sample["truth"],
            "tier": tier,
            "source": source,
            "rf_prediction": rf_prediction,
            "rf_confidence": confidence,
            "go_prediction": go_prediction,
            "go_tier": go_tier,
        })
    return records


def _metric_view(records: list[dict]) -> dict:
    count = len(records)
    identified = [record for record in records if record["prediction"]]
    correct = [record for record in records if record["correct"]]
    by_truth: dict[str, Counter] = defaultdict(Counter)
    for record in records:
        by_truth[record["truth"]][record["prediction"] or "unknown"] += 1
    tier_metrics = {}
    for tier in sorted({record["tier"] for record in records}):
        tier_records = [record for record in records if record["tier"] == tier]
        tier_metrics[str(tier)] = {
            "samples": len(tier_records),
            "correct": sum(record["correct"] for record in tier_records),
            "accuracy": (
                sum(record["correct"] for record in tier_records)
                / len(tier_records) if tier_records else None),
        }
    return {
        "samples": count,
        "identified": len(identified),
        "correct": len(correct),
        "coverage": len(identified) / count if count else 0.0,
        "accuracy_over_all": len(correct) / count if count else 0.0,
        "accuracy_when_identified": (
            sum(record["correct"] for record in identified) / len(identified)
            if identified else None),
        "tier_counts": dict(sorted(Counter(
            str(record["tier"]) for record in records).items())),
        "per_tier": tier_metrics,
        "phase_counts": dict(sorted(Counter(
            record["phase"] for record in records).items())),
        "per_truth_confusion": {
            truth: dict(sorted(predictions.items()))
            for truth, predictions in sorted(by_truth.items())
        },
    }


def _metrics(records: list[dict]) -> dict:
    unique = {}
    for record in records:
        identity = (
            record["transport"], record["truth"], record["member"],
            record["response_sha256"],
        )
        unique.setdefault(identity, record)

    pair_groups: dict[tuple, list[dict]] = defaultdict(list)
    for record in records:
        pair_groups[(record["candidate_id"], record["truth"])].append(record)
    pair_records = []
    for (candidate_id, truth), facts in sorted(pair_groups.items()):
        correct = any(fact["prediction"] == truth for fact in facts)
        identified = any(fact["prediction"] for fact in facts)
        pair_records.append({
            "candidate_id": candidate_id,
            "truth": truth,
            "identified": identified,
            "correct": correct,
        })
    pair_count = len(pair_records)
    pair_identified = sum(record["identified"] for record in pair_records)
    pair_correct = sum(record["correct"] for record in pair_records)
    return {
        "primary_unit": "unique_response_identity",
        "response_identity_definition": (
            "transport,canonical_truth_cluster,member,response_bytes"),
        "unique_response_identity": _metric_view(list(unique.values())),
        "observation_weighted": _metric_view(records),
        "candidate_truth_pair": {
            "pairs": pair_count,
            "identified": pair_identified,
            "correctly_identified": pair_correct,
            "coverage": pair_identified / pair_count if pair_count else 0.0,
            "correct_coverage": pair_correct / pair_count if pair_count else 0.0,
            "success_definition": (
                "at least one response fact from the candidate/truth pair is "
                "classified as the canonical truth cluster"),
        },
    }


def _rf_disjointness(atoms: list[Mapping], stability: Mapping,
                     transport: str) -> dict:
    construction_packets = {atom["packet_identity"] for atom in atoms}
    construction_families = {atom["probe_family_identity"] for atom in atoms}
    lineage_complete = all(
        atom.get("probe_family_basis") == "lineage" for atom in atoms)
    challenge_packets = set()
    challenge_families = set()
    for result in stability.get("candidate_results", []):
        identity = result.get("identity") or {}
        if identity.get("transport") != transport:
            continue
        source = result.get("source") or {}
        packet_hex = str(identity.get("packet_hex") or "")
        challenge_packets.add(packet_identity(packet_hex))
        family, basis = probe_family_identity(
            transport=transport,
            mutation_target=str(identity.get("mutation_target") or ""),
            parent_seed_id=str(source.get("parent_seed_id") or ""),
            parent_packet_hash=str(source.get("parent_packet_hash") or ""),
            packet_hex=packet_hex,
        )
        if basis != "lineage":
            raise ValueError("E0 challenge lacks parent probe-family lineage")
        challenge_families.add(family)
    packet_overlap = construction_packets & challenge_packets
    family_overlap = construction_families & challenge_families
    if packet_overlap or family_overlap:
        raise ValueError(
            "RF E0 challenge overlaps RF construction: "
            f"packets={len(packet_overlap)} families={len(family_overlap)}")
    return {
        "packet_overlap_count": 0,
        "probe_family_overlap_count": 0,
        "rf_construction_lineage_complete": lineage_complete,
        "held_out_status": (
            "packet_and_probe_family_disjoint"
            if lineage_complete else
            "packet_disjoint_and_known_families_disjoint_legacy_lineage_partial"),
    }


def evaluate(args: argparse.Namespace) -> dict:
    cluster_rules = _load_rules_json(args.cluster_rules)
    member_rules = _load_rules_json(args.member_rules)
    bundle = load_rule_bundle_provenance(
        args.rule_bundle,
        cluster_rules_path=args.cluster_rules,
        member_rules_path=args.member_rules,
        corpus_path=args.rule_corpus,
        corpus_provenance_path=args.rule_corpus_provenance,
        agent_state_paths=args.agent_state,
        zgrab_dir=args.zgrab_dir,
    )
    rule_atoms, rule_provenance = load_rule_corpus(
        args.rule_corpus, args.rule_corpus_provenance)
    stability = load_stability_artifact(args.stability_artifact)
    validation = load_rule_validation_round(
        args.validation_round,
        rule_bundle=bundle,
        corpus_atoms=rule_atoms,
        corpus_provenance=rule_provenance,
        stability_artifact=stability,
        transport=args.transport,
    )
    rf_manifest, model, encoder = load_tier2_rf_artifact(args.rf_manifest)
    rf_atoms, rf_provenance = load_rule_corpus(
        rf_manifest["corpus"]["path"],
        rf_manifest["corpus"]["provenance_path"])
    if rf_provenance["corpus_digest"] != rf_manifest["corpus"]["corpus_digest"]:
        raise ValueError("RF corpus digest no longer matches RF manifest")
    disjointness = _rf_disjointness(rf_atoms, stability, args.transport)

    samples = response_samples(stability, args.transport)
    runtime_rules = _runtime_4form_rules(cluster_rules)
    work_dir = tempfile.mkdtemp(prefix="e0_full_cascade_")
    try:
        rules_path = ""
        if runtime_rules:
            rules_path = os.path.join(work_dir, "rules_4form.json")
            with open(rules_path, "w", encoding="utf-8") as handle:
                json.dump(runtime_rules, handle, sort_keys=True)
        harness = GoCascadeHarness(
            args.go_bin, args.zgrab_dir, timeout=args.harness_timeout)
        if not harness.available():
            raise ValueError("Go cascade harness is unavailable")
        predictions = {}
        engine_meta = {}
        for start in range(0, len(samples), args.chunk_size):
            batch = samples[start:start + args.chunk_size]
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
            samples, predictions, model=model, encoder=encoder,
            threshold=float(rf_manifest["training_contract"][
                "deployment_threshold"]),
            feature_names=rf_manifest["feature_names"],
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    output = Path(args.output)
    prediction_path = output / "predictions.jsonl"
    n_written, prediction_sha = _atomic_jsonl(prediction_path, records)
    core = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "transport": args.transport,
        "rule_bundle_artifact_hash": bundle["artifact_hash"],
        "rule_validation_round_hash": validation["artifact_hash"],
        "stability_artifact_hash": stability["artifact_hash"],
        "rf_artifact_hash": rf_manifest["artifact_hash"],
        "rf_corpus_digest": rf_manifest["corpus"]["corpus_digest"],
        "rf_disjointness": disjointness,
        "cascade_order": ["tier1_rules", "tier2_random_forest", "tier3_baseline"],
        "rf_threshold": rf_manifest["training_contract"][
            "deployment_threshold"],
        "metrics": _metrics(records),
        "engine_meta": engine_meta,
        "predictions": {
            "path": str(prediction_path.resolve()),
            "count": n_written,
            "sha256": prediction_sha,
        },
    }
    manifest = dict(core)
    manifest["artifact_hash"] = canonical_sha256(core)
    manifest["created_at"] = datetime.now(
        timezone.utc).isoformat(timespec="seconds")
    _atomic_json(output / "manifest.json", manifest)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate the complete identification cascade on E0")
    parser.add_argument("--cluster-rules", required=True)
    parser.add_argument("--member-rules")
    parser.add_argument("--rule-bundle", required=True)
    parser.add_argument("--rule-corpus", required=True)
    parser.add_argument("--rule-corpus-provenance", required=True)
    parser.add_argument("--agent-state", action="append", required=True)
    parser.add_argument("--rf-manifest", required=True)
    parser.add_argument("--stability-artifact", required=True)
    parser.add_argument("--validation-round", required=True)
    parser.add_argument("--transport", choices=("tcp", "udp"), required=True)
    parser.add_argument("--zgrab-dir", default=str(ROOT / "PW_Scanner"))
    parser.add_argument("--go-bin", default="go")
    parser.add_argument("--harness-timeout", type=float, default=600.0)
    parser.add_argument("--chunk-size", type=int, default=2000)
    parser.add_argument("--output", required=True)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = evaluate(args)
    except (OSError, ValueError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "artifact_hash": manifest["artifact_hash"],
        "transport": manifest["transport"],
        "unique_response_identity": manifest["metrics"][
            "unique_response_identity"],
        "candidate_truth_pair": manifest["metrics"][
            "candidate_truth_pair"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
