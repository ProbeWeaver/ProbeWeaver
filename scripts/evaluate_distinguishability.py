#!/usr/bin/env python3
"""Evaluate response identities using the scanner Go cascade. Stream candidates and write bounded artifacts for identification-aware selection. Rules-only mode excludes the RF and must not be reported as the full classifier. Require matching provenance before claiming a verified split."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import ijson
except ImportError:  
    sys.stderr.write(
        "error: ijson is required for streaming evaluation (input files can be "
        "8GB+; whole-file json.load fallback is forbidden by design).\n"
        "Install it with: mamba install -n protocol_fuzzer ijson\n"
    )
    raise SystemExit(2)

import config  # noqa: E402
from core.candidate_stream import iter_candidate_stream  # noqa: E402
from core.candidate_stability import (  # noqa: E402
    canonical_sha256 as stability_canonical_sha256,
    load_stability_artifact,
)
from core.distinguishability import (  # noqa: E402
    DEFAULT_EVAL_RATIO,
    DEFAULT_NOVELTY_CAP,
    DEFAULT_SPLIT_KEY,
    ENGINE_IMPLEMENTATION,
    ENGINE_MODE,
    LEAKAGE_UNVERIFIED,
    LEAKAGE_VERIFIED,
    MANIFEST_FILENAME,
    SPLIT_KEY_PACKET_TARGET_MEMBER,
    VALID_SPLIT_KEYS,
    DistinguishabilityArtifactWriter,
    NoveltyTracker,
    RecordEvaluation,
    atomic_write_json,
    build_rule_provenance,
    finalize_record_eval,
    parse_nested_record,
    prepare_record_eval,
    response_sha,
    rules_digest,
    runtime_registry_digest,
    source_digest_of,
    validate_rule_provenance,
)
from core.distinguishability import (  # noqa: E402
    PHASE_LEGACY_UNKNOWN,
    PHASE_POST_PAYLOAD,
    PHASE_PRE_PAYLOAD_BANNER,
)
from core.rule_bundle_provenance import (  # noqa: E402
    RuleBundleProvenanceError,
    load_rule_bundle_provenance,
)
from core.rule_corpus import (  # noqa: E402
    load_rule_corpus,
    partition_for_response_identity,
    response_identity as rule_response_identity,
)
from core.rule_validation import (  # noqa: E402
    RuleValidationError,
    load_rule_validation_round,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("evaluate_distinguishability")

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ZGRAB_DIR = _REPO_ROOT / "PW_Scanner"

STRICT_SPLIT_METHOD = "full_source_evaluation_v3"
_KNOWN_PHASES = (PHASE_POST_PAYLOAD, PHASE_PRE_PAYLOAD_BANNER)

# ============================================================================

# ============================================================================

def _load_rules_json(path: Optional[str]) -> List[dict]:
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError(f"rules file must be a JSON array: {path}")
    return [r for r in data if isinstance(r, dict)]

#: "service and (pattern or magic_hex) are required"。
_CODE_RULE_KINDS = frozenset({"code", "member_code"})

def _runtime_4form_rules(cluster_rules: List[dict]) -> List[dict]:
    """Select the ordered four-form runtime rules used by the Go harness."""
    return [
        rule for rule in cluster_rules
        if str(rule.get("type") or "") not in _CODE_RULE_KINDS
        and str(rule.get("source") or "") not in _CODE_RULE_KINDS
    ]

class GoCascadeHarness:
    """Batch client of the scanner's own gated Go identification harness."""

    TEST_NAME = "TestDistinguishBatchHarness"

    def __init__(self, go_bin: str, zgrab_dir: str, timeout: float = 600.0) -> None:
        self.go_bin = go_bin
        self.zgrab_dir = str(zgrab_dir)
        self.timeout = float(timeout)
        self.n_runs = 0
        self.n_errors = 0
        self.last_error = ""

    def available(self) -> bool:
        from shutil import which
        return which(self.go_bin) is not None and os.path.isdir(self.zgrab_dir)

    def run(self, samples: List[dict], rules_path: str, work_dir: str
            ) -> Tuple[Dict[str, dict], dict, str]:
        """Run."""
        if not samples:
            return {}, {}, ""
        in_path = os.path.join(work_dir, "batch_in.jsonl")
        out_path = os.path.join(work_dir, "batch_out.jsonl")
        meta_path = os.path.join(work_dir, "batch_meta.json")
        with open(in_path, "w", encoding="utf-8") as fh:
            for s in samples:
                fh.write(json.dumps(
                    {"id": s["key"], "response_hex": s["response"].hex()}) + "\n")
        env = dict(os.environ)
        env.update({
            "DISTINGUISH_BATCH": "1",
            "DISTINGUISH_INPUT": in_path,
            "DISTINGUISH_OUTPUT": out_path,
            "DISTINGUISH_META": meta_path,
        })
        if rules_path:
            env["DISTINGUISH_RULES"] = rules_path
        else:
            env.pop("DISTINGUISH_RULES", None)
        self.n_runs += 1
        try:
            proc = subprocess.run(
                [self.go_bin, "test", "./modules/fuzzing/",
                 "-run", self.TEST_NAME, "-count=1"],
                cwd=self.zgrab_dir, env=env, capture_output=True,
                text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.n_errors += 1
            self.last_error = f"go harness timeout ({self.timeout:g}s)"
            return {}, {}, self.last_error
        except FileNotFoundError:
            self.n_errors += 1
            self.last_error = f"go executable not found: {self.go_bin}"
            return {}, {}, self.last_error
        if proc.returncode != 0 or not os.path.isfile(out_path):
            self.n_errors += 1
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()
            self.last_error = "go harness failed: " + (tail[-1] if tail else "no output")
            return {}, {}, self.last_error
        predictions: Dict[str, dict] = {}
        with open(out_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                predictions[str(rec.get("id"))] = rec
        meta: dict = {}
        if os.path.isfile(meta_path):
            try:
                with open(meta_path, encoding="utf-8") as fh:
                    meta = json.load(fh)
            except (OSError, json.JSONDecodeError):
                meta = {}
        return predictions, meta, ""

def _engine_coverage(rules_4form_services: set, engine_meta: dict) -> set:
    """Union services covered by four-form and compiled code registries."""
    code_services = set(engine_meta.get("code_rule_services") or [])
    return set(rules_4form_services) | code_services

# ============================================================================

# ============================================================================

def _iter_input_records(path: str):
    """Stream nested JSON arrays or compressed candidate JSONL records."""
    if str(path).endswith(".jsonl.gz"):
        for record in iter_candidate_stream(path):
            yield record
        return
    with open(path, "rb") as fh:
        for record in ijson.items(fh, "item"):
            yield record

def _iter_stability_reprobe_records(stability: dict, transport: str):
    """Yield one phase-aware evaluation record per unique payload.

    Repetition observations are aggregated from the candidate-stability
    artifact itself.  The same payload may have been retained for several
    mutation targets; identification depends on payload+transport, so those
    observations are unioned before evaluation.  TCP and UDP are never mixed
    in one distinguishability artifact because the historical packet hash is
    payload-only.
    """
    by_packet: Dict[str, dict] = {}
    for result in stability.get("candidate_results", []):
        identity = result.get("identity") or {}
        if str(identity.get("transport") or "") != transport:
            continue
        packet_hex = str(identity.get("packet_hex") or "").strip().lower()
        if not packet_hex:
            raise ValueError("stability candidate missing packet_hex")
        aggregate = by_packet.setdefault(packet_hex, {
            "packet_hex": packet_hex,
            "mutation_target": str(identity.get("mutation_target") or ""),
            "candidate_type": str(identity.get("candidate_type") or "multi_probe"),
            "transport": transport,
            "iteration": int((result.get("source") or {}).get("iteration", 0) or 0),
            "responses_by_key": {},
        })
        for repetition in result.get("repetition_observations") or []:
            for member in repetition.get("members") or []:
                service = str(member.get("member") or "")
                response_hex = str(member.get("response_hex") or "").lower()
                banner_hex = str(member.get("banner_hex") or "").lower()
                phase = str(member.get("response_phase") or "")
                key = (service, response_hex, banner_hex, phase)
                aggregate["responses_by_key"][key] = {
                    "service": service,
                    "response_hex": response_hex,
                    "banner_hex": banner_hex,
                    "response_phase": phase,
                    "latency_ms": float(member.get("latency_ms", 0.0) or 0.0),
                    "banner_latency_ms": float(
                        member.get("banner_latency_ms", 0.0) or 0.0),
                    "payload_latency_ms": float(
                        member.get("payload_latency_ms", 0.0) or 0.0),
                }
    for packet_hex in sorted(by_packet):
        aggregate = by_packet[packet_hex]
        responses = [
            aggregate["responses_by_key"][key]
            for key in sorted(aggregate["responses_by_key"])
        ]
        if not responses:
            continue
        yield {
            "packet_hex": aggregate["packet_hex"],
            "mutation_target": aggregate["mutation_target"],
            "candidate_type": aggregate["candidate_type"],
            "transport": aggregate["transport"],
            "iteration": aggregate["iteration"],
            "responses": responses,
        }

def _strict_phase_violation(facts) -> Optional[str]:
    """Report any response lacking an explicit known phase."""
    for cluster, metas in (facts.response_metadata or {}).items():
        for index, meta in enumerate(metas or []):
            phase = str((meta or {}).get("response_phase") or PHASE_LEGACY_UNKNOWN)
            if phase not in _KNOWN_PHASES:
                return f"cluster {cluster!r} response #{index} phase {phase!r}"
    return None

def evaluate(
    inputs: List[str],
    cluster_rules_path: Optional[str],
    member_rules_path: Optional[str],
    out_dir: str,
    objective_version: Optional[str],
    provenance_path: Optional[str] = None,
    eval_ratio: float = DEFAULT_EVAL_RATIO,
    split_key: str = SPLIT_KEY_PACKET_TARGET_MEMBER,
    chunk_size: int = 2000,
    go_bin: str = "go",
    zgrab_dir: str = str(DEFAULT_ZGRAB_DIR),
    harness_timeout: float = 600.0,
    novelty_cap: int = DEFAULT_NOVELTY_CAP,
    max_records: int = 0,
    rule_bundle_provenance_path: Optional[str] = None,
    rule_corpus_path: Optional[str] = None,
    rule_corpus_provenance_path: Optional[str] = None,
    agent_state_paths: Optional[List[str]] = None,
    stability_artifact_path: Optional[str] = None,
    stability_transport: Optional[str] = None,
    validation_round_path: Optional[str] = None,
) -> Optional[dict]:
    cluster_rules = _load_rules_json(cluster_rules_path)
    member_rules = _load_rules_json(member_rules_path)

    cluster_rules_4form = _runtime_4form_rules(cluster_rules)

    if not 0.0 < eval_ratio < 1.0:
        logger.error("--eval-ratio must be in (0,1) exclusive, got %r", eval_ratio)
        return None
    if split_key not in VALID_SPLIT_KEYS:
        logger.error("--split-key must be one of %s, got %r", VALID_SPLIT_KEYS, split_key)
        return None
    if chunk_size < 1:
        logger.error("--chunk-size must be >= 1, got %r", chunk_size)
        return None
    if novelty_cap < 0 or max_records < 0:
        logger.error("--novelty-cap / --max-records must be >= 0")
        return None
    if stability_artifact_path and inputs:
        logger.error(
            "--stability-artifact is a complete response source and cannot be "
            "combined with ordinary --inputs")
        return None
    if not stability_artifact_path and not inputs:
        logger.error("one of --inputs or --stability-artifact is required")
        return None
    if stability_transport not in (None, "tcp", "udp"):
        logger.error("--stability-transport must be tcp or udp")
        return None
    if stability_transport and not stability_artifact_path:
        logger.error("--stability-transport requires --stability-artifact")
        return None
    if validation_round_path and not stability_artifact_path:
        logger.error(
            "--validation-round requires --stability-artifact; construction "
            "inputs cannot certify held-out performance")
        return None
    for path in inputs:
        if not os.path.isfile(path):
            logger.error("input file not found: %s", path)
            return None

    if not cluster_rules_path and not member_rules_path:
        logger.error("at least one of --cluster-rules / --member-rules is required")
        return None

    strict_mode = bool(rule_bundle_provenance_path)
    if stability_artifact_path and not strict_mode:
        logger.error(
            "stability reprobe evaluation requires strict rule-bundle mode")
        return None
    bundle: Optional[dict] = None
    partition_resolver = None
    if not strict_mode and (rule_corpus_path or rule_corpus_provenance_path
                            or agent_state_paths):
        logger.error(
            "--rule-corpus / --rule-corpus-provenance / --agent-state only make "
            "sense together with --rule-bundle-provenance (strict mode)")
        return None
    corpus_atoms = None
    corpus_provenance = None
    if strict_mode:
        if provenance_path:
            logger.error(
                "strict rule-bundle mode does not use the legacy --provenance "
                "path (no fallback); remove --provenance")
            return None

    stability_source: Optional[dict] = None
    selected_stability_transport: Optional[str] = None
    if stability_artifact_path:
        if not os.path.isfile(stability_artifact_path):
            logger.error("stability artifact not found: %s", stability_artifact_path)
            return None
        try:
            stability_source = load_stability_artifact(stability_artifact_path)
        except (OSError, ValueError) as exc:
            logger.error("[eval] stability artifact rejected: %s", exc)
            return None
        transports = sorted({
            str((result.get("identity") or {}).get("transport") or "")
            for result in stability_source.get("candidate_results", [])
        } - {""})
        if stability_transport:
            if stability_transport not in transports:
                logger.error(
                    "stability artifact has transports %s, not requested %s",
                    transports, stability_transport)
                return None
            selected_stability_transport = stability_transport
        elif len(transports) == 1:
            selected_stability_transport = transports[0]
        else:
            logger.error(
                "stability artifact contains multiple transports %s; run one "
                "strict evaluation per transport with --stability-transport",
                transports)
            return None
    if strict_mode:
        missing = []
        if not rule_corpus_path:
            missing.append("--rule-corpus")
        if not rule_corpus_provenance_path:
            missing.append("--rule-corpus-provenance")
        if not agent_state_paths:
            missing.append("--agent-state (at least one)")
        if missing:
            logger.error(
                "strict rule-bundle mode requires explicit corpus / corpus "
                "provenance / agent state inputs; missing: %s (fail-fast, no "
                "fallback to legacy provenance)", ", ".join(missing))
            return None
        for strict_path in [rule_bundle_provenance_path, rule_corpus_path,
                            rule_corpus_provenance_path, *agent_state_paths]:
            if not os.path.isfile(strict_path):
                logger.error("strict rule-bundle input not found: %s", strict_path)
                return None
        try:

            bundle = load_rule_bundle_provenance(
                rule_bundle_provenance_path,
                cluster_rules_path=cluster_rules_path,
                member_rules_path=member_rules_path,
                corpus_path=rule_corpus_path,
                corpus_provenance_path=rule_corpus_provenance_path,
                agent_state_paths=agent_state_paths,
                zgrab_dir=zgrab_dir)
            corpus_atoms, corpus_provenance = load_rule_corpus(
                rule_corpus_path, rule_corpus_provenance_path)
        except (RuleBundleProvenanceError, OSError, ValueError) as exc:
            logger.error("[eval] strict rule bundle rejected (fail-fast, no "
                         "fallback): %s", exc)
            return None

    validation_round: Optional[dict] = None
    if validation_round_path:
        if not strict_mode:
            logger.error("--validation-round requires strict rule-bundle mode")
            return None
        if not os.path.isfile(validation_round_path):
            logger.error("validation round not found: %s", validation_round_path)
            return None
        try:
            validation_round = load_rule_validation_round(
                validation_round_path,
                rule_bundle=bundle,
                corpus_atoms=corpus_atoms,
                corpus_provenance=corpus_provenance,
                stability_artifact=stability_source,
                transport=selected_stability_transport,
            )
        except (OSError, RuleValidationError, ValueError) as exc:
            logger.error("[eval] validation round rejected: %s", exc)
            return None

    ruleset_digest = rules_digest(cluster_rules, member_rules)

    harness = GoCascadeHarness(go_bin, zgrab_dir, timeout=harness_timeout)
    if not harness.available():
        logger.error(
            "go binary %r or zgrab dir %r unavailable — the rules_only_tier_cascade "
            "engine cannot run (no guessing); use --skip-engine only if you accept "
            "all engine statuses being unknown", go_bin, zgrab_dir)
        return None

    try:
        runtime_digest, runtime_files = runtime_registry_digest(zgrab_dir)
    except ValueError as exc:
        logger.error("[eval] %s", exc)
        return None

    if strict_mode:
        
        if bundle["rules"]["digest"] != ruleset_digest:
            logger.error(
                "[eval] strict bundle rules digest %r != evaluation rules "
                "digest %r", bundle["rules"]["digest"], ruleset_digest)
            return None
        if bundle["runtime"]["digest"] != runtime_digest:
            logger.error(
                "[eval] strict bundle runtime digest %r != evaluation runtime "
                "digest %r", bundle["runtime"]["digest"], runtime_digest)
            return None
        if stability_source is not None:
            for field in (
                    "objective_version", "weight_config_hash",
                    "background_artifact_hash"):
                actual = stability_source.get(field)
                expected = bundle["corpus"].get(field)
                if actual != expected:
                    logger.error(
                        "[eval] stability %s=%r != strict rule corpus %r",
                        field, actual, expected)
                    return None

        partition_resolver = lambda _response: "eval"

    if stability_source is not None:
        source_digest = stability_canonical_sha256({
            "mode": "candidate_stability_reprobes",
            "stability_artifact_hash": stability_source["artifact_hash"],
            "transport": selected_stability_transport,
        })
    else:
        source_digest = source_digest_of(inputs)
    leakage_status = LEAKAGE_UNVERIFIED
    leakage_reason = "no rule-training provenance provided"
    provenance_summary: dict = {}
    if strict_mode:
        leakage_status = (
            LEAKAGE_VERIFIED if validation_round is not None
            else LEAKAGE_UNVERIFIED)
        leakage_reason = (
            "fresh challenge packets and parent probe families are disjoint "
            "from the fully bound construction corpus"
            if validation_round is not None else
            "rule bundle integrity is verified, but this source is construction "
            "or otherwise lacks a bound fresh probe-family-disjoint round; "
            "reported rule metrics are in-sample")
        provenance_summary = {
            "mode": "strict_rule_bundle",
            "path": os.path.abspath(rule_bundle_provenance_path),
            "artifact_hash": bundle["artifact_hash"],
            "rules_digest": bundle["rules"]["digest"],
            "runtime_registry_digest": bundle["runtime"]["digest"],
            "corpus": {
                "digest": bundle["corpus"]["corpus_digest"],
                "file_sha256": bundle["corpus"]["corpus_file_sha256"],
                "source_candidates_digest": bundle["corpus"][
                    "source_candidates_digest"],
                "path": bundle["corpus"]["path"],
            },
            "agent_state_hashes": [
                {"path": rec["path"], "file_sha256": rec["file_sha256"]}
                for rec in bundle["agent_states"]],
        }
        if validation_round is not None:
            provenance_summary["validation_round"] = {
                "path": os.path.abspath(validation_round_path),
                "artifact_hash": validation_round["artifact_hash"],
                "validation_mode": validation_round["validation_mode"],
                "held_out_axis": validation_round["held_out_axis"],
                "transport": validation_round["transport"],
                "challenge": dict(validation_round["challenge"]),
                "disjointness": dict(validation_round["disjointness"]),
            }
        if stability_source is not None:
            provenance_summary["source_binding"] = {
                "mode": "candidate_stability_reprobes",
                "stability_artifact_hash": stability_source["artifact_hash"],
                "stability_source_candidates_digest": stability_source[
                    "source_candidates_digest"],
                "response_phase_schema_version": stability_source[
                    "response_phase_schema_version"],
                "transport": selected_stability_transport,
            }
    elif provenance_path:
        try:
            with open(provenance_path, encoding="utf-8") as fh:
                provenance = json.load(fh)
            validate_rule_provenance(
                provenance, cluster_rules, member_rules,
                expected_source_digest=source_digest,
                split_key=split_key, eval_ratio=eval_ratio,
                require_train_only=True,
                expected_runtime_digest=runtime_digest)
            leakage_status = LEAKAGE_VERIFIED
            leakage_reason = ("provenance matched rules/source/split/runtime and "
                              "declared train-only")
            provenance_summary = {
                "path": os.path.abspath(provenance_path),
                "provenance_hash": provenance.get("provenance_hash", ""),
                "rules_digest": provenance.get("rules", {}).get("digest", ""),
                "runtime_registry_digest": provenance.get(
                    "runtime_registry_digest", ""),
                "declared_train_only": provenance.get("declared_train_only", False),
            }
        except (OSError, ValueError) as exc:
            leakage_status = LEAKAGE_UNVERIFIED
            leakage_reason = f"provenance rejected: {exc}"
            logger.warning("[eval] %s", leakage_reason)
    if leakage_status != LEAKAGE_VERIFIED:
        logger.warning(
            "[eval] leakage_status=unverified (%s) — selector strict rule-confirmed "
            "mode will reject this artifact; proxy mode still works", leakage_reason)

    novelty = NoveltyTracker(cap=novelty_cap)
    writer = DistinguishabilityArtifactWriter(out_dir)
    
    harness_work_dir = tempfile.mkdtemp(prefix="distinguish_harness_")
    runtime_rules_path = ""

    manifest_result: Optional[dict] = None

    try:

        if cluster_rules_4form:
            runtime_rules_path = os.path.join(
                harness_work_dir, "cluster_rules_4form.json")
            with open(runtime_rules_path, "w", encoding="utf-8") as fh:
                json.dump(cluster_rules_4form, fh, sort_keys=True, indent=2)
        files_meta: List[dict] = []
        source_paths = (
            [stability_artifact_path] if stability_source is not None else inputs)
        totals = {"files": len(source_paths), "records": 0, "used": 0,
                  "skipped_schema": 0, "skipped_diagnostic": 0, "duplicated": 0}
        t0 = time.time()
        global_records = 0        
        stop = False

        engine_meta: dict = {}
        probe = [{"key": "__probe__", "cluster": "", "member": "",
                  "response": b"\x00"}]
        _, engine_meta, probe_err = harness.run(
            probe, runtime_rules_path, harness_work_dir)
        if probe_err:
            logger.error("[eval] engine probe failed: %s", probe_err)
            return None
        if engine_meta.get("engine_mode") != ENGINE_MODE:
            logger.error("[eval] harness engine_mode mismatch: %r != %r",
                         engine_meta.get("engine_mode"), ENGINE_MODE)
            return None
        if strict_mode:
            
            meta_runtime = str(engine_meta.get("runtime_registry_digest") or "")
            if meta_runtime and meta_runtime != bundle["runtime"]["digest"]:
                logger.error(
                    "[eval] harness runtime digest %r != strict bundle runtime "
                    "digest %r", meta_runtime, bundle["runtime"]["digest"])
                return None
        rules_4form_services = {
            str(r.get("service"))
            for r in cluster_rules_4form if r.get("service")}
        coverage = _engine_coverage(rules_4form_services, engine_meta)
        logger.info(
            "[eval] engine=%s | 4-form rules=%d services=%d + compiled code "
            "services=%d -> coverage=%d clusters | member_code clusters=%d",
            engine_meta.get("engine_mode"), len(cluster_rules_4form),
            len(rules_4form_services),
            len(engine_meta.get("code_rule_services") or []), len(coverage),
            len(engine_meta.get("member_code_rule_clusters") or {}))

        for path in source_paths:
            per_file = {"path": os.path.abspath(path), "records": 0, "used": 0,
                        "skipped_schema": 0, "skipped_diagnostic": 0}
            if stability_source is not None:
                per_file["source_kind"] = "candidate_stability_reprobes"
                per_file["transport"] = selected_stability_transport
            try:
                st = os.stat(path)
                per_file["size_bytes"] = st.st_size
                per_file["mtime"] = datetime.fromtimestamp(
                    st.st_mtime, timezone.utc).isoformat()
            except OSError:
                pass
            ft = time.time()
            chunk: List[RecordEvaluation] = []
            chunk_samples: List[dict] = []

            def _flush_chunk() -> None:
                nonlocal chunk, chunk_samples
                predictions: Dict[str, dict] = {}
                engine_error = ""
                if chunk_samples:
                    preds, _meta, engine_error = harness.run(
                        chunk_samples, runtime_rules_path, harness_work_dir)
                    predictions = preds
                    writer.stats.n_engine_samples += len(chunk_samples)
                for record_eval in chunk:
                    entry = finalize_record_eval(record_eval, predictions, engine_error)
                    writer.write_entry(entry)
                chunk, chunk_samples = [], []

            try:
                records = (
                    _iter_stability_reprobe_records(
                        stability_source, selected_stability_transport)
                    if stability_source is not None
                    else _iter_input_records(path))
                for record in records:
                    
                    if max_records and global_records >= max_records:
                        stop = True
                        break
                    global_records += 1
                    per_file["records"] += 1
                    if not isinstance(record, dict):
                        per_file["skipped_schema"] += 1
                        continue
                    candidate_type = str(record.get("candidate_type") or "multi_probe")
                    if candidate_type == "diagnostic_only":
                        per_file["skipped_diagnostic"] += 1
                        continue
                    facts = parse_nested_record(record)
                    if facts is None:
                        per_file["skipped_schema"] += 1
                        continue
                    if strict_mode:

                        violation = _strict_phase_violation(facts)
                        if violation is not None:
                            logger.error(
                                "[eval] strict rule-bundle mode requires "
                                "phase-aware records (%s); rerun collection with "
                                "phase capture or use allow-legacy corpus mode — "
                                "no silent skip/downgrade", violation)
                            return None
                    
                    record_eval = prepare_record_eval(
                        facts, coverage, novelty=novelty,
                        split_key=split_key, eval_ratio=eval_ratio,
                        partition_resolver=partition_resolver)
                    per_file["used"] += 1
                    chunk.append(record_eval)
                    chunk_samples.extend(record_eval.samples)
                    if len(chunk) >= chunk_size:
                        _flush_chunk()
                _flush_chunk()
            except ValueError as exc:
                logger.error("[eval] %s: %s", path, exc)
                return None
            per_file["elapsed_s"] = round(time.time() - ft, 1)
            logger.info("[eval] scanned %s: %s", path, json.dumps(per_file))
            files_meta.append(per_file)
            if stop:
                logger.warning("[eval] --max-records reached; evaluation truncated")
                break

        for key in ("records", "used", "skipped_schema", "skipped_diagnostic"):
            totals[key] = sum(f.get(key, 0) for f in files_meta)
        totals["duplicated"] = writer.stats.n_duplicated_packet
        totals["engine_runs"] = harness.n_runs
        totals["engine_errors"] = harness.n_errors
        manifest_result = writer.finalize({
            "objective_version": objective_version or getattr(config, "OBJECTIVE_VERSION", None),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "rules": {
                "cluster_rules_path": os.path.abspath(cluster_rules_path) if cluster_rules_path else "",
                "member_rules_path": os.path.abspath(member_rules_path) if member_rules_path else "",
                "n_cluster_rules": len(cluster_rules),
                "n_member_rules": len(member_rules),
                "digest": ruleset_digest,
                "runtime_4form_rule_count": len(cluster_rules_4form),
                "runtime_rules_note": (
                    "the Go harness receives only the 4-form runtime subset "
                    "(rules with type/source in {code, member_code} are compiled "
                    "into code_rules.go and never passed to fingerprint.LoadRules; "
                    "empty subset means no DISTINGUISH_RULES); digest / "
                    "n_cluster_rules / paths keep full-rules semantics"),
                "member_rules_note": (
                    "member_rules.json contributes to the digest only; runtime Stage B "
                    "uses compiled member_code (MemberResolveCode) exclusively"),
            },
            "split": (
                {
                    "method": STRICT_SPLIT_METHOD,
                    "mode": "strict_rule_bundle",
                    "held_out_axis": bundle["training_contract"][
                        "held_out_axis"],
                    "construction": dict(bundle["corpus"]["construction"]),
                    "validation": (
                        {
                            "status": "verified",
                            "artifact_hash": validation_round["artifact_hash"],
                            "mode": validation_round["validation_mode"],
                            "held_out_axis": validation_round["held_out_axis"],
                        } if validation_round is not None else {
                            "status": "not_bound",
                            "mode": "construction_in_sample",
                        }
                    ),
                    "policy": (
                        "all responses in the bound source enter the Go harness; "
                        "construction sources are in-sample, and only a separately "
                        "bound probe-family-disjoint source may claim held-out"),
                } if strict_mode else {
                    "method": "stable sha256 hash split (core.distinguishability.stable_split_label)",
                    "key": split_key,
                    "eval_ratio": eval_ratio,
                    "policy": (
                        "engine predictions counted on eval-split responses only; "
                        "train-only clusters are unknown — responses used to generate "
                        "rules must not also certify held-out identifiability"),
                }
            ),
            "source_digest": source_digest,
            "strict_rule_bundle": strict_mode,
            "source_digest_note": (
                ("canonical identity of the bound candidate-stability artifact "
                 "and selected transport; evaluated responses come from its "
                 "three reprobe observations — NOT the rule-training corpus"
                 if stability_source is not None else
                 "identity of the evaluated candidate input file(s) only — NOT "
                 "the rule-training corpus identity; the training corpus is "
                 "bound by provenance.corpus (digest / file_sha256 / "
                 "source_candidates_digest)")
            ) if strict_mode else "",
            "source": {
                "generator": "scripts/evaluate_distinguishability.py",
                "files": files_meta,
                "totals": totals,
            },
            "source_totals": totals,
            "leakage_status": leakage_status,
            "leakage_reason": leakage_reason,
            "provenance": provenance_summary,
            "engine": {
                "mode": ENGINE_MODE,
                "implementation": ENGINE_IMPLEMENTATION,
                "go_bin": go_bin,
                "zgrab_dir": os.path.abspath(zgrab_dir),
                "runtime_registry_digest": runtime_digest,
                "runtime_registry_files": runtime_files,
                "n_code_rule_services": len(engine_meta.get("code_rule_services") or []),
                "n_member_code_rule_clusters": len(
                    engine_meta.get("member_code_rule_clusters") or {}),
                "n_engine_coverage_clusters": len(coverage),
                "harness_runs": harness.n_runs,
                "harness_errors": harness.n_errors,
            },
            "engine_meta": {
                "engine_mode_from_harness": engine_meta.get("engine_mode", ""),
                "runtime_4form_rule_count": len(cluster_rules_4form),
                "code_rule_services_digest": hashlib.sha256(
                    json.dumps(sorted(engine_meta.get("code_rule_services") or []),
                               sort_keys=True).encode()).hexdigest()[:16],
                "member_code_rule_clusters_digest": hashlib.sha256(
                    json.dumps(sorted(
                        (engine_meta.get("member_code_rule_clusters") or {}).items()),
                        sort_keys=True).encode()).hexdigest()[:16],
            },
            "novelty_cap": novelty_cap,
            "novelty_tracker_capped": novelty.capped,
        })
        logger.info(
            "[eval] artifact written: %s | entries=%d | status=%s | leakage=%s (%s) | "
            "engine runs=%d errors=%d | elapsed=%.1fs",
            os.path.join(out_dir, MANIFEST_FILENAME),
            manifest_result["n_entries"], json.dumps(manifest_result["status_counts"]),
            leakage_status, leakage_reason, harness.n_runs, harness.n_errors,
            time.time() - t0,
        )
    finally:
        
        writer.close()
        shutil.rmtree(harness_work_dir, ignore_errors=True)

    return manifest_result

# ============================================================================

# ============================================================================

def cmd_provenance(args: argparse.Namespace) -> int:
    """Write a rule-training provenance manifest."""
    cluster_rules = _load_rules_json(args.cluster_rules)
    member_rules = _load_rules_json(args.member_rules)
    if not args.cluster_rules and not args.member_rules:
        logger.error("[provenance] at least one of --cluster-rules / --member-rules is required")
        return 2
    for path in args.sources:
        if not os.path.isfile(path):
            logger.error("[provenance] source file not found: %s", path)
            return 2
    if not 0.0 < args.eval_ratio < 1.0:
        logger.error("[provenance] --eval-ratio must be in (0,1) exclusive")
        return 2

    zgrab_dir = str(args.zgrab_dir) if args.zgrab_dir else str(DEFAULT_ZGRAB_DIR)
    try:
        runtime_digest, runtime_files = runtime_registry_digest(zgrab_dir)
    except ValueError as exc:
        logger.error("[provenance] %s", exc)
        return 2

    prov = build_rule_provenance(
        cluster_rules, member_rules, args.sources,
        split_key=args.split_key, eval_ratio=args.eval_ratio,
        declared_train_only=args.declare_train_only,
        runtime_registry_digest_hex=runtime_digest,
        runtime_registry_files=runtime_files,
        generator=args.generator, notes=args.notes)
    atomic_write_json(args.output, prov)
    logger.info(
        "[provenance] written %s | rules_digest=%s | source_digest=%s | "
        "declared_train_only=%s",
        args.output, prov["rules"]["digest"], prov["source_digest"],
        prov["declared_train_only"])
    if not args.declare_train_only:
        logger.warning(
            "[provenance] declared_train_only=false → leakage_status stays "
            "unverified; strict rule-confirmed selection will reject it")
    return 0

# ============================================================================
# argparse
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline response distinguishability evaluation (response coverage): "
                    "score each candidate packet's per-cluster responses against "
                    "the runtime rules-only tier cascade (proxy-only where the "
                    "engine has no rules).")
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser("evaluate", help="stream inputs → distinguishability artifact")
    ev.add_argument("-i", "--inputs", nargs="*", default=[],
                    help="nested-schema fingerprint library JSON file(s); mutually "
                         "exclusive with --stability-artifact")
    ev.add_argument("--cluster-rules", default=None,
                    help="cluster rules JSON (e.g. PW_Scanner/rules.json)")
    ev.add_argument("--member-rules", default=None,
                    help="member rules JSON (digest bookkeeping only; runtime "
                         "Stage B uses compiled member_code)")
    ev.add_argument("-o", "--output", required=True,
                    help="artifact output DIRECTORY (manifest.json + entries.jsonl)")
    ev.add_argument("--provenance", default=None,
                    help="rule-training provenance JSON (scripts/... provenance "
                         "subcommand); matched → leakage_status=verified")
    ev.add_argument("--objective-version", default=None,
                    help="objective version stamped into the artifact (default: "
                         "current config.OBJECTIVE_VERSION)")
    ev.add_argument("--eval-ratio", type=float,
                    default=getattr(config, "DISTINGUISHABILITY_EVAL_RATIO",
                                    DEFAULT_EVAL_RATIO))
    ev.add_argument("--split-key", choices=list(VALID_SPLIT_KEYS),
                    default=getattr(config, "DISTINGUISHABILITY_SPLIT_KEY",
                                    DEFAULT_SPLIT_KEY))
    ev.add_argument("--chunk-size", type=int,
                    default=getattr(config, "DISTINGUISHABILITY_CHUNK_SIZE", 2000))
    ev.add_argument("--go-bin",
                    default=getattr(config, "DISTINGUISHABILITY_GO_BIN", "go"))
    ev.add_argument("--zgrab-dir",
                    default=getattr(config, "DISTINGUISHABILITY_ZGRAB_DIR",
                                    str(DEFAULT_ZGRAB_DIR)),
                    help="zgrab2 module dir containing the harness")
    ev.add_argument("--harness-timeout", type=float,
                    default=getattr(config, "DISTINGUISHABILITY_HARNESS_TIMEOUT",
                                    600.0))
    ev.add_argument("--novelty-cap", type=int,
                    default=getattr(config, "DISTINGUISHABILITY_NOVELTY_CAP",
                                    DEFAULT_NOVELTY_CAP))
    ev.add_argument("--max-records", type=int, default=0,
                    help="GLOBAL cap across all inputs (0 = unlimited; smoke tests)")
    ev.add_argument("--rule-bundle-provenance", default=None,
                    help="background-adjusted search strict rule-bundle provenance manifest; enables "
                         "strict mode (requires --rule-corpus, "
                         "--rule-corpus-provenance, --agent-state; legacy "
                         "--provenance is then rejected)")
    ev.add_argument("--rule-corpus", default=None,
                    help="strict mode: rule-training corpus JSON (validated "
                         "against the bundle)")
    ev.add_argument("--rule-corpus-provenance", default=None,
                    help="strict mode: rule-corpus provenance sidecar "
                         "(partition ratios/salts source)")
    ev.add_argument("--agent-state", action="append", default=None,
                    dest="agent_state", metavar="PATH",
                    help="strict mode: finalized Agent state file (repeatable)")
    ev.add_argument(
        "--stability-artifact", default=None,
        help="strict mode: evaluate the phase-aware three-reprobe responses "
             "stored in a candidate-stability artifact (cannot combine with -i)")
    ev.add_argument(
        "--stability-transport", choices=("tcp", "udp"), default=None,
        help="required when the stability artifact contains both transports; "
             "one distinguishability artifact is produced per transport")
    ev.add_argument(
        "--validation-round", default=None,
        help="strict mode: probe-family-disjoint validation binding produced "
             "by scripts/build_rule_validation_round.py; without it strict "
             "rule-bundle evaluation remains leakage_status=unverified")
    ev.set_defaults(func=_cmd_evaluate)

    prov = sub.add_parser(
        "provenance", help="generate a rule-training provenance manifest")
    prov.add_argument("--cluster-rules", default=None)
    prov.add_argument("--member-rules", default=None)
    prov.add_argument("--sources", nargs="+", required=True,
                      help="corpus file(s) the rules were generated from")
    prov.add_argument("-o", "--output", required=True)
    prov.add_argument("--split-key", choices=list(VALID_SPLIT_KEYS),
                      default=getattr(config, "DISTINGUISHABILITY_SPLIT_KEY",
                                      DEFAULT_SPLIT_KEY))
    prov.add_argument("--eval-ratio", type=float, default=DEFAULT_EVAL_RATIO)
    prov.add_argument("--declare-train-only", dest="declare_train_only",
                      action="store_true", default=False,
                      help="DECLARE the rules were generated from the train "
                           "partition only (only if the generation process "
                           "actually did so — do not fabricate)")
    prov.add_argument("--no-declare-train-only", dest="declare_train_only",
                      action="store_false")
    prov.add_argument("--generator", default="",
                      help="free-text generator description (e.g. rule-gen skill)")
    prov.add_argument("--notes", default="")
    prov.add_argument("--zgrab-dir",
                      default=getattr(config, "DISTINGUISHABILITY_ZGRAB_DIR",
                                      str(DEFAULT_ZGRAB_DIR)),
                      help="zgrab2 module dir for runtime registry digest (default: PW_Scanner)")
    prov.set_defaults(func=cmd_provenance)
    return parser

def _cmd_evaluate(args: argparse.Namespace) -> int:
    manifest = evaluate(
        inputs=args.inputs,
        cluster_rules_path=args.cluster_rules,
        member_rules_path=args.member_rules,
        out_dir=args.output,
        objective_version=args.objective_version,
        provenance_path=args.provenance,
        eval_ratio=args.eval_ratio,
        split_key=args.split_key,
        chunk_size=args.chunk_size,
        go_bin=args.go_bin,
        zgrab_dir=args.zgrab_dir,
        harness_timeout=args.harness_timeout,
        novelty_cap=args.novelty_cap,
        max_records=args.max_records,
        rule_bundle_provenance_path=args.rule_bundle_provenance,
        rule_corpus_path=args.rule_corpus,
        rule_corpus_provenance_path=args.rule_corpus_provenance,
        agent_state_paths=args.agent_state,
        stability_artifact_path=args.stability_artifact,
        stability_transport=args.stability_transport,
        validation_round_path=args.validation_round,
    )
    return 0 if manifest is not None else 2

def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
