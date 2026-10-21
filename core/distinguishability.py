"""Streamed offline identification evaluation and provenance. Preserve banner/post-send facts, response identities and split assignments. Correct service labels establish coverage; proxy scores do not establish accuracy. Validate frozen rule, source and runtime digests; index large artifacts on disk."""

from __future__ import annotations

import atexit
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from services_config import identification_cluster_of

logger = logging.getLogger(__name__)

# ============================================================================

# ============================================================================

SCHEMA_VERSION = 2
ARTIFACT_TYPE = "distinguishability_evaluation"
EVALUATOR_VERSION = "distinguishability_evaluator"

ENGINE_MODE = "rules_only_tier_cascade"
ENGINE_IMPLEMENTATION = "go_scanner_harness_v1"
KNOWN_ENGINE_MODES = (ENGINE_MODE,)
KNOWN_ENGINE_IMPLEMENTATIONS = (ENGINE_IMPLEMENTATION,)

PROXY_VERSION = "proxy"
KNOWN_PROXY_VERSIONS = (PROXY_VERSION,)
KNOWN_EVALUATOR_VERSIONS = (EVALUATOR_VERSION,)

MANIFEST_FILENAME = "manifest.json"
ENTRIES_FILENAME = "entries.jsonl"

STATUS_RULE_CONFIRMED = "rule_confirmed"   
STATUS_AMBIGUOUS_CONFIRMED = "ambiguous_confirmed"  
STATUS_RULE_REJECTED = "rule_rejected"     
STATUS_PROXY = "proxy"                     
STATUS_UNKNOWN = "unknown"                 
VALID_STATUSES = (
    STATUS_RULE_CONFIRMED, STATUS_AMBIGUOUS_CONFIRMED,
    STATUS_RULE_REJECTED, STATUS_PROXY, STATUS_UNKNOWN,
)

MEMBER_STATUS_CONFIRMED = "member_code_confirmed"
MEMBER_STATUS_UNKNOWN = "unknown"          
MEMBER_STATUS_NOT_RUN = "not_run"          

LEAKAGE_VERIFIED = "verified"
LEAKAGE_UNVERIFIED = "unverified"
VALID_LEAKAGE_STATUS = (LEAKAGE_VERIFIED, LEAKAGE_UNVERIFIED)

# split
SPLIT_TRAIN = "train"
SPLIT_EVAL = "eval"

SPLIT_KEY_RESPONSE_IDENTITY = "response_identity"
SPLIT_KEY_PACKET = "packet"
SPLIT_KEY_PACKET_TARGET_MEMBER = "packet_target_member"
VALID_SPLIT_KEYS = (
    SPLIT_KEY_RESPONSE_IDENTITY, SPLIT_KEY_PACKET, SPLIT_KEY_PACKET_TARGET_MEMBER,
)
DEFAULT_SPLIT_KEY = SPLIT_KEY_RESPONSE_IDENTITY
DEFAULT_EVAL_RATIO = 0.3
_SPLIT_BUCKETS = 10_000

PHASE_PRE_PAYLOAD_BANNER = "pre_payload_banner"
PHASE_POST_PAYLOAD = "post_payload"
PHASE_LEGACY_UNKNOWN = "legacy_unknown"
KNOWN_RESPONSE_PHASES = (
    PHASE_PRE_PAYLOAD_BANNER, PHASE_POST_PAYLOAD, PHASE_LEGACY_UNKNOWN,
)

EXTERNAL_PARTITION_FIT = "fit"
EXTERNAL_PARTITION_DEV = "dev"
EXTERNAL_PARTITION_EVAL = "eval"
VALID_EXTERNAL_PARTITIONS = (
    EXTERNAL_PARTITION_FIT, EXTERNAL_PARTITION_DEV, EXTERNAL_PARTITION_EVAL,
)

RUNTIME_REGISTRY_FILES = (
    "lib/fingerprint/code_rules.go",
    "lib/fingerprint/member_code_rules.go",
    "lib/fingerprint/rule_engine.go",
    "modules/fuzzing/scanner.go",
    "modules/fuzzing/identify_batch.go",
)

PROXY_WEIGHTS = {
    "cross_member_consistency": 0.4,   
    "no_collision": 0.3,               
    "novelty": 0.2,                    
    "min_length": 0.1,                 
}
PROXY_MIN_LENGTH_BYTES = 4
DEFAULT_NOVELTY_CAP = 50_000

DEDUP_POLICY = "first-wins-global"

PROXY_NOT_ACCURACY_NOTE = (
    "proxy metrics are lightweight proxies for identifiability, NOT identification "
    "accuracy; only rule_confirmed (cascade primary == ground truth) counts as "
    "correct identification by the rules-only engine"
)
RULES_ONLY_NOTE = (
    "engine_mode=rules_only_tier_cascade: Tier1(code+specific) short-circuit, no "
    "Tier2 RF; results are NOT full-classifier identification"
)

def packet_hash_from_hex(packet_hex: str) -> str:
    """Hash decoded payload bytes consistently with the online packet identity."""
    try:
        raw = bytes.fromhex(packet_hex)
    except (ValueError, TypeError):
        return hashlib.sha256(str(packet_hex).encode("utf-8")).hexdigest()
    return hashlib.sha256(raw).hexdigest()

def response_sha(response: bytes) -> str:
    return hashlib.sha256(response).hexdigest()[:16]

def stable_split_label(
    packet_hash: str,
    mutation_target: str,
    member: str,
    response_sha_hex: str,
    split_key: str = DEFAULT_SPLIT_KEY,
    eval_ratio: float = DEFAULT_EVAL_RATIO,
) -> str:
    """Assign a deterministic split label from the key and ratio."""
    if split_key not in VALID_SPLIT_KEYS:
        raise ValueError(f"split_key must be one of {VALID_SPLIT_KEYS}, got {split_key!r}")
    if not 0.0 < eval_ratio < 1.0:
        raise ValueError(f"eval_ratio must be in (0,1) exclusive, got {eval_ratio!r}")
    if split_key == SPLIT_KEY_RESPONSE_IDENTITY:
        payload = response_sha_hex
    elif split_key == SPLIT_KEY_PACKET:
        payload = packet_hash
    else:
        payload = "|".join((packet_hash, mutation_target, member, response_sha_hex))
    bucket = int(hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8], 16) % _SPLIT_BUCKETS
    return SPLIT_EVAL if bucket < int(eval_ratio * _SPLIT_BUCKETS) else SPLIT_TRAIN

def split_leakage_risk(split_key: str) -> str:
    """Describe the leakage assumptions of the selected split strategy."""
    if split_key == SPLIT_KEY_RESPONSE_IDENTITY:
        return "none: identical response bytes always share the same split"
    return (
        "response-duplication: identical response bytes may fall on both sides "
        "of the split (rules learn from response bytes); use response_identity "
        "for verified leakage control"
    )

def runtime_registry_digest(zgrab_dir: str) -> Tuple[str, list]:
    """Hash compiled registries and the scanner cascade implementation."""
    root = Path(zgrab_dir)
    if not root.is_dir():
        raise ValueError(f"zgrab dir not found: {zgrab_dir}")
    records = []
    for rel in RUNTIME_REGISTRY_FILES:
        p = root / rel
        if not p.is_file():
            raise ValueError(f"runtime registry file missing: {p}")
        blob = p.read_bytes()
        records.append({
            "path": rel, "size": len(blob),
            "sha256_16": hashlib.sha256(blob).hexdigest()[:16],
        })
    payload = json.dumps(records, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16], records

def source_digest_of(paths: Sequence[str]) -> str:
    """Hash sorted source paths, sizes and timestamps, not full file contents."""
    items = []
    for p in sorted(os.path.abspath(str(p)) for p in paths):
        try:
            st = os.stat(p)
            items.append([p, st.st_size, int(st.st_mtime)])
        except OSError:
            items.append([p, "missing"])
    return hashlib.sha256(json.dumps(items).encode("utf-8")).hexdigest()[:16]

def rules_digest(cluster_rules: Sequence[dict], member_rules: Sequence[dict]) -> str:
    """Hash a canonical sorted representation of the rule set."""
    payload = {
        "cluster": sorted(cluster_rules, key=lambda r: json.dumps(r, sort_keys=True)),
        "member": sorted(member_rules, key=lambda r: json.dumps(r, sort_keys=True)),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]

# ============================================================================

# ============================================================================

class NoveltyTracker:
    """Track first-seen service/response identities under a fixed memory cap."""

    def __init__(self, cap: int = DEFAULT_NOVELTY_CAP) -> None:
        self.cap = int(cap)
        self._seen: set = set()
        self.capped = False

    def observe(self, cluster: str, sha_hex: str) -> Optional[bool]:
        if (cluster, sha_hex) in self._seen:
            return False
        if len(self._seen) >= self.cap:
            self.capped = True
            return None
        self._seen.add((cluster, sha_hex))
        return True

def proxy_metrics_for_packet(
    cluster_responses: Dict[str, List[Tuple[str, bytes]]],
    novelty: Optional[NoveltyTracker] = None,
    min_length_bytes: int = PROXY_MIN_LENGTH_BYTES,
) -> Dict[str, dict]:
    """Compute non-accuracy proxy measurements for services without rules."""
    owners: Dict[bytes, set] = {}
    for cluster, responses in cluster_responses.items():
        for _member, resp in responses:
            if resp:
                owners.setdefault(bytes(resp), set()).add(cluster)

    out: Dict[str, dict] = {}
    for cluster, responses in cluster_responses.items():
        resps = [bytes(r) for _m, r in responses if r]
        if not resps:
            continue
        counts = Counter(resps)
        if len(resps) > 1:
            cross_member: Optional[float] = max(counts.values()) / len(resps)
        else:
            cross_member = None   
        n_collisions = sum(len(owners[r] - {cluster}) for r in counts)
        no_collision = 1.0 if n_collisions == 0 else 0.0
        min_length_ok = 1.0 if min(len(r) for r in resps) >= min_length_bytes else 0.0

        novel_flags: List[Optional[bool]] = []
        if novelty is not None:
            novel_flags = [novelty.observe(cluster, response_sha(r)) for r in resps]
        if novel_flags and all(f is not None for f in novel_flags):
            novelty_fraction: Optional[float] = sum(1 for f in novel_flags if f) / len(novel_flags)
        else:
            novelty_fraction = None

        components = {
            "cross_member_consistency": cross_member,
            "no_collision": no_collision,
            "novelty": novelty_fraction,
            "min_length": min_length_ok,
        }
        num = den = 0.0
        for name, weight in PROXY_WEIGHTS.items():
            value = components[name]
            if value is None:
                continue
            num += weight * value
            den += weight
        score = (num / den) if den > 0 else None

        out[cluster] = {
            "is_proxy": True,
            "note": PROXY_NOT_ACCURACY_NOTE,
            "proxy_version": PROXY_VERSION,
            "n_responses": len(resps),
            "cross_member_consistency": cross_member,
            "n_cross_service_collisions": n_collisions,
            "novelty_fraction": novelty_fraction,
            "novelty_tracker_capped": bool(novelty and novelty.capped),
            "min_length_bytes": min_length_bytes,
            "min_length_ok": bool(min_length_ok),
            "proxy_score": score,
        }
    return out

# ============================================================================

# ============================================================================

PROVENANCE_SCHEMA_VERSION = 1
PROVENANCE_ARTIFACT_TYPE = "rule_training_provenance"

def provenance_core_hash(d: dict) -> str:
    """Hash semantic provenance fields excluding time and notes."""
    core_keys = (
        "schema_version", "artifact_type", "rules", "runtime_registry_digest",
        "runtime_registry_files", "source_digest", "split",
        "declared_train_only", "generator", "tool_version",
    )
    core = {k: d[k] for k in core_keys if k in d}
    return hashlib.sha256(
        json.dumps(core, sort_keys=True).encode("utf-8")).hexdigest()[:16]

def build_rule_provenance(
    cluster_rules: Sequence[dict],
    member_rules: Sequence[dict],
    source_paths: Sequence[str],
    split_key: str,
    eval_ratio: float,
    declared_train_only: bool,
    runtime_registry_digest_hex: str = "",
    runtime_registry_files: Optional[List[dict]] = None,
    generator: str = "",
    notes: str = "",
) -> dict:
    """Build a rule-training provenance manifest."""
    if split_key not in VALID_SPLIT_KEYS:
        raise ValueError(f"invalid split_key {split_key!r}")
    if not 0.0 < eval_ratio < 1.0:
        raise ValueError(f"invalid eval_ratio {eval_ratio!r}")
    prov = {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "artifact_type": PROVENANCE_ARTIFACT_TYPE,
        "rules": {
            "digest": rules_digest(cluster_rules, member_rules),
            "n_cluster_rules": len(cluster_rules),
            "n_member_rules": len(member_rules),
        },
        "runtime_registry_digest": runtime_registry_digest_hex,
        "runtime_registry_files": runtime_registry_files or [],
        "source_digest": source_digest_of(source_paths),
        "split": {
            "key": split_key,
            "eval_ratio": eval_ratio,
            "partition_used_for_training": SPLIT_TRAIN,
            "leakage_risk": split_leakage_risk(split_key),
        },
        "declared_train_only": bool(declared_train_only),
        "generator": generator,
        "tool_version": EVALUATOR_VERSION,
        "notes": notes,
    }
    prov["provenance_hash"] = provenance_core_hash(prov)
    return prov

def validate_rule_provenance(
    provenance: dict,
    cluster_rules: Sequence[dict],
    member_rules: Sequence[dict],
    expected_source_digest: str,
    split_key: str,
    eval_ratio: float,
    require_train_only: bool = True,
    expected_runtime_digest: str = "",
) -> None:
    """Require matching rule, input, split and runtime identities."""
    if not isinstance(provenance, dict):
        raise ValueError("provenance is not a JSON object")
    if provenance.get("schema_version") != PROVENANCE_SCHEMA_VERSION:
        raise ValueError(
            f"provenance schema_version mismatch: {provenance.get('schema_version')!r}")
    if provenance.get("artifact_type") != PROVENANCE_ARTIFACT_TYPE:
        raise ValueError(
            f"provenance artifact_type mismatch: {provenance.get('artifact_type')!r}")
    stored = provenance.get("provenance_hash")
    if stored != provenance_core_hash(provenance):
        raise ValueError(
            f"provenance_hash mismatch (stored={stored!r}) — corrupted or edited")
    actual_digest = rules_digest(cluster_rules, member_rules)
    if provenance.get("rules", {}).get("digest") != actual_digest:
        raise ValueError(
            f"provenance rule digest mismatch: provenance="
            f"{provenance.get('rules', {}).get('digest')!r}, actual={actual_digest!r} "
            f"— rules changed since provenance was recorded")
    if expected_runtime_digest:
        if provenance.get("runtime_registry_digest") != expected_runtime_digest:
            raise ValueError(
                f"provenance runtime registry digest mismatch: provenance="
                f"{provenance.get('runtime_registry_digest')!r}, expected="
                f"{expected_runtime_digest!r} — compiled Go registries / cascade "
                f"implementation changed; the recorded provenance binds a "
                f"different runtime classifier")
    elif not provenance.get("runtime_registry_digest"):
        raise ValueError(
            "provenance lacks runtime_registry_digest — identification depends on "
            "the compiled Go registries, not only the JSON rules")
    if provenance.get("source_digest") != expected_source_digest:
        raise ValueError(
            f"provenance source digest mismatch: provenance="
            f"{provenance.get('source_digest')!r}, evaluation input="
            f"{expected_source_digest!r} — rules were trained on a different corpus")
    split = provenance.get("split", {})
    if split.get("key") != split_key or split.get("eval_ratio") != eval_ratio:
        raise ValueError(
            f"provenance split mismatch: {split!r} vs evaluation "
            f"(key={split_key!r}, eval_ratio={eval_ratio!r})")
    if split.get("partition_used_for_training") != SPLIT_TRAIN:
        raise ValueError(
            "provenance must declare training on the train partition only, got "
            f"{split.get('partition_used_for_training')!r}")
    if require_train_only and not provenance.get("declared_train_only"):
        raise ValueError(
            "provenance does not declare rules were generated from the train "
            "partition only (declared_train_only=false) — leakage unverified")

# ============================================================================

# ============================================================================

@dataclass(frozen=True)
class RecordFacts:
    packet_hex: str
    packet_hash: str
    mutation_target: str
    candidate_type: str
    transport: str
    iteration: int
    cluster_responses: Dict[str, List[Tuple[str, bytes]]]

    response_metadata: Dict[str, List[dict]] = field(default_factory=dict)

def parse_nested_record(record: dict) -> Optional[RecordFacts]:
    """Extract immutable response facts and the explicit mutation target."""
    if not isinstance(record, dict):
        return None
    packet_hex = record.get("packet_hex")
    if not packet_hex or not isinstance(packet_hex, str):
        return None
    cluster_responses: Dict[str, List[Tuple[str, bytes]]] = {}
    response_metadata: Dict[str, List[dict]] = {}
    responses = record.get("responses")
    if not isinstance(responses, list):
        return None
    for group in responses:
        if not isinstance(group, dict):
            return None
        if isinstance(group.get("responses"), list):
            cluster = str(group.get("service") or "")
            member_entries = group.get("responses", [])
        else:
            
            member = str(group.get("service") or "")
            if not member:
                return None
            from config import cluster_of
            cluster = str(cluster_of(member))
            member_entries = [group]
        if not cluster:
            return None
        for member_entry in member_entries:
            if not isinstance(member_entry, dict):
                continue
            member = str(member_entry.get("service") or "")
            if not member:
                continue
            rhex = str(member_entry.get("response_hex") or "")
            bhex = str(member_entry.get("banner_hex") or "")
            declared_phase = member_entry.get("response_phase")
            raw_facts: List[Tuple[str, dict]] = []
            if declared_phase is None:

                src = rhex or bhex
                if src:
                    raw_facts.append(
                        (src, {"response_phase": PHASE_LEGACY_UNKNOWN}))
            else:
                banner_is_response = (
                    str(declared_phase) == PHASE_PRE_PAYLOAD_BANNER
                    and bool(rhex) and bool(bhex) and rhex == bhex)
                if bhex and not banner_is_response:
                    raw_facts.append(
                        (bhex, {"response_phase": PHASE_PRE_PAYLOAD_BANNER}))
                if rhex:
                    raw_facts.append((rhex, {"response_phase": (
                        PHASE_PRE_PAYLOAD_BANNER if banner_is_response
                        else PHASE_POST_PAYLOAD)}))
            for src, meta in raw_facts:
                try:
                    resp = bytes.fromhex(src)
                except ValueError:
                    continue
                cluster_responses.setdefault(cluster, []).append((member, resp))
                response_metadata.setdefault(cluster, []).append(dict(meta))
    if not cluster_responses:
        return None
    return RecordFacts(
        packet_hex=packet_hex,
        packet_hash=packet_hash_from_hex(packet_hex),
        mutation_target=str(record.get("mutation_target") or ""),
        candidate_type=str(record.get("candidate_type") or "multi_probe"),
        transport=str(record.get("transport") or ""),
        iteration=int(record.get("iteration") or 0),
        cluster_responses=cluster_responses,
        response_metadata=response_metadata,
    )

@dataclass
class RecordEvaluation:
    """Prepared record and pending samples for the identification engine."""
    entry: dict
    samples: List[dict]

def prepare_record_eval(
    facts: RecordFacts,
    engine_coverage: Set[str],
    novelty: Optional[NoveltyTracker] = None,
    split_key: str = DEFAULT_SPLIT_KEY,
    eval_ratio: float = DEFAULT_EVAL_RATIO,
    partition_resolver: Optional[Callable[[bytes], str]] = None,
) -> RecordEvaluation:
    """Assign splits, calculate proxies and gather bounded evaluation samples."""
    if split_key not in VALID_SPLIT_KEYS:
        raise ValueError(f"invalid split_key {split_key!r}")
    if partition_resolver is not None and not callable(partition_resolver):
        raise ValueError("partition_resolver must be callable(response_bytes)->str")

    no_rule_clusters = [c for c in facts.cluster_responses if c not in engine_coverage]
    proxy_metrics = proxy_metrics_for_packet(
        {c: facts.cluster_responses[c] for c in no_rule_clusters}, novelty=novelty)

    clusters_out: Dict[str, dict] = {}
    samples: List[dict] = []
    for cluster, responses in facts.cluster_responses.items():
        meta_list = facts.response_metadata.get(cluster) or []
        facts_list = []
        eval_list: List[Tuple[int, str, bytes]] = []   # (fact_index, member, resp)
        for fact_index, (member, resp) in enumerate(responses):
            meta = meta_list[fact_index] if fact_index < len(meta_list) else {}
            phase = str(meta.get("response_phase") or PHASE_LEGACY_UNKNOWN)
            sha_hex = response_sha(resp)
            if partition_resolver is not None:
                split = partition_resolver(resp)
                if split not in VALID_EXTERNAL_PARTITIONS:
                    raise ValueError(
                        f"partition_resolver returned invalid partition {split!r}; "
                        f"expected one of {list(VALID_EXTERNAL_PARTITIONS)}")
            else:
                split = stable_split_label(
                    facts.packet_hash, facts.mutation_target, member, sha_hex,
                    split_key=split_key, eval_ratio=eval_ratio)
            facts_list.append({
                "member": member, "sha": sha_hex, "len": len(resp),
                "split": split, "response_phase": phase})
            if split == SPLIT_EVAL:
                eval_list.append((fact_index, member, resp))
        entry_cluster: dict = {
            "responses": facts_list,
            "proxy": None,
            "not_evaluable_reason": "",
        }
        if cluster not in engine_coverage:
            entry_cluster["status"] = STATUS_PROXY
            entry_cluster["engine_covered"] = False
            entry_cluster["score"] = (
                proxy_metrics[cluster]["proxy_score"]
                if proxy_metrics.get(cluster) else None)
            entry_cluster["proxy"] = proxy_metrics.get(cluster)
            entry_cluster["members"] = {
                m: MEMBER_STATUS_NOT_RUN for _fi, m, _r in eval_list}
        else:
            entry_cluster["engine_covered"] = True
            entry_cluster["status"] = STATUS_UNKNOWN    
            entry_cluster["score"] = None
            entry_cluster["not_evaluable_reason"] = "engine evaluation pending"
            entry_cluster["members"] = {}
            for eval_index, (fact_index, member, resp) in enumerate(eval_list):
                meta = meta_list[fact_index] if fact_index < len(meta_list) else {}
                samples.append({
                    "key": "{}|{}|{}|{}|{}".format(
                        facts.packet_hash, cluster, member,
                        response_sha(resp), eval_index),
                    "cluster": cluster,
                    "member": member,
                    "response": resp,
                    "fact_index": fact_index,
                    "response_phase": str(
                        meta.get("response_phase") or PHASE_LEGACY_UNKNOWN),
                })
        clusters_out[cluster] = entry_cluster

    entry = {
        "packet_hash": facts.packet_hash,
        "mutation_target": facts.mutation_target,
        "candidate_type": facts.candidate_type,
        "transport": facts.transport,
        "iteration": facts.iteration,
        "engine_mode": ENGINE_MODE,
        "n_clusters_triggered": len(facts.cluster_responses),
        "clusters": clusters_out,
        "identifiable_clusters": [],
        "identifiable_observed_pairs": [],
        "identifiable_active_pairs": [],
        "banner_identifiable_pairs": [],
        "cluster_identifiable_pairs": [],
        "exact_identifiable_pairs": [],
        "ambiguous_identifiable_pairs": [],
        "member_code_confirmed_pairs": [],
        "score": None,
        "not_evaluable_reason": "",
    }
    _finalize_entry_scores(entry)
    return RecordEvaluation(entry=entry, samples=samples)

def finalize_record_eval(
    evaluation: RecordEvaluation,
    predictions: Dict[str, dict],
    engine_error: str = "",
) -> dict:
    """Attach engine predictions and preserve phase-aware identification facts."""
    entry = evaluation.entry
    by_cluster: Dict[str, List[dict]] = {}
    for sample in evaluation.samples:
        pred_key = sample["key"]
        pred = predictions.get(pred_key)
        by_cluster.setdefault(sample["cluster"], []).append(
            {"sample": sample, "pred": pred})

    sampled_clusters = set(by_cluster.keys())
    for cluster, c_entry in entry["clusters"].items():
        if c_entry.get("status") == STATUS_UNKNOWN and cluster not in sampled_clusters \
                and c_entry.get("not_evaluable_reason") == "engine evaluation pending":
            c_entry["not_evaluable_reason"] = "no eval-split responses (all train)"

    for cluster, group in by_cluster.items():
        c_entry = entry["clusters"].get(cluster)
        if c_entry is None or c_entry.get("status") not in (STATUS_UNKNOWN,):
            continue
        if c_entry.get("not_evaluable_reason") != "engine evaluation pending":
            continue

        if engine_error:
            c_entry["status"] = STATUS_UNKNOWN
            c_entry["not_evaluable_reason"] = f"engine harness error: {engine_error}"
            continue

        any_pred = False
        correct = False
        ambiguous_correct = False
        member_correct: Dict[str, bool] = {}
        member_correct_cluster: Dict[str, bool] = {}
        member_correct_phases: Dict[str, Set[str]] = {}   
        for item in group:
            sample, pred = item["sample"], item["pred"]
            fact_index = int(sample.get("fact_index", -1))
            resp_facts = c_entry.get("responses") or []
            resp_fact = (
                resp_facts[fact_index]
                if 0 <= fact_index < len(resp_facts) else None)
            if pred is None:
                if resp_fact is not None:
                    resp_fact["pred"] = None
                continue
            p = str(pred.get("pred") or "")
            matches = pred.get("matches") or []
            candidates = sorted({str(c) for c in (pred.get("candidates") or [])
                                 if str(c)})
            if not candidates:

                candidates = [p] if p else []
            canonical = identification_cluster_of(cluster)
            valid_equivalence = bool(candidates) and all(
                identification_cluster_of(candidate) == canonical
                for candidate in candidates)
            is_exact = (p == cluster and candidates == [cluster])
            is_ambiguous_correct = (
                cluster in candidates and len(candidates) > 1
                and valid_equivalence and identification_cluster_of(p) == canonical)
            if resp_fact is not None:

                resp_fact["pred"] = p
                resp_fact["pred_source"] = pred.get("source", "")
                resp_fact["pred_tier"] = pred.get("tier", 0)
                resp_fact["n_matches"] = len(matches)
                resp_fact["candidates"] = candidates
                resp_fact["ambiguous"] = len(candidates) > 1 or len(matches) > 1
                resp_fact["ambiguity_valid"] = bool(is_ambiguous_correct)
            if p:
                any_pred = True
            is_correct = is_exact or is_ambiguous_correct
            if is_correct:
                correct = True
                ambiguous_correct = ambiguous_correct or is_ambiguous_correct
                member_correct_cluster[sample["member"]] = True
                member_correct_phases.setdefault(sample["member"], set()).add(
                    str(sample.get("response_phase") or PHASE_LEGACY_UNKNOWN))
                resolved = str(pred.get("member") or "")
                if resolved == sample["member"] and pred.get("member_source") == "member_code":
                    member_correct[sample["member"]] = True
        if correct:
            c_entry["status"] = (
                STATUS_AMBIGUOUS_CONFIRMED if ambiguous_correct
                else STATUS_RULE_CONFIRMED)
            c_entry["score"] = 1.0
            c_entry["not_evaluable_reason"] = ""
        elif any_pred:
            c_entry["status"] = STATUS_RULE_REJECTED
            c_entry["score"] = 0.0
            primary_preds = sorted({
                str(item["pred"].get("pred") or "")
                for item in group if item["pred"] is not None
                and item["pred"].get("pred")
            })
            c_entry["not_evaluable_reason"] = (
                "engine primary never == this cluster (primary predictions: "
                + ", ".join(primary_preds) + ")")
        else:
            c_entry["status"] = STATUS_UNKNOWN
            c_entry["not_evaluable_reason"] = "engine returned unknown for all eval responses"

        members: Dict[str, str] = {}
        for item in group:
            member = item["sample"]["member"]
            if c_entry["status"] in (
                    STATUS_RULE_CONFIRMED, STATUS_AMBIGUOUS_CONFIRMED) and \
                    member_correct_cluster.get(member):
                members[member] = (
                    MEMBER_STATUS_CONFIRMED if member_correct.get(member)
                    else MEMBER_STATUS_UNKNOWN)
            else:
                members[member] = MEMBER_STATUS_NOT_RUN
        c_entry["members"] = members
        if c_entry["status"] in (
                STATUS_RULE_CONFIRMED, STATUS_AMBIGUOUS_CONFIRMED):

            c_entry["member_correct_phases"] = {
                m: sorted(phases)
                for m, phases in member_correct_phases.items()
                if member_correct_cluster.get(m)
            }

    _finalize_entry_scores(entry)
    _finalize_response_outcome_counts(entry)
    return entry

def _finalize_entry_scores(entry: dict) -> None:
    """Aggregate correctly identified services and implementation pairs."""
    scores = []
    identifiable_clusters: Set[str] = set()
    for cluster, c_entry in sorted(entry["clusters"].items()):
        if c_entry.get("status") in (
                STATUS_RULE_CONFIRMED, STATUS_AMBIGUOUS_CONFIRMED):
            identifiable_clusters.add(cluster)
        score = c_entry.get("score")
        if score is not None:
            scores.append(float(score))
    entry["identifiable_clusters"] = sorted(identifiable_clusters)

    observed_pairs: Set[Tuple[str, str]] = set()
    exact_pairs: Set[Tuple[str, str]] = set()
    ambiguous_pairs: Set[Tuple[str, str]] = set()
    active_pairs: Set[Tuple[str, str]] = set()
    banner_pairs: Set[Tuple[str, str]] = set()
    member_pairs: List[List[str]] = []
    for cluster, c_entry in sorted(entry["clusters"].items()):
        if c_entry.get("status") not in (
                STATUS_RULE_CONFIRMED, STATUS_AMBIGUOUS_CONFIRMED):
            continue
        phases_by_member = c_entry.get("member_correct_phases") or {}
        for member, status in sorted(c_entry.get("members", {}).items()):
            if status in (MEMBER_STATUS_CONFIRMED, MEMBER_STATUS_UNKNOWN):
                observed_pairs.add((cluster, member))   
                if c_entry.get("status") == STATUS_AMBIGUOUS_CONFIRMED:
                    ambiguous_pairs.add((cluster, member))
                else:
                    exact_pairs.add((cluster, member))
            if status == MEMBER_STATUS_CONFIRMED:
                member_pairs.append([cluster, member])
            for phase in phases_by_member.get(member, []):
                if phase == PHASE_POST_PAYLOAD:
                    active_pairs.add((cluster, member))
                elif phase == PHASE_PRE_PAYLOAD_BANNER:
                    banner_pairs.add((cluster, member))
                
    entry["identifiable_observed_pairs"] = [list(p) for p in sorted(observed_pairs)]
    entry["identifiable_active_pairs"] = [list(p) for p in sorted(active_pairs)]
    entry["banner_identifiable_pairs"] = [list(p) for p in sorted(banner_pairs)]
    entry["cluster_identifiable_pairs"] = [list(p) for p in sorted(observed_pairs)]
    entry["exact_identifiable_pairs"] = [list(p) for p in sorted(exact_pairs)]
    entry["ambiguous_identifiable_pairs"] = [
        list(p) for p in sorted(ambiguous_pairs)]
    entry["member_code_confirmed_pairs"] = member_pairs
    entry["score"] = (sum(scores) / len(scores)) if scores else None
    if not entry["clusters"]:
        entry["not_evaluable_reason"] = "no evaluable clusters"

def _finalize_response_outcome_counts(entry: dict) -> None:
    """Attach response-fact counts used by phase-aware selection reports.

    Only facts sent to the frozen cascade receive a rule outcome.  V3 strict
    mode evaluates the whole bound source; formal held-out status is supplied
    by a separate probe-family validation artifact, not a response-byte split.
    ``phase_missing`` is orthogonal and counts every legacy/unknown-phase fact.
    """
    counts: Counter = Counter()
    for cluster, cluster_entry in (entry.get("clusters") or {}).items():
        engine_covered = bool(cluster_entry.get("engine_covered"))
        for fact in cluster_entry.get("responses") or []:
            phase = str(fact.get("response_phase") or PHASE_LEGACY_UNKNOWN)
            if phase not in (PHASE_POST_PAYLOAD, PHASE_PRE_PAYLOAD_BANNER):
                counts["phase_missing"] += 1
            if fact.get("split") != SPLIT_EVAL:
                counts["not_eval_partition"] += 1
                continue
            if not engine_covered:
                counts["proxy"] += 1
                continue
            prediction = str(fact.get("pred") or "")
            candidates = {str(c) for c in (fact.get("candidates") or []) if str(c)}
            if prediction == cluster and candidates in (set(), {cluster}):
                counts["rule_confirmed"] += 1
            elif (cluster in candidates and len(candidates) > 1
                  and all(identification_cluster_of(candidate)
                          == identification_cluster_of(cluster)
                          for candidate in candidates)):
                counts["ambiguous_confirmed"] += 1
            elif prediction:
                counts["rule_rejected"] += 1
            else:
                counts["unknown"] += 1
    entry["response_outcome_counts"] = {
        key: int(counts.get(key, 0))
        for key in (
            "rule_confirmed", "ambiguous_confirmed", "rule_rejected", "unknown", "proxy",
            "not_eval_partition", "phase_missing")
    }

# ============================================================================

# ============================================================================

@dataclass
class WriterStats:
    n_records: int = 0
    n_entries: int = 0
    n_skipped_schema: int = 0
    n_skipped_diagnostic: int = 0
    n_duplicated_packet: int = 0
    n_engine_samples: int = 0
    cluster_status_counts: Counter = field(default_factory=Counter)

class DistinguishabilityArtifactWriter:
    """Stream entries and a manifest with on-disk deduplication."""

    def __init__(self, out_dir: str) -> None:
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._entries_path = self.out_dir / ENTRIES_FILENAME
        self._fh = open(self._entries_path, "w", encoding="utf-8")
        self._hasher = hashlib.sha256()
        self.stats = WriterStats()
        self._dedup_dir = tempfile.mkdtemp(prefix="distinguish_dedup_")
        self._dedup_conn = sqlite3.connect(
            os.path.join(self._dedup_dir, "dedup.db"))
        self._dedup_conn.execute(
            "CREATE TABLE seen (packet_hash TEXT PRIMARY KEY)")
        self._closed = False

    def write_entry(self, entry: dict) -> bool:
        """Write one entry using first-seen packet-hash deduplication."""
        cur = self._dedup_conn.execute(
            "INSERT OR IGNORE INTO seen (packet_hash) VALUES (?)",
            (entry["packet_hash"],))
        self._dedup_conn.commit()
        if cur.rowcount != 1:
            self.stats.n_duplicated_packet += 1
            return False
        line = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        self._fh.write(line + "\n")
        self._hasher.update((line + "\n").encode("utf-8"))
        self.stats.n_entries += 1
        for c_entry in entry["clusters"].values():
            self.stats.cluster_status_counts[c_entry.get("status", "?")] += 1
        return True

    def close(self) -> None:
        """Close."""
        if self._closed:
            return
        self._closed = True
        try:
            if not self._fh.closed:
                self._fh.flush()
                self._fh.close()
        finally:
            try:
                self._dedup_conn.close()
            except sqlite3.Error:
                pass
            shutil.rmtree(self._dedup_dir, ignore_errors=True)

    def finalize(self, manifest_fields: dict) -> dict:
        self.close()      
        manifest = dict(manifest_fields)
        manifest["schema_version"] = SCHEMA_VERSION
        manifest["artifact_type"] = ARTIFACT_TYPE
        manifest["evaluator_version"] = EVALUATOR_VERSION
        manifest["engine_mode"] = ENGINE_MODE
        manifest["engine_implementation"] = ENGINE_IMPLEMENTATION
        manifest["proxy_version"] = PROXY_VERSION
        manifest["dedup_policy"] = DEDUP_POLICY
        manifest["entries_file"] = ENTRIES_FILENAME
        manifest["n_entries"] = self.stats.n_entries
        manifest["entries_sha256"] = self._hasher.hexdigest()[:16]
        manifest["status_counts"] = dict(sorted(self.stats.cluster_status_counts.items()))
        manifest.setdefault("leakage_status", LEAKAGE_UNVERIFIED)
        manifest.setdefault("notes", {})
        manifest["notes"].update({
            "proxy_not_accuracy": PROXY_NOT_ACCURACY_NOTE,
            "engine_mode_note": RULES_ONLY_NOTE,
            "identification_semantics": (
                "rule_confirmed requires an exact singleton candidate; "
                "ambiguous_confirmed requires the ground-truth cluster to be in "
                "a declared identification-equivalence candidate group. Cross-group "
                "multi-matches remain confusion and are NOT confirmed"
            ),
            "member_semantics": (
                "Stage B runs only when cluster primary is correct; member_code "
                "(compiled MemberResolveCode) only — 4-form member rules are not "
                "runtime Stage B and never yield member_code_confirmed"
            ),
            "pair_semantics": (
                "cluster_identifiable_pairs = members with >=1 eval response "
                "correctly cluster-identified; member_code_confirmed_pairs is a "
                "separate stricter metric, never mixed into cluster coverage"
            ),
            "phase_accounting": (
                "identifiable_observed_pairs counts members with >=1 correct eval "
                "response of ANY phase (cluster_identifiable_pairs is a legacy "
                "alias of it); identifiable_active_pairs counts correct "
                "post_payload responses only; banner_identifiable_pairs counts "
                "correct pre_payload_banner responses only; a single response "
                "flagged pre_payload_banner with response_hex==banner_hex is one "
                "banner fact (never double-counted); phase-less legacy responses "
                "count toward observed only; pairs are deduplicated per "
                "(cluster, member), so banner+post both correct = one observed pair"
            ),
            "direction_semantics": "mutation_target only; origin_protocol is never read",
            "split_semantics": (
                "engine predictions counted on eval-split responses only; "
                "train-only clusters are unknown"
            ),
        })
        manifest["manifest_core_hash"] = manifest_core_hash(manifest)
        atomic_write_json(str(self.out_dir / MANIFEST_FILENAME), manifest)
        return manifest

def manifest_core_hash(manifest: dict) -> str:
    """Hash semantic manifest fields excluding creation time and absolute paths."""
    core_keys = (
        "schema_version", "artifact_type", "evaluator_version", "engine_mode",
        "engine_implementation", "proxy_version", "objective_version", "rules",
        "engine",
        "split", "source_digest", "source_totals", "n_entries", "entries_sha256",
        "status_counts", "leakage_status", "provenance", "dedup_policy",
        "engine_meta", "novelty_tracker_capped", "strict_rule_bundle", "notes",
    )
    core = {k: manifest[k] for k in core_keys if k in manifest}
    return hashlib.sha256(
        json.dumps(core, sort_keys=True).encode("utf-8")).hexdigest()[:16]

def atomic_write_json(path: str, obj: dict) -> None:
    """Write JSON through a flushed temporary file and atomic replacement."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

# ============================================================================

# ============================================================================

class DistinguishabilityIndex:
    """Read-only disk index of evaluation entries keyed by packet hash."""

    def __init__(self, manifest: dict, db_path: str) -> None:
        self.manifest = manifest
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS entries ("
            " packet_hash TEXT PRIMARY KEY,"
            " statuses TEXT, ident_pairs TEXT, member_pairs TEXT, proxies TEXT,"
            " active_pairs TEXT, banner_pairs TEXT, outcome_counts TEXT,"
            " exact_pairs TEXT, ambiguous_pairs TEXT)")
        
        existing_cols = {
            r[1] for r in self._conn.execute("PRAGMA table_info(entries)")}
        for col in ("active_pairs", "banner_pairs", "outcome_counts",
                    "exact_pairs", "ambiguous_pairs"):
            if col not in existing_cols:
                self._conn.execute(
                    f"ALTER TABLE entries ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")

    def _insert_rows(self, rows: List[tuple]) -> None:
        self._conn.executemany(
            "INSERT OR REPLACE INTO entries ("
            "packet_hash,statuses,ident_pairs,member_pairs,proxies,active_pairs,"
            "banner_pairs,outcome_counts,exact_pairs,ambiguous_pairs) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _row(self, packet_hash: str) -> Optional[tuple]:
        cur = self._conn.execute(
            "SELECT statuses, ident_pairs, member_pairs, proxies, active_pairs, "
            "banner_pairs, outcome_counts, exact_pairs, ambiguous_pairs "
            "FROM entries WHERE packet_hash = ?",
            (packet_hash,))
        return cur.fetchone()

    def entry_loaded(self, packet_hash: str) -> bool:
        return self._row(packet_hash) is not None

    def observed_identifiable_pairs(
            self, packet_hash: str) -> FrozenSet[Tuple[str, str]]:
        """Return correctly identified service/implementation pairs in either phase."""
        row = self._row(packet_hash)
        if row is None or not row[1]:
            return frozenset()
        return frozenset(tuple(p) for p in json.loads(row[1]))

    def active_identifiable_pairs(
            self, packet_hash: str) -> FrozenSet[Tuple[str, str]]:
        """Return correctly identified post-send service/implementation pairs."""
        row = self._row(packet_hash)
        if row is None or not row[4]:
            return frozenset()
        return frozenset(tuple(p) for p in json.loads(row[4]))

    def banner_identifiable_pairs(
            self, packet_hash: str) -> FrozenSet[Tuple[str, str]]:
        """Return correctly identified pre-payload banner pairs."""
        row = self._row(packet_hash)
        if row is None or not row[5]:
            return frozenset()
        return frozenset(tuple(p) for p in json.loads(row[5]))

    def response_outcome_counts(self, packet_hash: str) -> Dict[str, int]:
        """Return eval-response outcomes and phase-missing facts for one packet.

        Counts are response-fact counts, not cluster counts.  Older artifacts
        have no compact outcome column and therefore return an empty mapping;
        formal phase-aware reports must reject that absence explicitly.
        """
        row = self._row(packet_hash)
        if row is None or len(row) < 7 or not row[6]:
            return {}
        raw = json.loads(row[6])
        return {str(key): int(value) for key, value in raw.items()}

    def identifiable_pairs(self, packet_hash: str) -> FrozenSet[Tuple[str, str]]:
        """Compatibility alias for coverage in either phase."""
        return self.observed_identifiable_pairs(packet_hash)

    def exact_identifiable_pairs(
            self, packet_hash: str) -> FrozenSet[Tuple[str, str]]:
        """Pairs resolved to one exact service label."""
        row = self._row(packet_hash)
        if row is None or len(row) < 8 or not row[7]:
            return frozenset()
        return frozenset(tuple(p) for p in json.loads(row[7]))

    def ambiguous_identifiable_pairs(
            self, packet_hash: str) -> FrozenSet[Tuple[str, str]]:
        """Pairs resolved only to an evidence-configured equivalent set."""
        row = self._row(packet_hash)
        if row is None or len(row) < 9 or not row[8]:
            return frozenset()
        return frozenset(tuple(p) for p in json.loads(row[8]))

    def identifiable_clusters(self, packet_hash: str) -> FrozenSet[str]:
        return frozenset(c for c, _m in self.identifiable_pairs(packet_hash))

    def member_confirmed_pairs(self, packet_hash: str) -> FrozenSet[Tuple[str, str]]:
        row = self._row(packet_hash)
        if row is None or not row[2]:
            return frozenset()
        return frozenset(tuple(p) for p in json.loads(row[2]))

    def cluster_status(self, packet_hash: str, cluster: str) -> Optional[str]:
        row = self._row(packet_hash)
        if row is None or not row[0]:
            return None
        return json.loads(row[0]).get(cluster)

    def proxy_multiplier(self, packet_hash: str,
                         triggered_clusters: Iterable[str]) -> Optional[float]:
        row = self._row(packet_hash)
        if row is None or not row[3]:
            return None
        proxies = json.loads(row[3])
        scores = [
            proxies[c] for c in triggered_clusters
            if c in proxies and proxies[c] is not None
        ]
        if not scores:
            return None
        return sum(scores) / len(scores)

    def status_counts_over(self, packet_hashes: Iterable[str]) -> Dict[str, int]:
        counts: Counter = Counter()
        for ph in packet_hashes:
            row = self._row(ph)
            if row is None or not row[0]:
                continue
            for status in json.loads(row[0]).values():
                counts[status] += 1
        return dict(sorted(counts.items()))

    @property
    def artifact_hash(self) -> str:
        return str(self.manifest.get("manifest_core_hash", ""))

    @property
    def objective_version(self) -> Optional[str]:
        value = self.manifest.get("objective_version")
        return str(value) if value is not None else None

    @property
    def engine_mode(self) -> str:
        return str(self.manifest.get("engine_mode", ""))

    @property
    def leakage_status(self) -> str:
        return str(self.manifest.get("leakage_status", LEAKAGE_UNVERIFIED))

    @property
    def rule_digest(self) -> str:
        return str(self.manifest.get("rules", {}).get("digest", ""))

    @property
    def source_digest(self) -> str:
        return str(self.manifest.get("source_digest", ""))

    @property
    def n_entries(self) -> int:
        return int(self.manifest.get("n_entries", 0))

    def summary(self) -> dict:
        return {
            "manifest_core_hash": self.artifact_hash,
            "objective_version": self.objective_version,
            "engine_mode": self.engine_mode,
            "leakage_status": self.leakage_status,
            "rule_digest": self.rule_digest,
            "source_digest": self.source_digest,
            "n_entries": self.n_entries,
            "split": self.manifest.get("split", {}),
            "status_counts": self.manifest.get("status_counts", {}),
        }

def validate_manifest(
    manifest: dict,
    expected_objective_version: Optional[str] = None,
    expected_rule_digest: Optional[str] = None,
    expected_source_digest: Optional[str] = None,
    expected_engine_mode: Optional[str] = ENGINE_MODE,
    require_leakage_verified: bool = False,
    expected_runtime_digest: Optional[str] = None,
) -> None:
    """Reject incompatible or incomplete evaluation provenance."""
    if not isinstance(manifest, dict):
        raise ValueError("manifest is not a JSON object")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"manifest schema_version mismatch: {manifest.get('schema_version')!r} "
            f"!= {SCHEMA_VERSION}")
    if manifest.get("artifact_type") != ARTIFACT_TYPE:
        raise ValueError(
            f"manifest artifact_type mismatch: {manifest.get('artifact_type')!r}")
    for key, known in (
        ("evaluator_version", KNOWN_EVALUATOR_VERSIONS),
        ("proxy_version", KNOWN_PROXY_VERSIONS),
        ("engine_mode", KNOWN_ENGINE_MODES),
        ("engine_implementation", KNOWN_ENGINE_IMPLEMENTATIONS),
    ):
        if manifest.get(key) not in known:
            raise ValueError(
                f"manifest {key} mismatch: {manifest.get(key)!r} not in {list(known)}")
    stored = manifest.get("manifest_core_hash")
    recomputed = manifest_core_hash(manifest)
    if stored != recomputed:
        raise ValueError(
            f"manifest_core_hash mismatch (stored={stored!r}, recomputed="
            f"{recomputed!r}) — file corrupted or edited after generation")
    leakage = manifest.get("leakage_status")
    if leakage not in VALID_LEAKAGE_STATUS:
        raise ValueError(f"manifest leakage_status invalid: {leakage!r}")
    if require_leakage_verified and leakage != LEAKAGE_VERIFIED:
        raise ValueError(
            "artifact leakage_status is not 'verified' — rules lack train-split "
            "training provenance; rule-confirmed results would self-certify on "
            "the rule-generation corpus")
    if expected_engine_mode is not None and manifest.get("engine_mode") != expected_engine_mode:
        raise ValueError(
            f"artifact engine_mode mismatch: artifact={manifest.get('engine_mode')!r}, "
            f"expected={expected_engine_mode!r}")
    if expected_objective_version is not None:
        if manifest.get("objective_version") != expected_objective_version:
            raise ValueError(
                f"artifact objective_version mismatch: artifact="
                f"{manifest.get('objective_version')!r}, expected="
                f"{expected_objective_version!r}")
    if expected_rule_digest is not None:
        if manifest.get("rules", {}).get("digest") != expected_rule_digest:
            raise ValueError(
                f"artifact rule digest mismatch: artifact="
                f"{manifest.get('rules', {}).get('digest')!r}, expected="
                f"{expected_rule_digest!r}")
    if expected_source_digest is not None:
        if manifest.get("source_digest") != expected_source_digest:
            raise ValueError(
                f"artifact source digest mismatch: artifact="
                f"{manifest.get('source_digest')!r}, expected="
                f"{expected_source_digest!r} — selection library differs from "
                f"the evaluated library")
    if expected_runtime_digest is not None:
        stored_runtime = manifest.get("engine", {}).get("runtime_registry_digest")
        if stored_runtime != expected_runtime_digest:
            raise ValueError(
                f"artifact runtime registry digest mismatch: artifact="
                f"{stored_runtime!r}, expected={expected_runtime_digest!r} — "
                f"compiled Go registries / cascade implementation changed since "
                f"evaluation; the runtime classifier differs even if JSON rules "
                f"are unchanged")

_INDEX_CACHE: Dict[Tuple[str, str], str] = {}
_INDEX_TEMP_DIRS: List[str] = []

def _cleanup_index_temp_dirs() -> None:
    """Remove process-owned temporary index directories at exit."""
    for d in _INDEX_TEMP_DIRS:
        shutil.rmtree(d, ignore_errors=True)
    _INDEX_TEMP_DIRS.clear()
    _INDEX_CACHE.clear()

atexit.register(_cleanup_index_temp_dirs)

def load_distinguishability_artifact(
    artifact_path: str,
    strict: bool = True,
    expected_objective_version: Optional[str] = None,
    expected_rule_digest: Optional[str] = None,
    expected_source_digest: Optional[str] = None,
    expected_engine_mode: Optional[str] = ENGINE_MODE,
    require_leakage_verified: bool = False,
    expected_runtime_digest: Optional[str] = None,
) -> Optional[DistinguishabilityIndex]:
    """Validate the manifest and stream entries into a disk index."""
    path = Path(artifact_path)
    base = path.parent if path.name == MANIFEST_FILENAME else path
    manifest_file = base / MANIFEST_FILENAME
    entries_file = base / ENTRIES_FILENAME
    index: Optional[DistinguishabilityIndex] = None
    tmp_dir: Optional[str] = None
    try:
        if not manifest_file.is_file():
            raise ValueError(f"manifest not found: {manifest_file}")
        with open(manifest_file, encoding="utf-8") as fh:
            manifest = json.load(fh)
        validate_manifest(
            manifest,
            expected_objective_version=expected_objective_version,
            expected_rule_digest=expected_rule_digest,
            expected_source_digest=expected_source_digest,
            expected_engine_mode=expected_engine_mode,
            require_leakage_verified=require_leakage_verified,
            expected_runtime_digest=expected_runtime_digest,
        )
        if not entries_file.is_file():
            raise ValueError(f"entries file not found: {entries_file}")

        cache_key = (str(base.resolve()), str(manifest.get("manifest_core_hash", "")))
        cached = _INDEX_CACHE.get(cache_key)
        if cached is not None and os.path.exists(cached):
            return DistinguishabilityIndex(manifest, cached)

        tmp_dir = tempfile.mkdtemp(prefix="distinguish_index_")
        _INDEX_TEMP_DIRS.append(tmp_dir)
        db_path = os.path.join(tmp_dir, "index.db")
        index = DistinguishabilityIndex(manifest, db_path)
        hasher = hashlib.sha256()
        n_entries = 0
        rows: List[tuple] = []
        with open(entries_file, encoding="utf-8") as fh:
            for line in fh:
                hasher.update(line.encode("utf-8"))
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                ph = entry.get("packet_hash")
                if not ph:
                    raise ValueError("entries.jsonl contains entry without packet_hash")
                n_entries += 1
                clusters = entry.get("clusters", {})
                observed = entry.get("identifiable_observed_pairs")
                if observed is None:

                    observed = entry.get("cluster_identifiable_pairs", [])
                rows.append((
                    ph,
                    json.dumps({str(c): ce.get("status", STATUS_UNKNOWN)
                                for c, ce in clusters.items()}, sort_keys=True),
                    json.dumps(observed),
                    json.dumps(entry.get("member_code_confirmed_pairs", [])),
                    json.dumps({
                        str(c): ce["proxy"]["proxy_score"]
                        for c, ce in clusters.items()
                        if ce.get("proxy") and ce["proxy"].get("proxy_score") is not None
                    }, sort_keys=True),
                    json.dumps(entry.get("identifiable_active_pairs", [])),
                    json.dumps(entry.get("banner_identifiable_pairs", [])),
                    json.dumps(entry.get("response_outcome_counts", {}),
                               sort_keys=True),
                    json.dumps(entry.get("exact_identifiable_pairs", [])),
                    json.dumps(entry.get("ambiguous_identifiable_pairs", [])),
                ))
                if len(rows) >= 10_000:
                    index._insert_rows(rows)
                    rows = []
        if rows:
            index._insert_rows(rows)
        if n_entries != int(manifest.get("n_entries", -1)):
            raise ValueError(
                f"entries count mismatch: file has {n_entries}, manifest says "
                f"{manifest.get('n_entries')!r}")
        if hasher.hexdigest()[:16] != manifest.get("entries_sha256"):
            raise ValueError(
                "entries_sha256 mismatch — entries.jsonl corrupted or edited "
                "after generation")
        _INDEX_CACHE[cache_key] = db_path
        return index
    except (ValueError, OSError, sqlite3.Error) as exc:
        
        if index is not None:
            try:
                index.close()
            except sqlite3.Error:
                pass
        if tmp_dir is not None and tmp_dir in _INDEX_TEMP_DIRS:
            _INDEX_TEMP_DIRS.remove(tmp_dir)
            shutil.rmtree(tmp_dir, ignore_errors=True)
        if strict:
            raise
        logger.warning(
            "[DISTINGUISHABILITY] artifact rejected (fallback to mode 'none'): %s",
            exc,
        )
        return None
