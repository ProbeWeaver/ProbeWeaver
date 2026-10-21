"""Stream nested candidate records and select probes by weighted marginal identifiable coverage. Keep TCP/UDP universes separate, count each service/implementation pair once, and preserve candidate eligibility and artifact provenance. Response presence alone does not establish identification."""

import argparse
import copy
import json
import logging
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

from tqdm import tqdm

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("MALLOC_ARENA_MAX", "8")

import config
from config import SERVICE_CLUSTERS, cluster_of
from core.clustering import (
    record_candidate_type,
    record_mutation_target,
)
from core.distinguishability import (
    PHASE_POST_PAYLOAD,
    PHASE_PRE_PAYLOAD_BANNER,
    PROXY_NOT_ACCURACY_NOTE,
    packet_hash_from_hex,
)
from core.candidate_collector import (
    CANDIDATE_EXPLORATORY_MULTI_PROBE,
    CANDIDATE_MULTI_PROBE,
    CANDIDATE_TARGET_REACHABILITY,
)
from core.candidate_stability import candidate_identity_digest
from core.candidate_stream import iter_candidate_stream

logger = logging.getLogger("select_packets")

VALID_DISTINGUISHABILITY_MODES = ("none", "proxy", "rule-confirmed")

CANDIDATE_ADMISSION_LEGACY = "legacy"
CANDIDATE_ADMISSION_STRICT = "strict"
CANDIDATE_ADMISSION_VALIDATED_EXPANDED = "validated-expanded"
VALID_CANDIDATE_ADMISSION_MODES = (
    CANDIDATE_ADMISSION_LEGACY,
    CANDIDATE_ADMISSION_STRICT,
    CANDIDATE_ADMISSION_VALIDATED_EXPANDED,
)
CANDIDATE_VALIDATED_EXPLORATORY = "validated_exploratory"
_STRICT_CANDIDATE_TYPES = frozenset({
    CANDIDATE_MULTI_PROBE,
    CANDIDATE_TARGET_REACHABILITY,
})
_KNOWN_RESPONSE_PHASES = frozenset({
    PHASE_POST_PAYLOAD,
    PHASE_PRE_PAYLOAD_BANNER,
})

from core.service_weights import (  # noqa: F401 (re-export)
    CENSYS_COUNTS,
    CENSYS_KEY_OF_CLUSTER,
    DEFAULT_COUNT,
    DEFAULT_SECURITY,
    SECURITY_WEIGHTS,
    censys_key_of_cluster,
    compute_cluster_weights,
    load_censys_counts,
    parse_summary_txt,
    weight_config_hash,
)

# ============================================================================

# ============================================================================

def _is_flat(record: dict) -> bool:
    """Detect a flat response list without implementation nesting."""
    responses = record.get("responses", [])
    if not isinstance(responses, list) or not responses:
        return False
    first = responses[0]
    return isinstance(first, dict) and "response_hex" in first and "responses" not in first

def _phase_pairs(record: dict) -> Tuple[
        Set[Tuple[str, str]], Set[Tuple[str, str]],
        Set[Tuple[str, str]], bool]:
    """Return observed/active/banner member pairs plus phase-awareness.

    This mirrors the evaluator's response expansion: Banner+post yields two
    phase facts, while ``pre_payload_banner`` with identical response/banner
    bytes remains one Banner fact.  Cluster identity is always derived from
    the member registry, never trusted from the outer group label.
    """
    observed: Set[Tuple[str, str]] = set()
    active: Set[Tuple[str, str]] = set()
    banner: Set[Tuple[str, str]] = set()
    phase_aware = True
    saw_fact = False
    for group in record.get("responses") or []:
        if not isinstance(group, dict):
            continue
        members = group.get("responses")
        if not isinstance(members, list):
            members = [group]
        for member_entry in members:
            if not isinstance(member_entry, dict):
                continue
            member = str(member_entry.get("service") or "")
            if not member:
                continue
            response_hex = str(member_entry.get("response_hex") or "")
            banner_hex = str(member_entry.get("banner_hex") or "")
            if not response_hex and not banner_hex:
                continue
            pair = (cluster_of(member), member)
            phase = member_entry.get("response_phase")
            if phase not in _KNOWN_RESPONSE_PHASES:
                phase_aware = False
                saw_fact = True
                observed.add(pair)
                continue
            saw_fact = True
            banner_is_response = (
                phase == PHASE_PRE_PAYLOAD_BANNER
                and bool(response_hex) and bool(banner_hex)
                and response_hex == banner_hex)
            if banner_hex and not banner_is_response:
                observed.add(pair)
                banner.add(pair)
            if response_hex:
                observed.add(pair)
                if banner_is_response:
                    banner.add(pair)
                else:
                    active.add(pair)
    return observed, active, banner, bool(saw_fact and phase_aware)

def _admit_candidate(
    record: dict,
    admission_mode: str,
    validated_exploratory_ids: Set[str],
) -> Tuple[bool, str]:
    candidate_type = record_candidate_type(record)
    if candidate_type == "diagnostic_only":
        return False, candidate_type
    if admission_mode == CANDIDATE_ADMISSION_LEGACY:
        return True, candidate_type
    if candidate_type in _STRICT_CANDIDATE_TYPES:
        return True, candidate_type
    if (admission_mode == CANDIDATE_ADMISSION_VALIDATED_EXPANDED
            and candidate_type == CANDIDATE_EXPLORATORY_MULTI_PROBE
            and candidate_identity_digest(record) in validated_exploratory_ids):
        return True, CANDIDATE_VALIDATED_EXPLORATORY
    return False, candidate_type

def _validate_admission_runtime(
    candidate_admission: str,
    effective_mode: str,
    formal_phase_aware: bool,
) -> None:
    """Fail closed when expanded admission loses its rule-confirmed runtime."""
    if candidate_admission != CANDIDATE_ADMISSION_VALIDATED_EXPANDED:
        return
    if effective_mode != "rule-confirmed":
        raise ValueError(
            "validated-expanded cannot fall back from rule-confirmed mode")
    if not formal_phase_aware:
        raise ValueError(
            "validated-expanded requires a strict phase-aware rule bundle "
            "evaluation artifact")

def _promotion_selection_binding_errors(
    promotion_artifact: dict,
    dist_index,
    packet_transport: str,
) -> List[str]:
    """Cross-check identities shared by promotion and final selection.

    Promotion evaluates the three-reprobe corpus, whereas final selection may
    evaluate the full candidate corpus.  Their evaluation manifest hashes are
    intentionally allowed to differ; the frozen rule bundle/runtime, objective
    and transport must be identical.
    """
    provenance = dist_index.manifest.get("provenance") or {}
    promotion_transport = str(
        (promotion_artifact.get("source_binding") or {}).get("transport") or "")
    checks = (
        (provenance.get("artifact_hash"),
         promotion_artifact.get("rule_bundle_artifact_hash"),
         "rule bundle artifact"),
        (dist_index.objective_version,
         promotion_artifact.get("objective_version"),
         "objective_version"),
        (packet_transport, promotion_transport, "transport"),
    )
    return [
        f"{label}: {actual!r} != {expected!r}"
        for actual, expected, label in checks
        if actual != expected
    ]

def _iter_input_records(fp: str) -> Iterator[dict]:
    """Stream nested JSON arrays or compressed candidate JSONL records."""
    if str(fp).lower().endswith(".gz"):
        try:
            yield from iter_candidate_stream(fp)
        except (OSError, EOFError) as exc:
            raise ValueError(
                f"corrupt gzip candidate stream {fp}: {exc}") from exc
    else:
        try:
            import ijson
        except ImportError:
            raise RuntimeError(
                "ijson is required: large corpora must be streamed rather than loaded whole."
                "mamba install -n protocol_fuzzer ijson")
        
        with open(fp, "rb") as fh:
            for record in ijson.items(fh, "item"):
                yield record

def load_nested_packets(
    input_files: List[str],
    *,
    candidate_admission: str = CANDIDATE_ADMISSION_LEGACY,
    validated_exploratory_ids: Optional[Set[str]] = None,
    require_phase_aware: bool = False,
) -> List[dict]:
    """Stream nested candidates, merge duplicate payloads and preserve eligibility."""
    if candidate_admission not in VALID_CANDIDATE_ADMISSION_MODES:
        raise ValueError(
            f"candidate_admission must be one of "
            f"{VALID_CANDIDATE_ADMISSION_MODES}, got {candidate_admission!r}")
    validated_ids = set(validated_exploratory_ids or ())
    if (candidate_admission == CANDIDATE_ADMISSION_VALIDATED_EXPANDED
            and validated_exploratory_ids is None):
        raise ValueError(
            "validated-expanded admission requires a validated "
            "exploratory promotion artifact")

    packets_by_hex: Dict[str, dict] = {}
    packet_rank: Dict[str, int] = {}
    packet_order: Dict[str, int] = {}
    next_order = 0
    flat_files: List[str] = []

    files_iter = tqdm(input_files, desc="Load files", unit="file", ncols=90, leave=False)
    for fp in files_iter:
        size_mb = Path(fp).stat().st_size / (1024 * 1024) if Path(fp).is_file() else 0.0
        files_iter.set_postfix_str(f"{Path(fp).name} ({size_mb:.0f}MB)")
        t_load = time.time()
        n_recs = 0
        is_candidate_stream = Path(fp).suffix.lower() == ".gz"
        rec_iter = _iter_input_records(fp)
        rec_bar = tqdm(rec_iter, desc="  Extract packets", unit="rec", ncols=90, leave=False)
        try:
            for rec in rec_bar:
                n_recs += 1
                if not isinstance(rec, dict):
                    continue
                # Candidate streams deliberately use a flat member-response
                # list.  Historical flat fingerprint libraries are rejected,
                # while _phase_pairs supports both this authoritative stream
                # schema and the public nested schema.
                if not is_candidate_stream and _is_flat(rec):
                    if fp not in flat_files:
                        flat_files.append(fp)
                    continue
                ph = str(rec.get("packet_hex") or "").strip().lower()
                if not ph:
                    continue
                admitted, admitted_type = _admit_candidate(
                    rec, candidate_admission, validated_ids)
                if not admitted:
                    continue

                observed_pairs, active_pairs, banner_pairs, phase_aware = (
                    _phase_pairs(rec))
                if require_phase_aware and not phase_aware:
                    raise ValueError(
                        "formal phase-aware selection rejected packet "
                        f"{ph[:16]}... without complete response_phase facts")
                if not observed_pairs:
                    continue  
                packet_record = {
                    "packet_hex": ph,
                    # Backward-compatible name: service-identification primary
                    # coverage is the observed (Banner OR post) union.
                    "pairs": observed_pairs,
                    "observed_pairs": observed_pairs,
                    "active_pairs": active_pairs,
                    "banner_pairs": banner_pairs,
                    "phase_aware": phase_aware,
                    "iteration": int(rec.get("iteration", 0)),
                    "transport": rec.get("transport", ""),
                    "candidate_type": admitted_type,
                    "source_candidate_type": record_candidate_type(rec),
                    "mutation_target": record_mutation_target(rec),
                    "objective_version": rec.get("objective_version", ""),
                    "weight_config_hash": rec.get("weight_config_hash", ""),
                }
                if admitted_type == CANDIDATE_VALIDATED_EXPLORATORY:
                    packet_record["promotion_candidate_id"] = (
                        candidate_identity_digest(rec))
                if "origin_protocol" in rec:
                    packet_record["origin_protocol"] = rec.get("origin_protocol", "")
                rank = (
                    2 if admitted_type in _STRICT_CANDIDATE_TYPES
                    else 1 if admitted_type == CANDIDATE_VALIDATED_EXPLORATORY
                    else 0)
                if ph not in packet_order:
                    packet_order[ph] = next_order
                    next_order += 1
                # A strict candidate always wins over the same payload retained
                # only through exploratory promotion.  Equal-rank records keep
                # the historical first-wins behavior.
                if ph not in packets_by_hex or rank > packet_rank[ph]:
                    packets_by_hex[ph] = packet_record
                    packet_rank[ph] = rank
        finally:
            rec_bar.close()
        tqdm.write(f"[load] {Path(fp).name}: {size_mb:.0f}MB → {n_recs} records "
                   f"({'gzip JSONL' if is_candidate_stream else 'ijson'} streamed "
                   f"{time.time() - t_load:.1f}s)")

    if flat_files:
        raise ValueError(
            "Input contains the legacy flat schema (" + ", ".join(flat_files) +
            "). This selector requires nested service/implementation records."
            "Convert the input to the nested phase-aware schema before retrying."
        )
    return [
        packets_by_hex[packet_hex]
        for packet_hex, _order in sorted(packet_order.items(), key=lambda item: item[1])
        if packet_hex in packets_by_hex
    ]

# ============================================================================

# ============================================================================

class PacketSelector:
    """Weighted greedy coverage over service/implementation pairs."""

    def __init__(
        self,
        packets: List[dict],
        cluster_weights: Dict[str, float],
        n_per_cluster: Dict[str, int],
        gamma: float = 1.0,
        objective: str = "weighted",
        quota: int = 1,
        distinguishability_mode: str = "none",
    ):
        if objective not in ("weighted", "lexicographic", "quota"):
            raise ValueError(f"objective must be 'weighted'/'lexicographic'/'quota', got {objective!r}")
        if distinguishability_mode not in VALID_DISTINGUISHABILITY_MODES:
            raise ValueError(
                f"distinguishability_mode must be one of {VALID_DISTINGUISHABILITY_MODES}, "
                f"got {distinguishability_mode!r}")
        self.packets = packets
        self.w = cluster_weights
        self.n_c = n_per_cluster                    
        self.gamma = gamma
        self.objective = objective
        self.quota = max(1, int(quota))              
        self.distinguishability_mode = distinguishability_mode
        self.clusters: Set[str] = set(cluster_weights.keys())
        self.total_weight = float(sum(cluster_weights.values()))  # ~1.0
        
        self._covered_pairs: Set[Tuple[str, str]] = set()
        self._covered_count: Dict[str, int] = {c: 0 for c in self.clusters}
        self._covered_clusters: Set[str] = set()    

    def _cluster_gain(self, c: str, k0: int, dn: int) -> float:
        """Calculate marginal utility from newly covered variants of one service."""
        n = self.n_c.get(c, 0)
        if n <= 0 or dn <= 0:
            return 0.0
        f0 = k0 / n
        f1 = (k0 + dn) / n
        return self.w.get(c, 0.0) * (f1 ** self.gamma - f0 ** self.gamma)

    def _weighted_coverage_of(self, covered_count: Dict[str, int]) -> float:
        """Sum service weights times the configured member-coverage fraction."""
        tot = 0.0
        for c in self.clusters:
            n = self.n_c.get(c, 0)
            if n > 0:
                tot += self.w.get(c, 0.0) * (covered_count.get(c, 0) / n) ** self.gamma
        return tot

    def _cluster_coverage_of(self, covered_clusters: Set[str]) -> float:
        """Sum weights of services with at least one covered implementation."""
        return sum(self.w.get(c, 0.0) for c in covered_clusters)

    def _effective_pairs(self, pkt: dict) -> Set[Tuple[str, str]]:
        """Count only correctly identified pairs in rule-confirmed mode."""
        if "effective_pairs" in pkt:
            return pkt["effective_pairs"]
        return pkt["pairs"]

    def _packet_gain_key(self, pkt: dict, covered_pairs: Set[Tuple[str, str]],
                         covered_clusters: Set[str], covered_count: Dict[str, int]):
        """Rank a packet's marginal contribution; return None for no new coverage."""
        new_by_c: Dict[str, int] = {}
        for pair in self._effective_pairs(pkt):
            if pair not in covered_pairs:
                new_by_c[pair[0]] = new_by_c.get(pair[0], 0) + 1
        if not new_by_c:
            return None
        mult = 1.0
        if self.distinguishability_mode == "proxy":
            mult = pkt.get("proxy_multiplier")
            mult = 1.0 if mult is None else float(mult)
        if self.objective == "quota":
            q = self.quota
            gain = 0.0
            for c, dn in new_by_c.items():
                k0 = covered_count.get(c, 0)
                cap_delta = min(k0 + dn, q) - min(k0, q)  
                if cap_delta > 0:
                    gain += self.w.get(c, 0.0) * cap_delta / q
            return gain * mult
        if self.objective == "lexicographic":
            primary = sum(self.w.get(c, 0.0) for c in new_by_c if c not in covered_clusters)
            secondary = 0.0
            for c, dn in new_by_c.items():
                n = self.n_c.get(c, 0)
                if n > 0:
                    secondary += self.w.get(c, 0.0) * dn / n
            return (primary * mult, secondary * mult)
        
        gain = 0.0
        for c, dn in new_by_c.items():
            gain += self._cluster_gain(c, covered_count[c], dn)
        return gain * mult

    def select(self, k: int = 30, min_new_coverage: float = 0.01) -> List[dict]:
        """Greedily select up to k probes with positive marginal coverage."""
        covered_pairs: Set[Tuple[str, str]] = set()
        covered_count: Dict[str, int] = {c: 0 for c in self.clusters}
        covered_clusters: Set[str] = set()
        used: Set[int] = set()
        selected: List[dict] = []
        total_pairs = sum(self.n_c.values())
        show_inner = len(self.packets) >= 5000  

        step_bar = tqdm(range(k), desc="Select probes", unit="step", ncols=90, leave=True)
        for step in step_bar:
            best_idx = -1
            best_key = None  # weighted: float；lexicographic: (primary, secondary)

            pkt_iter = enumerate(self.packets)
            inner = None
            if show_inner:
                inner = tqdm(pkt_iter, total=len(self.packets),
                             desc=f"  scan s{step + 1}", unit="pkt",
                             ncols=90, leave=False)
                pkt_iter = inner
            for i, pkt in pkt_iter:
                if i in used:
                    continue
                key = self._packet_gain_key(pkt, covered_pairs, covered_clusters, covered_count)
                if key is None:
                    continue
                if best_key is None or key > best_key:
                    best_key = key
                    best_idx = i
            if inner is not None:
                inner.close()

            if best_idx < 0:
                tqdm.write(f"[select] step {step + 1}: no new implementation coverage; stopping.")
                break
            
            stop = False
            if self.objective == "lexicographic":
                primary, secondary = best_key
                if primary <= 0.0 and (
                    self.total_weight <= 0 or secondary / self.total_weight < min_new_coverage
                ):
                    stop = True
                    tqdm.write(
                        f"[select] step {step + 1}: all services covered; marginal implementation gain "
                        f"{secondary:.6f} < threshold {min_new_coverage:.4f}"
                    )
            else:
                if self.total_weight > 0 and best_key / self.total_weight < min_new_coverage:
                    stop = True
                    tqdm.write(
                        f"[select] step {step + 1}: stopping at marginal gain {best_key:.6f} < threshold "
                        f"{min_new_coverage:.4f} (fraction of total weight "
                        f"{100.0 * best_key / self.total_weight:.2f}%）"
                    )
            if stop:
                break

            pkt = self.packets[best_idx]
            used.add(best_idx)

            newly: List[Tuple[str, str]] = []
            for pair in self._effective_pairs(pkt):
                if pair not in covered_pairs:
                    covered_pairs.add(pair)
                    covered_count[pair[0]] += 1
                    covered_clusters.add(pair[0])
                    newly.append(pair)

            rec = {
                "rank": step + 1,
                "packet_hex": pkt["packet_hex"],
                "mutation_target": pkt.get("mutation_target", ""),
                "candidate_type": pkt.get("candidate_type", "multi_probe"),
                "source_candidate_type": pkt.get(
                    "source_candidate_type",
                    pkt.get("candidate_type", "multi_probe")),
                "iteration": pkt["iteration"],
                "clusters": sorted({p[0] for p in pkt["pairs"]}),
                "covered_pairs_newly": [[c, m] for c, m in sorted(newly)],
            }
            if "origin_protocol" in pkt:
                rec["origin_protocol"] = pkt.get("origin_protocol", "")
            if "promotion_candidate_id" in pkt:
                rec["promotion_candidate_id"] = pkt["promotion_candidate_id"]
            if self.distinguishability_mode != "none":
                ident_pairs = pkt.get("identifiable_pairs") or frozenset()
                member_code_pairs = pkt.get("member_code_pairs") or frozenset()
                rec["distinguishability"] = {
                    "mode": self.distinguishability_mode,
                    "identifiable_pairs": [[c, m] for c, m in sorted(ident_pairs)],
                    "identifiable_observed_pairs": [
                        [c, m] for c, m in sorted(
                            pkt.get("identifiable_observed_pairs") or ())],
                    "identifiable_active_pairs": [
                        [c, m] for c, m in sorted(
                            pkt.get("identifiable_active_pairs") or ())],
                    "banner_identifiable_pairs": [
                        [c, m] for c, m in sorted(
                            pkt.get("banner_identifiable_pairs") or ())],
                    "exact_identifiable_pairs": [
                        [c, m] for c, m in sorted(
                            pkt.get("exact_identifiable_pairs") or ())],
                    "ambiguous_identifiable_pairs": [
                        [c, m] for c, m in sorted(
                            pkt.get("ambiguous_identifiable_pairs") or ())],

                    "excluded_pairs": [
                        [c, m] for c, m in sorted(pkt["pairs"] - ident_pairs)],
                    
                    "member_code_confirmed_pairs": [
                        [c, m] for c, m in sorted(member_code_pairs)],
                    "proxy_multiplier": pkt.get("proxy_multiplier"),
                    "response_outcome_counts": dict(sorted(
                        (pkt.get("response_outcome_counts") or {}).items())),
                }
            if self.objective == "lexicographic":
                primary, secondary = best_key
                rec["marginal_benefit"] = primary
                rec["primary_gain"] = primary
                rec["secondary_gain"] = secondary
            else:
                rec["marginal_benefit"] = best_key
            selected.append(rec)

            if self.objective == "lexicographic":
                step_bar.set_postfix(
                    ccov=f"{self._cluster_coverage_of(covered_clusters):.1%}",
                    cl=f"{len(covered_clusters)}/{len(self.clusters)}",
                    pairs=f"{len(covered_pairs)}/{total_pairs}",
                )
            else:
                step_bar.set_postfix(
                    cov=f"{self._weighted_coverage_of(covered_count):.1%}",
                    pairs=f"{len(covered_pairs)}/{total_pairs}",
                    gain=f"{best_key:.3f}",
                )
            logger.debug(
                "step %d: clusters=%s key=%s newly=%d pair(s)",
                step + 1, selected[-1]["clusters"], best_key, len(newly),
            )
        step_bar.close()

        self._covered_pairs = covered_pairs
        self._covered_count = covered_count
        self._covered_clusters = covered_clusters
        if self.objective == "lexicographic":
            logger.info(
                "Selected %d packets: %d/%d services (weighted service coverage %.1f%%) +"
                "%d/%d (service, implementation) pairs",
                len(selected), len(covered_clusters), len(self.clusters),
                100.0 * self._cluster_coverage_of(covered_clusters),
                len(covered_pairs), total_pairs,
            )
        else:
            logger.info(
                "Selected %d packets covering %d/%d pairs across %d services; weighted coverage %.1f%%",
                len(selected), len(covered_pairs), total_pairs,
                len(self.clusters), 100.0 * self._weighted_coverage_of(covered_count),
            )
        return selected

    def coverage_report(self, selected: List[dict]) -> dict:
        """Report identified pairs and declared but uncoverable variants."""
        
        universe_by_c: Dict[str, Set[str]] = {}
        for pkt in self.packets:
            for (c, m) in pkt["pairs"]:
                universe_by_c.setdefault(c, set()).add(m)

        def weighted_coverage(cov_count: Dict[str, int]) -> float:
            return self._weighted_coverage_of(cov_count)

        clusters_report = []
        for c in sorted(self.clusters):
            members_in_u = sorted(universe_by_c.get(c, set()))
            declared = SERVICE_CLUSTERS.get(c, [])
            covered_m = sorted(m for m in members_in_u if (c, m) in self._covered_pairs)
            uncovered_m = sorted(m for m in members_in_u if (c, m) not in self._covered_pairs)
            uncoverable_m = sorted(
                m for m in declared if m not in universe_by_c.get(c, set())
            )
            n_u = len(members_in_u)
            frac = (self._covered_count.get(c, 0) / n_u) if n_u else 0.0
            clusters_report.append({
                "cluster": c,
                "weight": self.w.get(c, 0.0),
                "censys_key": censys_key_of_cluster(c),
                "members_covered": len(covered_m),
                "members_responded": n_u,
                "members_declared": len(set(declared)),
                "fraction": frac,
                "weighted": self.w.get(c, 0.0) * (frac ** self.gamma),
                "covered_members": covered_m,
                "uncovered_members": uncovered_m,
                "uncoverable_members": uncoverable_m,
            })

        cumulative = []
        cum_count: Dict[str, int] = {c: 0 for c in self.clusters}
        cum_clusters: Set[str] = set()
        cum_pairs = 0
        for s in selected:
            for cm in s["covered_pairs_newly"]:
                cum_count[cm[0]] = cum_count.get(cm[0], 0) + 1
                cum_clusters.add(cm[0])
                cum_pairs += 1
            cumulative.append({
                "step": s["rank"],
                "weighted_coverage": weighted_coverage(cum_count),
                "cluster_coverage": self._cluster_coverage_of(cum_clusters),
                "n_clusters_covered": len(cum_clusters),
                "n_pairs_covered": cum_pairs,
            })

        return {
            "total_packets": len(selected),
            "objective": self.objective,
            "universe": {
                "n_clusters": len(self.clusters),
                "n_pairs": sum(len(v) for v in universe_by_c.values()),
                "n_packets_corpus": len(self.packets),
            },
            "weighted_coverage": weighted_coverage(self._covered_count),
            "cluster_coverage": self._cluster_coverage_of(self._covered_clusters),
            "n_clusters_covered": len(self._covered_clusters),
            "cumulative": cumulative,
            "clusters": clusters_report,
        }

def _pair_coverage_metrics(
    covered: Set[Tuple[str, str]],
    universe: Set[Tuple[str, str]],
    weights: Dict[str, float],
) -> dict:
    covered_clusters = {cluster for cluster, _member in covered}
    universe_clusters = {cluster for cluster, _member in universe}
    covered_weight = sum(weights.get(cluster, 0.0)
                         for cluster in covered_clusters)
    universe_weight = sum(weights.get(cluster, 0.0)
                          for cluster in universe_clusters)
    return {
        "n_member_pairs": len(covered),
        "n_member_pairs_available": len(universe),
        "member_pair_fraction": (
            len(covered) / len(universe) if universe else 0.0),
        "n_clusters": len(covered_clusters),
        "n_clusters_available": len(universe_clusters),
        "cluster_fraction": (
            len(covered_clusters) / len(universe_clusters)
            if universe_clusters else 0.0),
        "weighted_cluster_coverage": covered_weight,
        "weighted_cluster_fraction_of_available": (
            covered_weight / universe_weight if universe_weight else 0.0),
    }

def _identification_coverage_report(
    packets: List[dict],
    selected: List[dict],
    weights: Dict[str, float],
) -> dict:
    """Build Total/Active/Banner Coverage@k without double counting members."""
    fields = {
        "total_identifiable": "identifiable_observed_pairs",
        "active_identifiable": "identifiable_active_pairs",
        "banner_identifiable": "banner_identifiable_pairs",
    }
    universes = {
        name: set().union(*(set(pkt.get(field) or ()) for pkt in packets))
        if packets else set()
        for name, field in fields.items()
    }
    by_hex = {pkt["packet_hex"]: pkt for pkt in packets}
    cumulative_sets = {name: set() for name in fields}
    cumulative = []
    packet_additions = []
    outcome_counts: Counter = Counter()
    for selected_record in selected:
        packet = by_hex[selected_record["packet_hex"]]
        step_metrics = {"step": selected_record["rank"]}
        additions = {
            "rank": selected_record["rank"],
            "packet_hex": selected_record["packet_hex"],
            "candidate_type": selected_record.get("candidate_type", "multi_probe"),
        }
        for name, field in fields.items():
            pairs = set(packet.get(field) or ())
            new_pairs = pairs - cumulative_sets[name]
            old_clusters = {cluster for cluster, _member in cumulative_sets[name]}
            cumulative_sets[name].update(pairs)
            new_clusters = sorted(
                {cluster for cluster, _member in new_pairs} - old_clusters)
            additions[f"new_{name}_pairs"] = [
                [cluster, member] for cluster, member in sorted(new_pairs)]
            additions[f"new_{name}_clusters"] = new_clusters
            step_metrics[name] = _pair_coverage_metrics(
                cumulative_sets[name], universes[name], weights)
        outcome_counts.update(packet.get("response_outcome_counts") or {})
        cumulative.append(step_metrics)
        packet_additions.append(additions)
    final = {
        name: _pair_coverage_metrics(cumulative_sets[name], universes[name], weights)
        for name in fields
    }
    return {
        "semantics": (
            "Total Identifiable Coverage is the deduplicated union of correctly "
            "identified Banner and post-response (cluster,member) pairs. Active "
            "and Banner coverage are explanatory subsets; ranking uses Total."),
        "final": final,
        "cumulative": cumulative,
        "selected_packet_additions": packet_additions,
        "selected_candidate_type_counts": dict(sorted(Counter(
            record.get("candidate_type", "multi_probe")
            for record in selected).items())),
        "selected_response_outcome_counts": dict(sorted(outcome_counts.items())),
    }

# ============================================================================

# ============================================================================

def select_packets(
    packets: List[dict],
    counts: Dict[str, int],
    alpha: float = 0.7,
    gamma: float = 1.0,
    k: int = 30,
    min_new_coverage: float = 0.01,
    objective: str = "weighted",
    quota: int = 1,
    distinguishability: Optional[dict] = None,
) -> Tuple[List[dict], dict, Dict[str, float]]:
    """Build the universe, compute weights, select probes and report coverage."""
    
    dist_section: Optional[dict] = None
    eff_mode = "none"
    dist_index = None
    if distinguishability is not None:
        eff_mode = distinguishability.get("effective_mode") or distinguishability.get("mode") or "none"
        dist_index = distinguishability.get("index")
    if eff_mode != "none" and dist_index is not None:
        require_phase_aware = bool(
            (distinguishability or {}).get("require_phase_aware"))
        n_with_entry = 0
        n_phase_missing_packets = 0
        for pkt in packets:
            if require_phase_aware and not pkt.get("phase_aware"):
                raise ValueError(
                    "formal phase-aware rule-confirmed selection encountered "
                    f"legacy packet {pkt.get('packet_hex', '')[:16]}...")
            if not pkt.get("phase_aware"):
                n_phase_missing_packets += 1
            ph = packet_hash_from_hex(pkt["packet_hex"])
            if dist_index.entry_loaded(ph):
                n_with_entry += 1
            if eff_mode == "rule-confirmed":

                observed_ident = dist_index.observed_identifiable_pairs(ph)
                active_ident = dist_index.active_identifiable_pairs(ph)
                banner_ident = dist_index.banner_identifiable_pairs(ph)
                exact_query = getattr(
                    dist_index, "exact_identifiable_pairs", None)
                ambiguous_query = getattr(
                    dist_index, "ambiguous_identifiable_pairs", None)

                exact_ident = (
                    exact_query(ph) if exact_query else observed_ident)
                ambiguous_ident = (
                    ambiguous_query(ph) if ambiguous_query else frozenset())
                pkt["identifiable_pairs"] = pkt["pairs"] & observed_ident
                pkt["identifiable_observed_pairs"] = (
                    pkt.get("observed_pairs", pkt["pairs"]) & observed_ident)
                pkt["identifiable_active_pairs"] = (
                    pkt.get("active_pairs", set()) & active_ident)
                pkt["banner_identifiable_pairs"] = (
                    pkt.get("banner_pairs", set()) & banner_ident)
                pkt["exact_identifiable_pairs"] = (
                    pkt["pairs"] & exact_ident)
                pkt["ambiguous_identifiable_pairs"] = (
                    pkt["pairs"] & ambiguous_ident)
                pkt["effective_pairs"] = pkt["identifiable_observed_pairs"]
                pkt["member_code_pairs"] = dist_index.member_confirmed_pairs(ph) & pkt["pairs"]
                pkt["response_outcome_counts"] = (
                    dist_index.response_outcome_counts(ph))
                if require_phase_aware and not pkt["response_outcome_counts"]:
                    raise ValueError(
                        "formal phase-aware report requires a current "
                        "distinguishability artifact with response outcome facts")
            elif eff_mode == "proxy":
                pkt["proxy_multiplier"] = dist_index.proxy_multiplier(
                    ph, {c for c, _m in pkt["pairs"]})
        dist_section = {
            "mode": eff_mode,
            "requested_mode": (distinguishability or {}).get("mode", eff_mode),
            "artifact": dist_index.summary(),
            "n_packets_with_entry": n_with_entry,
            "n_packets_without_entry": len(packets) - n_with_entry,
            "n_phase_missing_packets": n_phase_missing_packets,
            "semantics": {
                "rule_confirmed": (
                    "primary coverage is identifiable_observed_pairs: the "
                    "deduplicated Banner OR post-response union correctly "
                    "identified by the held-out cascade; active and Banner "
                    "subsets are reported separately and never change ranking"),
                "ambiguity": (
                    "exact_identifiable_pairs resolve one service label; "
                    "ambiguous_identifiable_pairs resolve only an explicitly "
                    "configured, evidence-supported equivalent service set"),
                "proxy": PROXY_NOT_ACCURACY_NOTE,
            },
        }
        if (distinguishability or {}).get("fallback_reason"):
            dist_section["fallback_reason"] = distinguishability["fallback_reason"]

    universe_by_c: Dict[str, Set[str]] = {}
    for pkt in packets:
        for (c, m) in pkt["pairs"]:
            universe_by_c.setdefault(c, set()).add(m)
    clusters = set(universe_by_c.keys())
    n_per_cluster = {c: len(ms) for c, ms in universe_by_c.items()}

    weights = compute_cluster_weights(clusters, prevalence_alpha=alpha, counts=counts)
    current_weight_hash = weight_config_hash(
        prevalence_alpha=alpha,
        counts=counts,
    )

    total_pairs = sum(n_per_cluster.values())
    by_type = Counter(p.get("candidate_type", "multi_probe") for p in packets)
    logger.info(
        "Universe: %d unique packets / %d services / %d pairs |"
        "candidate channels: %s |"
        "objective=%s k=%d alpha=%.2f gamma=%.2f min_new_coverage=%.3f",
        len(packets), len(clusters), total_pairs, dict(by_type),
        objective, k, alpha, gamma, min_new_coverage,
    )
    top_w = sorted(weights.items(), key=lambda kv: -kv[1])[:5]
    logger.info("Top five service weights: %s", ", ".join(f"{c}={w:.3f}" for c, w in top_w))

    selector = PacketSelector(packets, weights, n_per_cluster, gamma=gamma,
                              objective=objective, quota=quota,
                              distinguishability_mode=eff_mode)
    selected = selector.select(k=k, min_new_coverage=min_new_coverage)
    report = selector.coverage_report(selected)
    if dist_section is not None:
        dist_section["selected_cluster_status_counts"] = dist_index.status_counts_over(
            packet_hash_from_hex(rec["packet_hex"]) for rec in selected)
        if eff_mode == "rule-confirmed":
            
            ident_total = sum(
                len(rec.get("distinguishability", {}).get(
                    "identifiable_observed_pairs", ()))
                for rec in selected)
            member_code_total = sum(
                len(rec.get("distinguishability", {}).get(
                    "member_code_confirmed_pairs", ()))
                for rec in selected)
            excluded_total = sum(
                len(rec.get("distinguishability", {}).get("excluded_pairs", ()))
                for rec in selected)
            exact_total = sum(
                len(rec.get("distinguishability", {}).get(
                    "exact_identifiable_pairs", ()))
                for rec in selected)
            ambiguous_total = sum(
                len(rec.get("distinguishability", {}).get(
                    "ambiguous_identifiable_pairs", ()))
                for rec in selected)
            dist_section["selected_pair_counts"] = {
                "cluster_identifiable": ident_total,
                "total_identifiable_observations": ident_total,
                "exact_identifiable": exact_total,
                "ambiguous_identifiable": ambiguous_total,
                "member_code_confirmed": member_code_total,
                "excluded": excluded_total,
            }
            report["identification_coverage"] = _identification_coverage_report(
                packets, selected, weights)
        report["distinguishability"] = dist_section
    source_objectives = sorted({
        p.get("objective_version", "") for p in packets
        if p.get("objective_version")
    })
    source_weight_hashes = sorted({
        p.get("weight_config_hash", "") for p in packets
        if p.get("weight_config_hash")
    })
    report["objective_versions"] = source_objectives
    report["source_weight_config_hashes"] = source_weight_hashes
    report["selector_weight_config_hash"] = current_weight_hash
    report["weight_config_match"] = (
        not source_weight_hashes or source_weight_hashes == [current_weight_hash]
    )
    if not report["weight_config_match"]:
        logger.warning(
            "Corpus weight configuration %s differs from selector configuration %s;"
            "use the same frozen counts and alpha for a comparable experiment.",
            source_weight_hashes, current_weight_hash,
        )
    return selected, report, weights

# ============================================================================
# CLI
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Select probes by service-weighted marginal implementation coverage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  mamba run -n protocol_fuzzer python scripts/select_packets.py \\
      -i outputs/fingerprints.json -o selected_packets.json -k 30
""",
    )
    parser.add_argument("--input", "-i", nargs="+", required=True,
                        help="Nested fingerprints.json inputs; deduplicated by packet_hex")
    parser.add_argument("--output", "-o", default="selected_packets.json",
                        help="Output path (default: selected_packets.json)")
    parser.add_argument("-k", type=int, default=30, help="Maximum number of probes (default: 30)")
    parser.add_argument("--alpha", type=float, default=0.7,
                        help="Prevalence/importance mixture: 1.0 = prevalence, 0.0 = importance (default: 0.7)")
    parser.add_argument("--gamma", type=float, default=1.0,
                        help="Member-coverage exponent: 1.0 linear, greater values favor depth, lower values favor breadth")
    parser.add_argument("--objective", choices=["weighted", "lexicographic", "quota"], default="weighted",
                        help="weighted = weighted implementation coverage (default);"
                             "lexicographic = service coverage first, implementation diversity second;"
                             "quota = reward only the first quota implementations per service")
    parser.add_argument("--quota", type=int, default=1,
                        help="Per-service implementation cap for the quota objective (default: 1)")
    parser.add_argument("--min-new-coverage", type=float, default=0.01,
                        dest="min_new_coverage",
                        help="Stop below this marginal fraction of total weight (default: 0.01)")
    parser.add_argument("--censys-summary",
                        default="",
                        help="Optional prevalence-count table;"
                             "an empty string uses only frozen counts")
    parser.add_argument("--limit", type=int, default=0,
                        help="Process only the first N packets for a smoke test (0 = all)")
    parser.add_argument(
        "--candidate-admission",
        choices=[CANDIDATE_ADMISSION_STRICT,
                 CANDIDATE_ADMISSION_VALIDATED_EXPANDED],
        default=CANDIDATE_ADMISSION_STRICT,
        help="Eligibility: strict admits multi_probe and target_reachability;"
             "validated-expanded also admits exploratory candidates with stability and separate validation evidence")
    parser.add_argument(
        "--validated-exploratory-artifact", default=None,
        help="Required for validated-expanded: output of scripts/promote_validated_exploratory.py")
    parser.add_argument("--distinguishability-mode",
                        choices=list(VALID_DISTINGUISHABILITY_MODES),
                        default=getattr(config, "DISTINGUISHABILITY_MODE", "none"),
                        help="Identification-aware mode: none uses no artifact;"
                             "rule-confirmed counts only artifact-confirmed"
                             "service coverage; proxy uses lightweight scores"
                             "for soft ranking, not accuracy claims")
    parser.add_argument("--distinguishability-artifact", default=None,
                        help="Identification artifact directory or manifest.json"
                             "(output of scripts/evaluate_distinguishability.py)")
    parser.add_argument("--distinguishability-rule-digest", default=None,
                        help="Expected rule-set digest, checked against the manifest in strict mode")
    parser.add_argument("--no-strict-distinguishability", action="store_true",
                        default=False,
                        help="Warn and explicitly fall back to none if artifact validation fails"
                             "while recording effective_mode, instead of failing immediately")
    parser.add_argument("--distinguishability-objective-version", default=None,
                        help="Expected objective_version (default: config.OBJECTIVE_VERSION)")
    parser.add_argument("--distinguishability-zgrab-dir", default=None,
                        help="Scanner directory used to calculate the runtime registry"
                             "digest (default: config.DISTINGUISHABILITY_ZGRAB_DIR)")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    t0 = time.time()

    promotion_artifact = None
    validated_exploratory_ids: Optional[Set[str]] = None
    if args.candidate_admission == CANDIDATE_ADMISSION_VALIDATED_EXPANDED:
        if not args.validated_exploratory_artifact:
            logger.error(
                "validated-expanded requires --validated-exploratory-artifact")
            return 2
        if args.distinguishability_mode != "rule-confirmed":
            logger.error(
                "validated-expanded is a service-identification result and "
                "requires --distinguishability-mode rule-confirmed")
            return 2
        from core.validated_exploratory import (
            load_validated_exploratory_artifact,
        )
        try:
            promotion_artifact = load_validated_exploratory_artifact(
                args.validated_exploratory_artifact,
                expected_objective_version=(
                    args.distinguishability_objective_version
                    or getattr(config, "OBJECTIVE_VERSION", None)))
        except (OSError, ValueError) as exc:
            logger.error("validated exploratory artifact rejected: %s", exc)
            return 2
        validated_exploratory_ids = {
            str(result["candidate_id"])
            for result in promotion_artifact["candidate_results"]
            if result.get("validated_exploratory")
        }

    try:
        packets = load_nested_packets(
            args.input,
            candidate_admission=args.candidate_admission,
            validated_exploratory_ids=validated_exploratory_ids,
            # Formal phase-awareness is decided after the evaluation manifest
            # is loaded.  Legacy provenance mode remains observed-union only.
            require_phase_aware=False,
        )
    except ValueError as e:
        logger.error(str(e))
        return 2
    if args.limit > 0:
        packets = packets[:args.limit]
    t_load = time.time() - t0
    logger.info("Loaded %d unique packets from %d files in %.1fs",
                len(packets), len(args.input), t_load)
    if not packets:
        logger.error("No eligible probes; exiting")
        return 1

    summary = args.censys_summary if args.censys_summary else None
    counts = load_censys_counts(summary)

    dist_arg: Optional[dict] = None
    if args.distinguishability_mode != "none":
        if not args.distinguishability_artifact:
            logger.error(
                "--distinguishability-mode %s requires --distinguishability-artifact",
                args.distinguishability_mode)
            return 2
        from core.distinguishability import (
            load_distinguishability_artifact,
            runtime_registry_digest,
            source_digest_of,
        )
        strict = (
            not args.no_strict_distinguishability
            and getattr(config, "DISTINGUISHABILITY_STRICT_VALIDATION", True)
        )
        expected_objective = (
            args.distinguishability_objective_version
            or getattr(config, "OBJECTIVE_VERSION", None)
        )

        require_leakage = args.distinguishability_mode == "rule-confirmed"
        dist_arg = {
            "mode": args.distinguishability_mode,
            "effective_mode": "none",
            "index": None,
            "fallback_reason": "",
            "require_phase_aware": False,
        }

        zgrab_dir = (
            args.distinguishability_zgrab_dir
            or getattr(config, "DISTINGUISHABILITY_ZGRAB_DIR", "PW_Scanner")
        )
        try:
            current_runtime_digest, _runtime_files = runtime_registry_digest(zgrab_dir)
        except (ValueError, OSError) as exc:
            logger.warning(
                "[DISTINGUISHABILITY] Cannot compute runtime digest: %s."
                "Strict mode rejects the artifact; non-strict mode can only fall back to none",
                exc
            )
            current_runtime_digest = ""

        formal_phase_aware = False
        try:
            index = load_distinguishability_artifact(
                args.distinguishability_artifact,
                strict=strict,
                expected_objective_version=expected_objective,
                expected_rule_digest=args.distinguishability_rule_digest,
                
                expected_source_digest=source_digest_of(args.input),
                require_leakage_verified=require_leakage,
                expected_runtime_digest=current_runtime_digest,
            )
        except ValueError as exc:
            logger.error("[DISTINGUISHABILITY] artifact rejected (strict): %s", exc)
            return 2
        if index is None:
            dist_arg["fallback_reason"] = (
                "artifact rejected (non-strict); effective mode downgraded to none")
            logger.warning("[DISTINGUISHABILITY] %s", dist_arg["fallback_reason"])
        else:
            formal_phase_aware = bool(
                args.distinguishability_mode == "rule-confirmed"
                and index.manifest.get("strict_rule_bundle") is True)
            packet_transports: Set[str] = set()
            if formal_phase_aware:
                packet_transports = {
                    str(packet.get("transport") or "") for packet in packets
                } - {""}
                if len(packet_transports) != 1:
                    logger.error(
                        "formal phase-aware selection requires one transport "
                        "per run; found %s", sorted(packet_transports))
                    return 2
            if promotion_artifact is not None and formal_phase_aware:
                mismatches = _promotion_selection_binding_errors(
                    promotion_artifact, index, next(iter(packet_transports)))
                if mismatches:
                    logger.error(
                        "validated-expanded provenance mismatch: %s",
                        "; ".join(mismatches))
                    return 2
            dist_arg["effective_mode"] = args.distinguishability_mode
            dist_arg["index"] = index
            dist_arg["require_phase_aware"] = formal_phase_aware
            logger.info(
                "[DISTINGUISHABILITY] artifact loaded: %s | entries=%d | "
                "objective_version=%s | rule_digest=%s | mode=%s",
                index.artifact_hash, index.n_entries, index.objective_version,
                index.rule_digest, dist_arg["effective_mode"],
            )

        try:
            _validate_admission_runtime(
                args.candidate_admission,
                dist_arg.get("effective_mode", "none"),
                formal_phase_aware,
            )
        except ValueError as exc:
            logger.error(str(exc))
            return 2

    strict_baseline = None
    if (args.candidate_admission ==
            CANDIDATE_ADMISSION_VALIDATED_EXPANDED):
        strict_packets = [
            copy.deepcopy(packet) for packet in packets
            if packet.get("candidate_type") != CANDIDATE_VALIDATED_EXPLORATORY
        ]
        strict_selected, strict_report, _strict_weights = select_packets(
            strict_packets, counts,
            alpha=args.alpha, gamma=args.gamma,
            k=args.k, min_new_coverage=args.min_new_coverage,
            objective=args.objective, quota=args.quota,
            distinguishability=dist_arg,
        )
        strict_baseline = {
            "admission": CANDIDATE_ADMISSION_STRICT,
            "selected_packets": len(strict_selected),
            "selected_candidate_type_counts": dict(sorted(Counter(
                item.get("candidate_type", "multi_probe")
                for item in strict_selected).items())),
            "identification_coverage": strict_report.get(
                "identification_coverage", {}),
        }

    t1 = time.time()
    selected, report, weights = select_packets(
        packets, counts,
        alpha=args.alpha, gamma=args.gamma,
        k=args.k, min_new_coverage=args.min_new_coverage,
        objective=args.objective, quota=args.quota,
        distinguishability=dist_arg,
    )
    report["candidate_admission"] = args.candidate_admission
    if strict_baseline is not None:
        expanded = {
            "admission": CANDIDATE_ADMISSION_VALIDATED_EXPANDED,
            "selected_packets": len(selected),
            "selected_candidate_type_counts": dict(sorted(Counter(
                item.get("candidate_type", "multi_probe")
                for item in selected).items())),
            "identification_coverage": report.get(
                "identification_coverage", {}),
        }
        strict_final = strict_baseline["identification_coverage"].get(
            "final", {})
        expanded_final = expanded["identification_coverage"].get("final", {})
        deltas = {}
        for scope in (
                "total_identifiable", "active_identifiable",
                "banner_identifiable"):
            left = strict_final.get(scope, {})
            right = expanded_final.get(scope, {})
            deltas[scope] = {
                "member_pairs": (
                    int(right.get("n_member_pairs", 0))
                    - int(left.get("n_member_pairs", 0))),
                "clusters": (
                    int(right.get("n_clusters", 0))
                    - int(left.get("n_clusters", 0))),
                "weighted_cluster_coverage": (
                    float(right.get("weighted_cluster_coverage", 0.0))
                    - float(left.get("weighted_cluster_coverage", 0.0))),
            }
        report["admission_comparison"] = {
            "strict": strict_baseline,
            "validated_expanded": expanded,
            "delta_validated_expanded_minus_strict": {
                "selected_packets": len(selected) - strict_baseline[
                    "selected_packets"],
                "coverage": deltas,
            },
        }
    t_sel = time.time() - t1
    logger.info("Selected %d probes in %.1fs", len(selected), t_sel)
    sel_by_type = Counter(s.get("candidate_type", "multi_probe") for s in selected)
    logger.info("Selected candidate channels: %s (multi_probe or strict target-reachability fallback)",
                dict(sel_by_type))

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    output = {
        "selected_packets": selected,
        "coverage": report,
        "cluster_weights": weights,
        "parameters": {
            "k": args.k,
            "alpha": args.alpha,
            "gamma": args.gamma,
            "objective": args.objective,
            "quota": args.quota,
            "min_new_coverage": args.min_new_coverage,
            "censys_source": args.censys_summary or "(hardcoded)",
            "weight_config_hash": report["selector_weight_config_hash"],
            "source_weight_config_hashes": report["source_weight_config_hashes"],
            "objective_versions": report["objective_versions"],
            "weight_config_match": report["weight_config_match"],
            "candidate_admission": args.candidate_admission,
            "validated_exploratory_artifact_hash": (
                promotion_artifact.get("artifact_hash", "")
                if promotion_artifact else ""),
        },
    }
    if dist_arg is not None:
        
        output["parameters"]["distinguishability"] = {
            "requested_mode": dist_arg.get("mode"),
            "effective_mode": dist_arg.get("effective_mode"),
            "fallback_reason": dist_arg.get("fallback_reason", ""),
            **(
                {"artifact": report["distinguishability"]["artifact"]}
                if "distinguishability" in report else {}
            ),
        }
    t2 = time.time()
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    t_write = time.time() - t2
    size_kb = out_path.stat().st_size / 1024
    logger.info("Wrote %d selected packets to %s (%.1f KB) in %.2fs",
                len(selected), out_path, size_kb, t_write)

    n_covered = sum(c["members_covered"] for c in report["clusters"])
    n_uncoverable = sum(len(c["uncoverable_members"]) for c in report["clusters"])
    logger.info(
        "Weighted coverage %.1f%%: %d/%d pairs across %d services;"
        "%d declared variants never responded; total %.1fs (load %.1f / select %.1f / write %.2f)",
        100.0 * report["weighted_coverage"], n_covered,
        report["universe"]["n_pairs"], report["universe"]["n_clusters"], n_uncoverable,
        time.time() - t0, t_load, t_sel, t_write,
    )
    top = sorted(report["clusters"], key=lambda c: -c["weight"])[:10]
    logger.info("Coverage for the top %d service weights:", len(top))
    for c in top:
        miss = c["uncovered_members"]
        miss_str = f"  missing {','.join(miss)}" if miss else ""
        logger.info("  %-16s w=%.3f  %d/%d responding variants (%.0f%%)%s",
                    c["cluster"], c["weight"], c["members_covered"],
                    c["members_responded"], 100.0 * c["fraction"], miss_str)
    return 0

if __name__ == "__main__":
    sys.exit(main())
