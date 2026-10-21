"""Deterministic phase-aware corpus preparation. Keep complete construction identities and cross-service negatives for validation. Previews summarize shapes but never define the validation denominator."""

from collections import Counter, namedtuple
from typing import Dict, List, Set
import random

Shape = namedtuple("Shape", ["hex_full", "preview_hex", "count", "full_len", "text_preview"])



# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

SHAPE_STATS_VERSION = 2

def sampling_config_hash(targets, cap_per_member: int,
                         distinct_sample_count=None, sample_seed: int = 12345,
                         mode: str = "cluster") -> str:
    """Hash targets, sample caps, modes and deterministic sampling seeds."""
    from core.rule_corpus import canonical_sha256

    return canonical_sha256({
        "shape_stats_version": SHAPE_STATS_VERSION,
        "targets": sorted(str(t) for t in targets),
        "cap_per_member": int(cap_per_member),
        "distinct_sample_count": (None if distinct_sample_count is None
                                  else int(distinct_sample_count)),
        "sample_seed": int(sample_seed),
        "mode": str(mode),
    })

def _positive_int(value, name: str, allow_none: bool = False):
    """Require a positive integer, rejecting booleans and unauthorized None values."""
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"{name} must be a positive integer"
            + ("" if not allow_none else " or None")
            + f", got {value!r}")
    return value

def collect_full_shape_stats(
    corpus_path: str,
    targets,
    provenance_path=None,
    cap_per_member: int = 400,
    distinct_sample_count=None,
    sample_seed: int = 12345,
    mode: str = "cluster",
    *,
    expected_corpus_digest: str = None,
    expected_objective_version: str = None,
    expected_weight_config_hash: str = None,
    expected_background_artifact_hash: str = None,
    expected_source_candidates_digest: str = None,
    expected_phase_awareness_mode: str = None,
) -> dict:
    """Load the complete strict phase-aware construction view for validation."""
    from core.rule_corpus import (
        PHASE_AWARENESS_STRICT, RuleCorpusError, load_rule_corpus,
    )

    targets = sorted({str(t) for t in targets})
    if not targets:
        raise ValueError("targets must be a non-empty iterable of cluster names")
    cap = _positive_int(cap_per_member, "cap_per_member")
    distinct = _positive_int(distinct_sample_count, "distinct_sample_count",
                             allow_none=True)
    if isinstance(sample_seed, bool) or not isinstance(sample_seed, int):
        raise ValueError(f"sample_seed must be an integer, got {sample_seed!r}")
    if mode not in ("cluster", "member"):
        raise ValueError(f"mode must be 'cluster' or 'member', got {mode!r}")
    if expected_phase_awareness_mode is not None \
            and expected_phase_awareness_mode != PHASE_AWARENESS_STRICT:
        raise ValueError(
            "collect_full_shape_stats only consumes strict phase-aware "
            f"corpora; expected_phase_awareness_mode="
            f"{expected_phase_awareness_mode!r} is not allowed")

    atoms, provenance = load_rule_corpus(
        corpus_path, provenance_path,
        expected_corpus_digest=expected_corpus_digest,
        expected_objective_version=expected_objective_version,
        expected_weight_config_hash=expected_weight_config_hash,
        expected_background_artifact_hash=expected_background_artifact_hash,
        expected_source_candidates_digest=expected_source_candidates_digest,
        expected_phase_awareness_mode=PHASE_AWARENESS_STRICT,
    )
    if provenance.get("phase_awareness_mode") != PHASE_AWARENESS_STRICT:
        
        raise RuleCorpusError(
            "non-strict phase-awareness provenance rejected: "
            f"{provenance.get('phase_awareness_mode')!r}")

    ordered = sorted(atoms, key=lambda a: (
        a.get("id_cluster", ""), a.get("member", ""),
        a.get("response_hex", ""), a.get("response_identity", ""),
        a.get("observation_identity", "")))

    stats: Dict[str, Dict[str, Counter]] = {}
    packets: Dict[str, Set[str]] = {}
    observations: Dict[str, List[dict]] = {}
    atom_counts: Dict[str, int] = {"atoms": 0}
    by_id_cluster: Dict[str, int] = {}

    for atom in ordered:
        atom_counts["atoms"] += 1
        id_cluster = atom.get("id_cluster", "")
        by_id_cluster[id_cluster] = by_id_cluster.get(id_cluster, 0) + 1
        packet_hex = atom.get("packet_hex", "")
        if packet_hex:
            packets.setdefault(id_cluster, set()).add(packet_hex.lower())
        rh = atom.get("response_hex", "")
        if not rh:
            continue
        key = (id_cluster, atom.get("member", ""))
        stats.setdefault(key[0], {}).setdefault(key[1], Counter())[rh] += 1
        if packet_hex:
            observations.setdefault(id_cluster, []).append({
                "packet": packet_hex.lower(),
                "response": rh.lower(),
                "packet_identity": atom.get("packet_identity", ""),
                "response_identity": atom.get("response_identity", ""),
                "member": atom.get("member", ""),
                "phase": atom.get("phase", ""),
            })
    atom_counts["by_id_cluster"] = dict(sorted(by_id_cluster.items()))

    identity = {
        "corpus_digest": provenance["corpus_digest"],
        "corpus_file_sha256": provenance["corpus_file_sha256"],
        "source_candidates_digest": provenance["source_candidates_digest"],
        "corpus_schema_version": provenance["corpus_schema_version"],
        "phase_awareness_mode": provenance["phase_awareness_mode"],
        "objective_version": provenance["objective_version"],
        "weight_config_hash": provenance["weight_config_hash"],
        "background_artifact_hash": provenance["background_artifact_hash"],
        "construction": dict(provenance["construction"]),
        "sampling_config_hash": sampling_config_hash(
            targets, cap, distinct, sample_seed, mode),
    }
    return {
        "stats": stats,
        "identity": identity,
        "atom_counts": atom_counts,
        "targets": targets,
        "packets": {cluster: sorted(hexes)
                    for cluster, hexes in sorted(packets.items())},
        "observations": {
            cluster: sorted(rows, key=lambda row: (
                row["packet_identity"], row["response_identity"],
                row["member"], row["phase"]))
            for cluster, rows in sorted(observations.items())},
    }

def cluster_negatives(stats: dict, target_cluster: str,
                      cap: int = None) -> Dict[str, List[bytes]]:
    """Build cross-service negative responses from the complete shape statistics."""
    cap = _positive_int(cap, "cap", allow_none=True)
    out: Dict[str, List[bytes]] = {}
    for cluster in sorted(stats):
        if cluster == target_cluster:
            continue
        merged: Counter = Counter()
        for member_counter in stats[cluster].values():
            merged.update(member_counter)
        bs: List[bytes] = []
        for hx in sorted(merged):
            try:
                bs.append(bytes.fromhex(hx))
            except ValueError:
                continue
            if cap is not None and len(bs) >= cap:
                break
        if bs:
            out[cluster] = bs
    return out

def cluster_counter(stats: dict, cluster: str) -> Counter:
    """Aggregate response frequencies across variants of one service."""
    out: Counter = Counter()
    for member_c in stats.get(cluster, {}).values():
        out.update(member_c)
    return out


def sample_distinct(counter: Counter, n: int, seed: int = 12345) -> List[bytes]:
    """Sample unique response shapes uniformly without replacement."""
    rng = random.Random(seed)
    hexes = []
    for h in counter:
        try:
            bytes.fromhex(h)            
            hexes.append(h)
        except ValueError:
            continue
    rng.shuffle(hexes)
    return [bytes.fromhex(h) for h in hexes[:n]]

def all_responses(counter: Counter) -> List[bytes]:
    """Expand all counted response observations without changing the denominator."""
    out: List[bytes] = []
    for hex_full, count in counter.items():
        try:
            b = bytes.fromhex(hex_full)
        except ValueError:
            continue
        out.extend([b] * count)
    return out

def counter_from_samples(samples: List[bytes]) -> Counter:
    """Rebuild shape frequencies from byte samples for display."""
    out: Counter = Counter()
    for b in samples:
        out[b.hex()] += 1
    return out

def member_counter(stats: dict, cluster: str, member: str) -> Counter:
    """Return response frequencies for one implementation."""
    return stats.get(cluster, {}).get(member, Counter())

def member_negatives(stats: dict, cluster: str, target_member: str,
                     cap: int = None) -> Dict[str, List[bytes]]:
    """Materialize sibling implementations as within-service negatives."""
    cap = _positive_int(cap, "cap", allow_none=True)
    out: Dict[str, List[bytes]] = {}
    for m, counter in stats.get(cluster, {}).items():
        if m == target_member:
            continue
        bs: List[bytes] = []
        for hex_full in counter:
            try:
                bs.append(bytes.fromhex(hex_full))
            except ValueError:
                continue
            if cap is not None and len(bs) >= cap:
                break
        if bs:
            out[m] = bs
    return out

def _decode_preview(hex_full: str, n_bytes: int, printable_ratio: float) -> str:
    """Render printable ASCII and replace other bytes with dots."""
    raw = bytes.fromhex(hex_full[: n_bytes * 2])
    if not raw:
        return ""
    printable = sum(1 for b in raw if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d))
    if printable / len(raw) < printable_ratio:
        return ""
    return "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in raw)

def top_k(counter: Counter, k: int, hex_cap: int = 64,
          text_cap: int = 256, printable_ratio: float = 0.6) -> List[Shape]:
    """Return the most frequent complete shapes with bounded hex/text previews."""
    out = []
    for hex_full, count in counter.most_common(k):
        preview = hex_full[: hex_cap * 2]            
        full_len = len(hex_full) // 2
        text_prev = _decode_preview(hex_full, text_cap, printable_ratio)
        out.append(Shape(hex_full, preview, count, full_len, text_prev))
    return out

