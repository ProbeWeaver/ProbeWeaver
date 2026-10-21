"""Transport-specific co-response calibration. Shrink observed conditional response frequencies toward structural heuristics. These are observational associations, not mutation causality. Validate objective, algorithm, topology and specification digests before reusing an artifact."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import tempfile
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple

import config
from core.compatibility import HEURISTIC_ALGORITHM_VERSION, CompatibilityGraph
from protocol.field import UnifiedProtocolSpec

logger = logging.getLogger(__name__)

# ============================================================================

# ============================================================================

SCHEMA_VERSION = 1
MODEL_NAME = "beta_binomial_shrinkage_v1"

NEUTRAL_Q = 0.5
VALID_TRANSPORTS = ("tcp", "udp")
AGGREGATE_TRANSPORT_KEY = "all"   

COMPAT_MODE_NONE = "none"                  
COMPAT_MODE_HEURISTIC = "heuristic"        
COMPAT_MODE_CALIBRATED = "calibrated"      
VALID_COMPAT_MODES = (COMPAT_MODE_NONE, COMPAT_MODE_HEURISTIC, COMPAT_MODE_CALIBRATED)

DEFAULT_PRIOR_STRENGTH = 10.0
DEFAULT_SMOOTHING = (1.0, 1.0)

FACTS_OK = "ok"
FACTS_EMPTY = "empty_trigger"                    
FACTS_SKIP_TRANSPORT = "skipped_unknown_transport"
FACTS_SKIP_SCHEMA = "skipped_invalid_schema"

_PAIR_KEY_SEP = "|"

def _pair_key(i: str, j: str) -> str:
    return f"{i}{_PAIR_KEY_SEP}{j}"

def stable_dict_hash(d: Dict[str, float]) -> str:
    """Hash a key-sorted mapping independently of insertion order."""
    payload = {k: float(v) for k, v in sorted(d.items())}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]

# ============================================================================

# ============================================================================

class PairCoResponseStats:
    """Sufficient service-level co-response statistics for one transport."""

    def __init__(self) -> None:
        self.n_packets = 0            
        self.n_any_trigger = 0        
        self.cluster_n: Counter[str] = Counter()
        self.pair_n: Counter[Tuple[str, str]] = Counter()

    def observe(self, triggered: Iterable[str]) -> None:
        """Observe."""
        clusters = set(triggered)
        for c in clusters:
            if _PAIR_KEY_SEP in c:
                raise ValueError(
                    f"cluster name {c!r} contains reserved separator {_PAIR_KEY_SEP!r}"
                )
        self.n_packets += 1
        if clusters:
            self.n_any_trigger += 1
        for c in clusters:
            self.cluster_n[c] += 1
        ordered = sorted(clusters)
        for i in ordered:
            for j in ordered:
                if i != j:
                    self.pair_n[(i, j)] += 1

    def merge(self, other: "PairCoResponseStats") -> None:
        """Merge."""
        self.n_packets += other.n_packets
        self.n_any_trigger += other.n_any_trigger
        self.cluster_n.update(other.cluster_n)
        self.pair_n.update(other.pair_n)

    @property
    def universe(self) -> List[str]:
        return sorted(self.cluster_n.keys())

    def to_dict(self) -> Dict[str, object]:
        return {
            "n_packets": self.n_packets,
            "n_any_trigger": self.n_any_trigger,
            "cluster_counts": dict(sorted(self.cluster_n.items())),
            "pair_counts": {
                _pair_key(i, j): n for (i, j), n in sorted(self.pair_n.items())
            },
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "PairCoResponseStats":
        stats = cls()
        stats.n_packets = int(data.get("n_packets", 0))
        stats.n_any_trigger = int(data.get("n_any_trigger", 0))
        stats.cluster_n.update(
            {str(k): int(v) for k, v in data.get("cluster_counts", {}).items()}
        )
        for key, n in data.get("pair_counts", {}).items():
            i, _, j = str(key).partition(_PAIR_KEY_SEP)
            stats.pair_n[(i, j)] = int(n)
        return stats

# ============================================================================

# ============================================================================

def jaccard(n_both: int, n_i: int, n_j: int) -> float:
    """Return symmetric co-response intersection over union."""
    union = n_i + n_j - n_both
    if union <= 0:
        return 0.0
    return n_both / union

def observational_conditional(
    n_both: int,
    n_i: int,
    smoothing: Tuple[float, float] = DEFAULT_SMOOTHING,
) -> float:
    """Return Beta-smoothed observational conditional co-response frequency."""
    a, b = smoothing
    if a < 0 or b < 0 or a + b <= 0:
        raise ValueError(f"smoothing must be (a>=0, b>=0, a+b>0), got {smoothing!r}")
    if n_i < 0 or n_both < 0 or n_both > n_i:
        raise ValueError(
            f"invalid counts: n_both={n_both}, n_i={n_i} (need 0 <= n_both <= n_i)"
        )
    return (n_both + a) / (n_i + a + b)

def shrinkage_posterior(
    prior_mean: float,
    prior_strength: float,
    n_both: int,
    n_i: int,
) -> Tuple[float, float, float, float]:
    """Shrink the observed conditional frequency toward the structural prior mean."""
    if not 0.0 <= prior_mean <= 1.0:
        raise ValueError(f"prior_mean must be in [0,1], got {prior_mean}")
    if prior_strength <= 0:
        raise ValueError(f"prior_strength must be > 0, got {prior_strength}")
    if n_i < 0 or n_both < 0 or n_both > n_i:
        raise ValueError(
            f"invalid counts: n_both={n_both}, n_i={n_i} (need 0 <= n_both <= n_i)"
        )
    alpha = prior_strength * prior_mean + n_both
    beta = prior_strength * (1.0 - prior_mean) + (n_i - n_both)
    total = alpha + beta
    mean = alpha / total
    std = math.sqrt(alpha * beta / (total * total * (total + 1.0)))
    return alpha, beta, mean, std

# ============================================================================

# ============================================================================

class HeuristicCompatScores:
    """Cached structural compatibility score provider."""

    def __init__(
        self,
        specs: Dict[str, UnifiedProtocolSpec],
        neutral_q: float = NEUTRAL_Q,
    ) -> None:
        if not 0.0 <= neutral_q <= 1.0:
            raise ValueError(f"neutral_q must be in [0,1], got {neutral_q}")
        self._neutral_q = float(neutral_q)
        self._graph = CompatibilityGraph()
        for spec in (specs or {}).values():
            self._graph.add_spec(spec)
        self._cache: Dict[Tuple[str, str], float] = {}
        self.n_score_calls = 0   

    def score(self, i: str, j: str) -> float:
        if i == j:
            return 1.0
        key = (i, j) if i <= j else (j, i)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        self.n_score_calls += 1
        if i not in self._graph.specs or j not in self._graph.specs:
            value = self._neutral_q
        else:

            value = float(self._graph.calculate_fusion_score(i, j).fusion_score)
            if not 0.0 <= value <= 1.0:
                value = min(max(value, 0.0), 1.0)
        self._cache[key] = value
        return value

def spec_cluster_universe(
    specs: Dict[str, UnifiedProtocolSpec], transport: str,
) -> set:
    """List profile services compatible with the requested transport."""
    t = str(transport).strip().lower()
    universe = {
        name for name, spec in (specs or {}).items()
        if str(getattr(spec, "transport", "")).strip().lower() in (t, "both")
    }
    for name in universe:
        if _PAIR_KEY_SEP in name:
            raise ValueError(
                f"spec name {name!r} contains reserved separator "
                f"{_PAIR_KEY_SEP!r}"
            )
    return universe

def _spec_digest_payload(name: str, spec: UnifiedProtocolSpec) -> List:
    """Describe the transport and structural fields covered by the profile digest."""
    try:
        fields = []
        for pf in spec.iter_positioned_fields():
            f = pf.field
            fields.append([
                f.name,
                pf.start_byte,
                pf.end_byte,
                getattr(f.field_type, "name", str(f.field_type)),
                getattr(getattr(f, "survival_type", None), "name", None),
                f.min_value,
                f.max_value,
                f.endian, f.block_name, f.length_encoding, f.length_mask,
                f.algorithm, f.ipv4_src_block_name, f.ipv4_dst_block_name,
                [v.hex() for v in f.negative_values],
                [
                    v.hex() if isinstance(v, (bytes, bytearray)) else str(v)
                    for v in (f.expected_values or [])
                ],
            ])
        return [name, getattr(spec, "transport", ""), getattr(spec, "profile_version", "legacy"), fields]
    except Exception:  
        return [name, "unserializable"]

def heuristic_spec_digest(spec: UnifiedProtocolSpec, name: str) -> str:
    """Hash the profile structure relevant to heuristic scoring."""
    blob = json.dumps(_spec_digest_payload(name, spec))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

def heuristic_spec_digests(
    specs: Dict[str, UnifiedProtocolSpec],
) -> Dict[str, str]:
    """Return the authoritative per-profile structural digests."""
    return {
        name: heuristic_spec_digest(spec, name)
        for name, spec in (specs or {}).items()
    }

def heuristic_config_hash(specs: Dict[str, UnifiedProtocolSpec]) -> str:
    """Hash sorted profile digests for calibration compatibility."""
    digests = heuristic_spec_digests(specs)
    payload = [[name, digests[name]] for name in sorted(digests)]
    blob = json.dumps(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

# ============================================================================

# ============================================================================

@dataclass(frozen=True)
class PacketFacts:
    """Service-level response facts extracted from one candidate record."""
    transport: str
    clusters: FrozenSet[str]
    status: str

def extract_packet_facts(record: Dict) -> PacketFacts:
    """Extract transport, observed services and record validity."""
    transport = str(record.get("transport") or "").strip().lower()
    if transport not in VALID_TRANSPORTS:
        return PacketFacts(transport=transport, clusters=frozenset(),
                           status=FACTS_SKIP_TRANSPORT)

    clusters: set = set()
    saw_nested = saw_flat = False
    responses = record.get("responses")
    if not isinstance(responses, list):
        return PacketFacts(transport=transport, clusters=frozenset(),
                           status=FACTS_SKIP_SCHEMA)

    for entry in responses:
        if not isinstance(entry, dict):
            return PacketFacts(transport=transport, clusters=frozenset(),
                               status=FACTS_SKIP_SCHEMA)
        if "responses" in entry:
            saw_nested = True
            cluster = entry.get("service")
            members = entry.get("responses")
            if not cluster or not isinstance(members, list):
                return PacketFacts(transport=transport, clusters=frozenset(),
                                   status=FACTS_SKIP_SCHEMA)
            if any(
                isinstance(m, dict) and m.get("response_hex")
                for m in members
            ):
                clusters.add(str(cluster))
        elif "response_hex" in entry:
            saw_flat = True
            member = entry.get("service")
            if not member:
                return PacketFacts(transport=transport, clusters=frozenset(),
                                   status=FACTS_SKIP_SCHEMA)
            if entry.get("response_hex"):
                clusters.add(config.cluster_of(str(member)))
        else:
            return PacketFacts(transport=transport, clusters=frozenset(),
                               status=FACTS_SKIP_SCHEMA)

    if saw_nested and saw_flat:
        return PacketFacts(transport=transport, clusters=frozenset(),
                           status=FACTS_SKIP_SCHEMA)

    status = FACTS_OK if clusters else FACTS_EMPTY
    return PacketFacts(transport=transport, clusters=frozenset(clusters),
                       status=status)

# ============================================================================

# ============================================================================

def _transport_calibration_section(
    stats: PairCoResponseStats,
    heuristic: HeuristicCompatScores,
    prior_strength: float,
    smoothing: Tuple[float, float],
    aggregate: bool,
    spec_universe: Optional[set] = None,
) -> Dict[str, object]:
    """Build one transport's calibration table."""
    spec_only = (spec_universe or set()) - set(stats.cluster_n)
    universe = sorted(set(stats.universe) | set(spec_universe or set()))
    pairs: Dict[str, Dict[str, float]] = {}
    for i in universe:
        for j in universe:
            if i == j:
                continue
            n_i = stats.cluster_n[i]          
            n_j = stats.cluster_n[j]
            n_both = stats.pair_n.get((i, j), 0)
            h = heuristic.score(i, j)
            alpha, beta, mean, std = shrinkage_posterior(
                h, prior_strength, n_both, n_i)
            pairs[_pair_key(i, j)] = {
                
                "n_i": n_i,
                "n_j": n_j,
                "n_both": n_both,
                "n_union": n_i + n_j - n_both,
                
                "jaccard": jaccard(n_both, n_i, n_j),
                "p_obs_j_given_i": observational_conditional(n_both, n_i, smoothing),
                
                "heuristic": h,
                
                "posterior_alpha": alpha,
                "posterior_beta": beta,
                "calibrated_mean": mean,
                "calibrated_std": std,
            }
    
    cluster_counts = {c: stats.cluster_n.get(c, 0) for c in universe}
    return {
        "aggregate": aggregate,

        "heuristic_only": bool(spec_only) and stats.n_packets == 0
                          and not stats.cluster_n,
        "n_packets": stats.n_packets,
        "n_any_trigger": stats.n_any_trigger,
        "universe": universe,
        "cluster_counts": cluster_counts,
        "pairs": pairs,
    }

def build_calibration_artifact(
    stats_by_transport: Dict[str, PairCoResponseStats],
    specs: Dict[str, UnifiedProtocolSpec],
    prior_strength: float = DEFAULT_PRIOR_STRENGTH,
    smoothing: Tuple[float, float] = DEFAULT_SMOOTHING,
    neutral_q: float = NEUTRAL_Q,
    source_metadata: Optional[Dict] = None,
    include_aggregate: bool = True,
    objective_version: Optional[str] = None,
) -> Dict[str, object]:
    """Build a versioned artifact from transport-specific sufficient statistics."""
    if prior_strength <= 0:
        raise ValueError(f"prior_strength must be > 0, got {prior_strength!r}")
    a, b = smoothing
    if a < 0 or b < 0 or a + b <= 0:
        raise ValueError(
            f"smoothing must be (a>=0, b>=0, a+b>0), got {smoothing!r}")
    if not 0.0 <= neutral_q <= 1.0:
        raise ValueError(f"neutral_q must be in [0,1], got {neutral_q!r}")
    if objective_version is None:
        objective_version = getattr(config, "OBJECTIVE_VERSION", None)

    heuristic = HeuristicCompatScores(specs, neutral_q=neutral_q)
    # Document-backed profiles can have different framing/anchors on each
    # transport. Keep the historical aggregate explicitly raw and non-runtime.
    # Legacy specs retain their historical metadata/digest contract.
    profiles = {
        t: {name: (spec.for_transport(t)
                   if spec.profile_version != "legacy" else spec)
            for name, spec in specs.items()
            if spec.transport in (t, "both")}
        for t in VALID_TRANSPORTS
    }
    transport_heuristics = {
        t: HeuristicCompatScores(selected, neutral_q=neutral_q)
        for t, selected in profiles.items()
    }
    spec_universe_by_transport = {
        t: spec_cluster_universe(specs, t) for t in VALID_TRANSPORTS
    }
    transports: Dict[str, Dict[str, object]] = {}
    for transport in sorted(stats_by_transport):
        aggregate = transport == AGGREGATE_TRANSPORT_KEY
        transports[transport] = _transport_calibration_section(
            stats_by_transport[transport],
            heuristic if aggregate else transport_heuristics[transport],
            prior_strength, smoothing, aggregate=aggregate,
            spec_universe=set() if aggregate
            else spec_universe_by_transport.get(transport, set()),
        )

    for transport in VALID_TRANSPORTS:
        if transport in transports:
            continue
        if spec_universe_by_transport.get(transport):
            transports[transport] = _transport_calibration_section(
                PairCoResponseStats(), transport_heuristics[transport],
                prior_strength, smoothing, aggregate=False,
                spec_universe=spec_universe_by_transport[transport],
            )
    if include_aggregate and AGGREGATE_TRANSPORT_KEY not in transports:
        agg = PairCoResponseStats()
        for t, s in stats_by_transport.items():
            if t != AGGREGATE_TRANSPORT_KEY:
                agg.merge(s)
        transports[AGGREGATE_TRANSPORT_KEY] = _transport_calibration_section(
            agg, heuristic, prior_strength, smoothing, aggregate=True,
            spec_universe=set().union(*spec_universe_by_transport.values())
            if spec_universe_by_transport else set(),
        )

    universe = sorted({
        c for section in transports.values()
        for c in section["universe"]  # type: ignore[arg-type]
    })
    artifact: Dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "model": MODEL_NAME,
        "objective_version": objective_version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "semantics": {
            "heuristic": (
                "Structural compatibility h(i,j) in [0,1] (nominal byte"
                "overlap heuristic; symmetric; missing profiles use neutral_q, not zero)"
            ),
            "observational": (
                "p_obs_j_given_i = (N(i&j)+a)/(N(i)+a+b): observational co-response frequency"
                "(not mutation causality; origin_protocol is unused)"
            ),
            "calibrated": (
                "Beta-binomial posterior mean q=(s*h+N(i&j))/(s+N(i));"
                "low counts favor the heuristic, high counts favor observations"
            ),
            "transport": (
                f"Statistics are transport-specific; {AGGREGATE_TRANSPORT_KEY!r} is an explicit aggregate"
                "(aggregate=true); not used at runtime"
            ),
        },
        "source": source_metadata or {},
        "cluster_universe": universe,
        "heuristic": {

            "config_hash": heuristic_config_hash(specs),
            "algorithm_version": HEURISTIC_ALGORITHM_VERSION,
            "spec_digests": heuristic_spec_digests(specs),
            "transport_profiles": {
                t: {"spec_digests": heuristic_spec_digests(selected),
                    "config_hash": heuristic_config_hash(selected)}
                for t, selected in profiles.items()
            },
            "n_specs": len(specs or {}),
            "spec_names": sorted((specs or {}).keys()),
            "neutral_q": float(neutral_q),
        },
        "prior_strength": float(prior_strength),
        "smoothing": [float(smoothing[0]), float(smoothing[1])],
        "transports": transports,
    }
    artifact["artifact_hash"] = artifact_core_hash(artifact)
    return artifact

def artifact_core_hash(data: Dict) -> str:
    """Hash all semantic calibration fields, excluding incidental metadata."""
    core = {
        k: data[k]
        for k in (
            "schema_version", "model", "objective_version", "cluster_universe",
            "heuristic", "prior_strength", "smoothing", "transports",
        )
        if k in data
    }
    blob = json.dumps(core, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

def atomic_write_json(path: str, obj: Dict) -> None:
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

def save_artifact(path: str, artifact: Dict) -> None:
    atomic_write_json(path, artifact)

class CalibrationArtifact:
    """Read-only access to calibration values and provenance."""

    def __init__(self, data: Dict) -> None:
        self._data = data

    @property
    def raw(self) -> Dict:
        return self._data

    @property
    def schema_version(self) -> int:
        return int(self._data.get("schema_version", -1))

    @property
    def model(self) -> str:
        return str(self._data.get("model", ""))

    @property
    def artifact_hash(self) -> str:
        return str(self._data.get("artifact_hash", ""))

    @property
    def universe(self) -> FrozenSet[str]:
        return frozenset(self._data.get("cluster_universe", ()))

    @property
    def prior_strength(self) -> float:
        return float(self._data.get("prior_strength", 0.0))

    @property
    def objective_version(self) -> Optional[str]:
        value = self._data.get("objective_version")
        return str(value) if value is not None else None

    @property
    def heuristic_config_hash(self) -> str:
        return str(self._data.get("heuristic", {}).get("config_hash", ""))

    @property
    def heuristic_algorithm_version(self) -> Optional[int]:
        value = self._data.get("heuristic", {}).get("algorithm_version")
        return int(value) if value is not None else None

    @property
    def spec_digests(self) -> Dict[str, str]:
        return dict(self._data.get("heuristic", {}).get("spec_digests", {}))

    @property
    def transports(self) -> FrozenSet[str]:
        return frozenset(self._data.get("transports", {}).keys())

    def transport_available(self, transport: str) -> bool:
        table = self._data.get("transports", {}).get(transport)
        return isinstance(table, dict) and not table.get("aggregate", False)

    def require_transport(self, transport: str) -> None:
        if not self.transport_available(transport):
            available = sorted(
                t for t in self.transports if t != AGGREGATE_TRANSPORT_KEY
            )
            raise ValueError(
                f"calibration artifact has no transport-stratified table for "
                f"{transport!r} (available: {available}; aggregate-only or "
                f"missing layer is NOT silently substituted)"
            )

    def require_universe(self, expected: Iterable[str]) -> None:
        missing = sorted(set(expected) - self.universe)
        if missing:
            raise ValueError(
                f"runtime universe clusters missing from calibration artifact: "
                f"{missing} (artifact universe has {len(self.universe)} clusters)"
            )

    def require_objective_version(self, expected: Optional[str]) -> None:
        """Reject a calibration artifact from another objective version."""
        if self.objective_version != expected:
            raise ValueError(
                f"artifact objective_version mismatch: artifact="
                f"{self.objective_version!r}, expected={expected!r}; q cannot be reused across "
                f"objective versions"
            )

    def require_heuristic_algorithm_version(self, expected: int) -> None:
        """Reject a calibration artifact from another scoring algorithm."""
        if self.heuristic_algorithm_version != expected:
            raise ValueError(
                f"artifact heuristic algorithm_version mismatch: artifact="
                f"{self.heuristic_algorithm_version!r}, expected={expected!r} — "
                f"heuristic scoring semantics changed, q values not comparable"
            )

    def require_spec_digests(self, expected: Dict[str, str],
                             transport: Optional[str] = None) -> None:
        """Require an exact digest match for every current profile."""
        profiles = self._data.get("heuristic", {}).get("transport_profiles")
        if transport is not None and profiles is not None:
            if transport not in profiles:
                raise ValueError(f"missing heuristic transport profile: {transport}")
            stored = profiles[transport]["spec_digests"]
        else:
            # Old artifacts remain readable, but their raw digests cannot pass
            # the new documented both->tcp/udp runtime identity check.
            stored = self.spec_digests
        missing = sorted(name for name in expected if name not in stored)
        changed = sorted(
            name for name in expected
            if name in stored and stored[name] != expected[name]
        )
        if missing or changed:
            raise ValueError(
                f"artifact heuristic spec digest mismatch: missing={missing}, "
                f"changed={changed} (artifact has {len(stored)} spec digests) "
                f"— protocol specs changed since calibration"
            )

    def _pair_entry(self, transport: str, i: str, j: str) -> Optional[Dict]:
        table = self._data.get("transports", {}).get(transport, {})
        return table.get("pairs", {}).get(_pair_key(i, j))

    def q(self, i: str, j: str, transport: str, default: float = NEUTRAL_Q) -> float:
        """Return a calibrated conditional response estimate for the service pair."""
        entry = self._pair_entry(transport, i, j)
        if entry is None:
            return float(default)
        return float(entry["calibrated_mean"])

    def heuristic(self, i: str, j: str, transport: str,
                  default: float = NEUTRAL_Q) -> float:
        entry = self._pair_entry(transport, i, j)
        if entry is None:
            return float(default)
        return float(entry["heuristic"])

    def summary(self) -> Dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "model": self.model,
            "objective_version": self.objective_version,
            "artifact_hash": self.artifact_hash,
            "cluster_universe_size": len(self.universe),
            "transports": sorted(self.transports),
            "prior_strength": self.prior_strength,
            "heuristic_config_hash": self.heuristic_config_hash,
            "heuristic_algorithm_version": self.heuristic_algorithm_version,
            "n_spec_digests": len(self.spec_digests),
        }

def validate_artifact(
    data: Dict,
    transport: Optional[str] = None,
    expected_universe: Optional[Iterable[str]] = None,
    expected_objective_version: Optional[str] = None,
    expected_spec_digests: Optional[Dict[str, str]] = None,
    expected_heuristic_algorithm_version: Optional[int] = None,
) -> None:
    """Reject incompatible objective, topology, algorithm or profile digests."""
    if not isinstance(data, dict):
        raise ValueError("artifact is not a JSON object")
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        raise ValueError(
            f"artifact schema_version mismatch: {version!r} != {SCHEMA_VERSION}"
        )
    model = data.get("model")
    if model != MODEL_NAME:
        raise ValueError(f"artifact model mismatch: {model!r} != {MODEL_NAME!r}")
    stored = data.get("artifact_hash")
    recomputed = artifact_core_hash(data)
    if stored != recomputed:
        raise ValueError(
            f"artifact_hash mismatch (stored={stored!r}, recomputed="
            f"{recomputed!r}) — file corrupted or edited after generation"
        )
    artifact = CalibrationArtifact(data)
    if transport is not None:
        artifact.require_transport(transport)
    if expected_universe is not None:
        artifact.require_universe(expected_universe)
    if expected_objective_version is not None:
        artifact.require_objective_version(expected_objective_version)
    if expected_heuristic_algorithm_version is not None:
        artifact.require_heuristic_algorithm_version(
            expected_heuristic_algorithm_version)
    if expected_spec_digests is not None:
        artifact.require_spec_digests(expected_spec_digests, transport=transport)

_VALIDATED_ARTIFACT_CACHE: Dict[str, CalibrationArtifact] = {}
_WARNED_KEYS: set = set()

def load_calibration_artifact(
    path: str,
    transport: Optional[str] = None,
    expected_universe: Optional[Iterable[str]] = None,
    strict: bool = True,
    expected_objective_version: Optional[str] = None,
    expected_spec_digests: Optional[Dict[str, str]] = None,
    expected_heuristic_algorithm_version: Optional[int] = None,
) -> Optional[CalibrationArtifact]:
    """Load and validate calibration with a process-local cache."""
    ap = os.path.abspath(path)
    try:
        artifact = _VALIDATED_ARTIFACT_CACHE.get(ap)
        if artifact is None:
            if not os.path.isfile(ap):
                raise ValueError(f"calibration artifact not found: {ap}")
            with open(ap, encoding="utf-8") as fh:
                data = json.load(fh)
            validate_artifact(data)   
            artifact = CalibrationArtifact(data)
            _VALIDATED_ARTIFACT_CACHE[ap] = artifact
        if transport is not None:
            artifact.require_transport(transport)
        if expected_universe is not None:
            artifact.require_universe(expected_universe)
        if expected_objective_version is not None:
            artifact.require_objective_version(expected_objective_version)
        if expected_heuristic_algorithm_version is not None:
            artifact.require_heuristic_algorithm_version(
                expected_heuristic_algorithm_version)
        if expected_spec_digests is not None:
            artifact.require_spec_digests(expected_spec_digests)
        return artifact
    except ValueError as exc:
        if strict:
            raise
        warn_key = (ap, str(transport), str(exc)[:120])
        if warn_key not in _WARNED_KEYS:
            _WARNED_KEYS.add(warn_key)
            logger.warning(
                "[COMPAT] calibration artifact rejected (fallback to mode "
                f"'{COMPAT_MODE_NONE}'): {exc}"
            )
        return None

# ============================================================================

# ============================================================================

def validate_epsilon(epsilon: float) -> float:
    """Require 0 < epsilon < 1 so smoothing cannot remove exploration."""
    eps = float(epsilon)
    if not (0.0 < eps < 1.0):
        raise ValueError(
            f"COMPATIBILITY_EPSILON must be in (0,1) exclusive, got {epsilon!r}"
        )
    return eps

def compat_breadth_weights(
    base_weights: Dict[str, float],
    target: str,
    q_row: Dict[str, float],
    epsilon: float,
    neutral_q: float = NEUTRAL_Q,
) -> Dict[str, float]:
    """Mix calibrated pair scores with epsilon and normalize outside the target."""
    eps = validate_epsilon(epsilon)
    out: Dict[str, float] = {}
    for cluster, weight in base_weights.items():
        if cluster == target:
            continue
        q = float(q_row.get(cluster, neutral_q))
        if not 0.0 <= q <= 1.0:
            raise ValueError(
                f"q({target!r},{cluster!r})={q} out of [0,1]"
            )
        w = float(weight)
        if w < 0:
            raise ValueError(f"base weight for {cluster!r} must be >= 0, got {w}")
        out[cluster] = w * ((1.0 - eps) * q + eps)
    total = sum(out.values())
    if total <= 0.0:
        n = len(out)
        return {c: 1.0 / n for c in out} if n else {}
    return {c: v / total for c, v in out.items()}

@dataclass(frozen=True)
class RuntimeCompatInfo:
    """Record the compatibility prior actually applied at runtime."""
    applied_mode: str                    
    requested_mode: str
    epsilon: float
    target: str
    transport: str
    artifact_path: str = ""
    artifact_hash: str = ""
    weight_hash: str = ""                
    n_clusters: int = 0                  
    fallback_reason: str = ""            

    def as_dict(self) -> Dict[str, object]:
        return {
            "applied_mode": self.applied_mode,
            "requested_mode": self.requested_mode,
            "epsilon": self.epsilon,
            "target": self.target,
            "transport": self.transport,
            "artifact_path": self.artifact_path,
            "artifact_hash": self.artifact_hash,
            "weight_hash": self.weight_hash,
            "n_clusters": self.n_clusters,
            "fallback_reason": self.fallback_reason,
        }

def runtime_compat_breadth_weights(
    base_weights: Dict[str, float],
    target: str,
    transport: str,
    mode: str,
    specs: Optional[Dict[str, UnifiedProtocolSpec]] = None,
    artifact_path: Optional[str] = None,
    epsilon: Optional[float] = None,
    neutral_q: Optional[float] = None,
    strict: Optional[bool] = None,
    expected_objective_version: Optional[str] = None,
    expected_spec_digests: Optional[Dict[str, str]] = None,
    expected_heuristic_algorithm_version: Optional[int] = None,
) -> Tuple[Optional[Dict[str, float]], RuntimeCompatInfo]:
    """Resolve the configured prior and build target-specific breadth weights."""
    if mode not in VALID_COMPAT_MODES:
        raise ValueError(
            f"COMPATIBILITY_PRIOR_MODE must be one of {VALID_COMPAT_MODES}, got {mode!r}"
        )
    eps = validate_epsilon(
        epsilon if epsilon is not None
        else getattr(config, "COMPATIBILITY_EPSILON", 0.1)
    )
    neutral = float(
        neutral_q if neutral_q is not None
        else getattr(config, "COMPATIBILITY_NEUTRAL_Q", NEUTRAL_Q)
    )
    strict_flag = bool(
        strict if strict is not None
        else getattr(config, "COMPATIBILITY_STRICT_VALIDATION", True)
    )
    info = RuntimeCompatInfo(
        applied_mode=COMPAT_MODE_NONE, requested_mode=mode, epsilon=eps,
        target=target, transport=transport,
    )
    if mode == COMPAT_MODE_NONE:
        return None, info

    q_row: Dict[str, float] = {}
    if mode == COMPAT_MODE_HEURISTIC:
        if not specs or target not in specs:
            reason = (f"heuristic mode requires a spec for target {target!r} "
                      f"(loaded specs: {len(specs or {})})")
            logger.warning("[COMPAT] %s — fallback to mode 'none'", reason)
            return None, _replace_info(info, fallback_reason=reason)
        scorer = HeuristicCompatScores(specs, neutral_q=neutral)
        q_row = {
            c: scorer.score(target, c)
            for c in base_weights if c != target
        }
    else:  # calibrated
        path = artifact_path or getattr(
            config, "COMPATIBILITY_PRIOR_ARTIFACT", "")
        universe = set(base_weights) | {target}

        expected_obj = (
            expected_objective_version
            if expected_objective_version is not None
            else getattr(config, "OBJECTIVE_VERSION", None)
        )

        expected_digests = expected_spec_digests
        if expected_digests is None and specs:
            expected_digests = heuristic_spec_digests(specs)
        
        expected_algo = (
            expected_heuristic_algorithm_version
            if expected_heuristic_algorithm_version is not None
            else HEURISTIC_ALGORITHM_VERSION
        )

        artifact = load_calibration_artifact(
            path, transport=transport or "",
            expected_universe=universe, strict=strict_flag,
            expected_objective_version=expected_obj,
            expected_spec_digests=expected_digests,
            expected_heuristic_algorithm_version=expected_algo,
        )
        if artifact is None:
            return None, _replace_info(
                info,
                fallback_reason=(
                    "calibration artifact rejected/missing "
                    f"(path={path}, transport={transport!r}, strict={strict_flag})"
                ),
            )
        q_row = {
            c: artifact.q(target, c, transport, default=neutral)
            for c in base_weights if c != target
        }
        info = _replace_info(info, artifact_path=os.path.abspath(path),
                             artifact_hash=artifact.artifact_hash)

    weights = compat_breadth_weights(base_weights, target, q_row, eps, neutral)
    info = _replace_info(
        info, applied_mode=mode, weight_hash=stable_dict_hash(weights),
        n_clusters=len(weights),
    )
    return weights, info

def _replace_info(info: RuntimeCompatInfo, **changes) -> RuntimeCompatInfo:
    return replace(info, **changes)
