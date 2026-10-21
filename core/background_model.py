"""Background-response calibration for the background-adjusted search objective.

The artifact deliberately contains facts and calibration parameters only.  It
does not run network probes and it never treats a classifier result as online
reward.  All rates are transport-stratified and Laplace smoothed.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Sequence

SCHEMA_VERSION = 1
ARTIFACT_TYPE = "background_response_profile"

def service_topology_hash(services: Mapping[str, object]) -> str:
    """Stable digest of member names, endpoints, transports and cluster mapping."""
    from config import cluster_of

    rows = []
    for member, raw in sorted(services.items()):
        if isinstance(raw, dict):
            host = raw.get("host", "")
            port = raw.get("port", 0)
            transport = raw.get("protocol", "tcp")
        else:
            values = tuple(raw)
            host = values[0] if len(values) > 0 else ""
            port = values[1] if len(values) > 1 else 0
            transport = values[2] if len(values) > 2 else "tcp"
        rows.append((member, cluster_of(member), str(host), int(port), str(transport)))
    blob = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:20]

def laplace_rate(hits: int, total: int) -> float:
    if hits < 0 or total < 0 or hits > total:
        raise ValueError(f"invalid hit count: hits={hits}, total={total}")
    return (float(hits) + 1.0) / (float(total) + 2.0)

def wilson_lower_bound(hits: int, total: int, z: float = 1.959963984540054) -> float:
    """Two-sided 95% Wilson-score lower bound by default."""
    if hits < 0 or total < 0 or hits > total:
        raise ValueError(f"invalid hit count: hits={hits}, total={total}")
    if total == 0:
        return 0.0
    n = float(total)
    p = float(hits) / n
    z2 = z * z
    center = p + z2 / (2.0 * n)
    radius = z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n)
    return max(0.0, (center - radius) / (1.0 + z2 / n))

def quantile(values: Sequence[float], q: float) -> float:
    """Deterministic linear-interpolation quantile (NumPy ``linear`` semantics)."""
    if not 0.0 <= q <= 1.0:
        raise ValueError(f"q must be in [0,1], got {q}")
    if not values:
        return 0.0
    ordered = sorted(float(v) for v in values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return ordered[lo]
    frac = pos - lo
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac

@dataclass(frozen=True)
class BackgroundEntry:
    control_hits: int = 0
    control_total: int = 0
    round1_hits: int = 0
    round1_total: int = 0
    mixed_rate: float = 0.5

    @classmethod
    def build(
        cls,
        *,
        control_hits: int,
        control_total: int,
        round1_hits: int,
        round1_total: int,
        eta: float,
    ) -> "BackgroundEntry":
        if not 0.0 <= eta <= 1.0:
            raise ValueError(f"eta must be in [0,1], got {eta}")
        pc = laplace_rate(control_hits, control_total)
        pr = laplace_rate(round1_hits, round1_total)
        return cls(
            control_hits=int(control_hits),
            control_total=int(control_total),
            round1_hits=int(round1_hits),
            round1_total=int(round1_total),
            mixed_rate=eta * pc + (1.0 - eta) * pr,
        )

    @property
    def control_rate(self) -> float:
        return laplace_rate(self.control_hits, self.control_total)

    @property
    def round1_rate(self) -> float:
        return laplace_rate(self.round1_hits, self.round1_total)

@dataclass(frozen=True)
class BannerEntry:
    hits: int = 0
    total: int = 0
    wilson_lower: float = 0.0
    stable: bool = False

    @classmethod
    def build(cls, hits: int, total: int, minimum: float) -> "BannerEntry":
        lower = wilson_lower_bound(hits, total)
        return cls(int(hits), int(total), lower, bool(total and lower >= minimum))

def adjusted_cluster_weights(
    base_weights: Mapping[str, float],
    rates: Mapping[str, float],
    gamma: float,
) -> Dict[str, float]:
    if gamma <= 0.0:
        raise ValueError(f"gamma must be > 0, got {gamma}")
    result: Dict[str, float] = {}
    for cluster, weight in base_weights.items():
        p = min(1.0, max(0.0, float(rates.get(cluster, 0.5))))
        result[cluster] = max(0.0, float(weight)) * ((1.0 - p) ** gamma)
    return result

def adjusted_breadth(
    triggered_clusters: Iterable[str],
    mutation_target: str,
    adjusted_weights: Mapping[str, float],
) -> float:
    triggered = set(triggered_clusters)
    denom = sum(
        float(weight) for cluster, weight in adjusted_weights.items()
        if cluster != mutation_target
    )
    if denom <= 0.0:
        return 0.0
    numerator = sum(
        float(adjusted_weights.get(cluster, 0.0))
        for cluster in triggered
        if cluster != mutation_target
    )
    return min(1.0, max(0.0, numerator / denom))

def select_gamma(
    base_weights: Mapping[str, float],
    rates: Mapping[str, float],
    candidates: Sequence[float] = (1.0, 2.0, 3.0),
    high_rate: float = 0.8,
    high_mass_max: float = 0.1,
) -> tuple[float, bool]:
    """Choose the smallest gamma suppressing high-background weight mass.

    Returns ``(gamma, met_target)``.  If no candidate satisfies the target,
    the largest candidate is returned with ``met_target=False``.
    """
    if not candidates or any(float(g) <= 0.0 for g in candidates):
        raise ValueError("gamma candidates must be non-empty and positive")
    if not 0.0 <= high_rate <= 1.0 or not 0.0 <= high_mass_max <= 1.0:
        raise ValueError("high_rate/high_mass_max must be in [0,1]")
    ordered = sorted({float(g) for g in candidates})
    for gamma in ordered:
        adjusted = adjusted_cluster_weights(base_weights, rates, gamma)
        total = sum(adjusted.values())
        high = sum(
            adjusted.get(cluster, 0.0)
            for cluster, p in rates.items()
            if float(p) >= high_rate
        )
        mass = high / total if total > 0.0 else 0.0
        if mass <= high_mass_max:
            return gamma, True
    return ordered[-1], False

def _canonical_hash(payload: Mapping[str, object]) -> str:
    data = dict(payload)
    data.pop("artifact_hash", None)
    blob = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

@dataclass
class BackgroundProfile:
    objective_version: str
    service_topology_hash: str
    weight_config_hash: str
    eta: float = 0.5
    high_rate: float = 0.8
    high_mass_max: float = 0.1
    gamma: Dict[str, float] = field(default_factory=dict)
    gamma_target_met: Dict[str, bool] = field(default_factory=dict)
    null_quantile: float = 0.95
    entries: Dict[str, Dict[str, BackgroundEntry]] = field(default_factory=dict)
    banner_members: Dict[str, Dict[str, BannerEntry]] = field(default_factory=dict)
    passive_clusters: Dict[str, list[str]] = field(default_factory=dict)
    null_thresholds: Dict[str, Dict[str, float]] = field(default_factory=dict)
    source_metadata: Dict[str, object] = field(default_factory=dict)
    artifact_hash: str = ""

    def rates_for(self, transport: str) -> Dict[str, float]:
        return {
            cluster: entry.mixed_rate
            for cluster, entry in self.entries.get(transport, {}).items()
        }

    def is_passive_target(self, transport: str, cluster: str) -> bool:
        return cluster in set(self.passive_clusters.get(transport, ()))

    def null_threshold(self, transport: str, target: str) -> float:
        return float(self.null_thresholds.get(transport, {}).get(target, 0.0))

    def adjusted_weights(
        self, transport: str, base_weights: Mapping[str, float]
    ) -> Dict[str, float]:
        gamma = float(self.gamma.get(transport, 1.0))
        return adjusted_cluster_weights(base_weights, self.rates_for(transport), gamma)

    def breadth(
        self,
        *,
        transport: str,
        mutation_target: str,
        payload_triggered_clusters: Iterable[str],
        base_weights: Mapping[str, float],
    ) -> float:
        return adjusted_breadth(
            payload_triggered_clusters,
            mutation_target,
            self.adjusted_weights(transport, base_weights),
        )

    def selective_clusters(
        self, transport: str, clusters: Iterable[str]
    ) -> set[str]:
        rates = self.rates_for(transport)
        return {c for c in clusters if rates.get(c, 0.5) < self.high_rate}

    def to_dict(self) -> dict:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": ARTIFACT_TYPE,
            "objective_version": self.objective_version,
            "service_topology_hash": self.service_topology_hash,
            "weight_config_hash": self.weight_config_hash,
            "parameters": {
                "eta": self.eta,
                "high_rate": self.high_rate,
                "high_mass_max": self.high_mass_max,
                "null_quantile": self.null_quantile,
            },
            "gamma": dict(sorted(self.gamma.items())),
            "gamma_target_met": dict(sorted(self.gamma_target_met.items())),
            "entries": {
                transport: {
                    cluster: asdict(entry)
                    for cluster, entry in sorted(items.items())
                }
                for transport, items in sorted(self.entries.items())
            },
            "banner_members": {
                transport: {
                    member: asdict(entry)
                    for member, entry in sorted(items.items())
                }
                for transport, items in sorted(self.banner_members.items())
            },
            "passive_clusters": {
                transport: sorted(clusters)
                for transport, clusters in sorted(self.passive_clusters.items())
            },
            "null_thresholds": {
                transport: {target: float(value) for target, value in sorted(items.items())}
                for transport, items in sorted(self.null_thresholds.items())
            },
            "source_metadata": self.source_metadata,
        }
        payload["artifact_hash"] = _canonical_hash(payload)
        return payload

    def save(self, path: str) -> None:
        payload = self.to_dict()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_suffix(target.suffix + ".tmp")
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
        self.artifact_hash = payload["artifact_hash"]

    @classmethod
    def load(
        cls,
        path: str,
        *,
        expected_objective_version: Optional[str] = None,
        expected_service_topology_hash: Optional[str] = None,
        expected_weight_config_hash: Optional[str] = None,
    ) -> "BackgroundProfile":
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        if data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("background profile schema_version mismatch")
        if data.get("artifact_type") != ARTIFACT_TYPE:
            raise ValueError("background profile artifact_type mismatch")
        expected_hash = _canonical_hash(data)
        if data.get("artifact_hash") != expected_hash:
            raise ValueError("background profile artifact hash mismatch")
        checks = (
            ("objective_version", expected_objective_version),
            ("service_topology_hash", expected_service_topology_hash),
            ("weight_config_hash", expected_weight_config_hash),
        )
        for key, expected in checks:
            if expected is not None and data.get(key) != expected:
                raise ValueError(
                    f"background profile {key} mismatch: file={data.get(key)!r}, "
                    f"expected={expected!r}"
                )
        params = data.get("parameters", {})
        profile = cls(
            objective_version=data.get("objective_version", ""),
            service_topology_hash=data.get("service_topology_hash", ""),
            weight_config_hash=data.get("weight_config_hash", ""),
            eta=float(params.get("eta", 0.5)),
            high_rate=float(params.get("high_rate", 0.8)),
            high_mass_max=float(params.get("high_mass_max", 0.1)),
            gamma={k: float(v) for k, v in data.get("gamma", {}).items()},
            gamma_target_met={k: bool(v) for k, v in data.get("gamma_target_met", {}).items()},
            null_quantile=float(params.get("null_quantile", 0.95)),
            entries={
                transport: {
                    cluster: BackgroundEntry(**entry)
                    for cluster, entry in items.items()
                }
                for transport, items in data.get("entries", {}).items()
            },
            banner_members={
                transport: {
                    member: BannerEntry(**entry)
                    for member, entry in items.items()
                }
                for transport, items in data.get("banner_members", {}).items()
            },
            passive_clusters={
                transport: list(clusters)
                for transport, clusters in data.get("passive_clusters", {}).items()
            },
            null_thresholds={
                transport: {target: float(value) for target, value in items.items()}
                for transport, items in data.get("null_thresholds", {}).items()
            },
            source_metadata=dict(data.get("source_metadata", {})),
            artifact_hash=expected_hash,
        )
        return profile
