"""Service-level packet outcomes and bounded soft rewards. Qualification requires target reachability, a selective additional post-send service and breadth above the transport/target control threshold. Banner timing is preserved separately. Multiple implementations never inflate service breadth."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from core.clustering import (
    cluster_of,
    observed_clusters_from,
    passive_clusters_from,
    payload_triggered_clusters_from,
)
from core.service_tester import ServiceResponse
from core.background_model import BackgroundProfile, adjusted_breadth, adjusted_cluster_weights

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

REWARD_MODE_TARGET_ONLY = "target_only"                      
REWARD_MODE_TARGET_GATED_BREADTH = "target_gated_breadth"    
REWARD_MODE_UNGATED_BREADTH = "ungated_breadth"              
REWARD_MODE_BACKGROUND_ADJUSTED = "background_adjusted_breadth"  # background-adjusted search

VALID_REWARD_MODES = (
    REWARD_MODE_TARGET_ONLY,
    REWARD_MODE_TARGET_GATED_BREADTH,
    REWARD_MODE_UNGATED_BREADTH,
    REWARD_MODE_BACKGROUND_ADJUSTED,
)

_DEFAULT_OBJECTIVE_VERSION = {
    REWARD_MODE_TARGET_ONLY: "target_only_v0",
    REWARD_MODE_TARGET_GATED_BREADTH: "target_gated_breadth_v1",
    REWARD_MODE_UNGATED_BREADTH: "ungated_breadth_ablation",
    REWARD_MODE_BACKGROUND_ADJUSTED: "background_adjusted_breadth",
}

@dataclass(frozen=True)
class PacketOutcome:
    """Phase-aware service response facts for one packet."""

    packet_hash: str
    mutation_target: str
    triggered_clusters: FrozenSet[str]
    triggered_members: FrozenSet[Tuple[str, str]]
    target_triggered: bool
    response_count: int
    transport: str = ""
    observed_clusters: FrozenSet[str] = frozenset()
    passive_clusters: FrozenSet[str] = frozenset()
    payload_triggered_clusters: FrozenSet[str] = frozenset()
    payload_triggered_members: FrozenSet[Tuple[str, str]] = frozenset()
    target_mode: str = "active"
    target_payload_triggered: bool = False
    target_passive_observed: bool = False
    banner_count: int = 0
    payload_response_count: int = 0

def packet_hash_of(packet: bytes) -> str:
    """Hash packet content for lineage and event correlation."""
    return hashlib.sha256(packet).hexdigest()

def build_packet_outcome(
    packet: bytes,
    responses: Sequence[ServiceResponse],
    mutation_target: str,
    transport: str = "",
    target_mode: str = "active",
) -> PacketOutcome:
    """Derive service-level facts from raw implementation responses."""
    if target_mode not in ("active", "passive"):
        raise ValueError(f"target_mode must be 'active' or 'passive', got {target_mode!r}")
    observed_clusters = observed_clusters_from(list(responses))
    passive_clusters = passive_clusters_from(list(responses))
    payload_clusters = payload_triggered_clusters_from(list(responses))
    triggered_members = frozenset(
        (cluster_of(r.service_name), r.service_name)
        for r in responses
        if r.response_bytes
    )
    payload_members = frozenset(
        (cluster_of(r.service_name), r.service_name)
        for r in responses
        if getattr(r, "response_phase", "post_payload") == "post_payload"
        and bool(r.response_bytes)
    )
    target_payload = mutation_target in payload_clusters
    # Banner observation is independent from the mutually exclusive
    # passive-only set: a member may emit both a pre-payload banner and a
    # post-payload response.
    target_passive = any(
        cluster_of(r.service_name) == mutation_target
        and getattr(r, "has_banner", False)
        for r in responses
    )
    target_triggered = (
        mutation_target in observed_clusters
        if target_mode == "passive"
        else target_payload
    )
    return PacketOutcome(
        packet_hash=packet_hash_of(packet),
        mutation_target=mutation_target,
        # Legacy alias: observed, not necessarily post-send. Breadth must
        # use payload_triggered_clusters explicitly; despite its historical
        # name that field denotes temporal phase, not payload causality.
        triggered_clusters=frozenset(observed_clusters),
        triggered_members=triggered_members,
        target_triggered=target_triggered,
        response_count=sum(1 for r in responses if r.response_bytes),
        transport=transport,
        observed_clusters=frozenset(observed_clusters),
        passive_clusters=frozenset(passive_clusters),
        payload_triggered_clusters=frozenset(payload_clusters),
        payload_triggered_members=payload_members,
        target_mode=target_mode,
        target_payload_triggered=target_payload,
        target_passive_observed=target_passive,
        banner_count=sum(1 for r in responses if getattr(r, "has_banner", False)),
        payload_response_count=sum(
            1 for r in responses
            if getattr(r, "response_phase", "post_payload") == "post_payload"
            and bool(r.response_bytes)
        ),
    )

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RewardBreakdown:
    """Explicit reward components used by the two utility heads."""

    reachability: float
    weighted_breadth: float
    target_gated_breadth: float
    n_clusters: int
    n_extra_clusters: int
    credit_weight: float
    objective_version: str
    raw_payload_breadth: float = 0.0
    background_adjusted_breadth: float = 0.0
    n_selective_extra_clusters: int = 0
    selective_extra_clusters: Tuple[str, ...] = ()
    null_threshold: float = 0.0
    qualifies_multi_probe: bool = False
    passive_target: bool = False
    reachability_credit_weight: float = 1.0
    background_artifact_hash: str = ""

def compute_credit_weight(
    n_touched_fields: int,
    mode: str = "shared",
) -> float:
    """Allocate bounded credit among the mutated fields."""
    if mode == "split":
        if n_touched_fields <= 0:
            return 0.0
        return 1.0 / n_touched_fields
    
    if n_touched_fields < 0:
        raise ValueError(f"n_touched_fields must be >= 0, got {n_touched_fields}")
    return 1.0

class MultiObjectiveReward:
    """Compute Reach and Breadth utility from packet observations."""

    def __init__(
        self,
        cluster_weights: Optional[Dict[str, float]] = None,
        mode: str = REWARD_MODE_TARGET_ONLY,
        lambda_breadth: float = 0.5,
        known_clusters: Optional[Iterable[str]] = None,
        objective_version: Optional[str] = None,
        credit_mode: str = "shared",
        compat_target: Optional[str] = None,
        compat_weights: Optional[Dict[str, float]] = None,
        compat_meta: Optional[Dict[str, object]] = None,
        background_profile: Optional[BackgroundProfile] = None,
        transport: str = "",
        mutation_target: Optional[str] = None,
    ):
        if mode not in VALID_REWARD_MODES:
            raise ValueError(
                f"unknown reward mode {mode!r}; expected one of {VALID_REWARD_MODES}"
            )
        if mode != REWARD_MODE_TARGET_ONLY and cluster_weights is None and known_clusters is None:
            raise ValueError(
                f"reward mode {mode!r} requires cluster_weights or known_clusters "
                f"to define the breadth universe"
            )
        if (compat_target is None) != (compat_weights is None):
            raise ValueError(
                "compat_target and compat_weights must be provided together"
            )
        self.mode = mode
        self.lambda_breadth = float(lambda_breadth)
        self.credit_mode = credit_mode
        self.objective_version = objective_version or _DEFAULT_OBJECTIVE_VERSION[mode]

        if cluster_weights is not None:
            self._weights: Dict[str, float] = dict(cluster_weights)
        elif known_clusters is not None:
            ks = set(known_clusters)
            n = max(1, len(ks))
            self._weights = {c: 1.0 / n for c in ks}
        else:
            self._weights = {}

        self.compat_target = compat_target
        self._compat_weights: Optional[Dict[str, float]] = (
            dict(compat_weights) if compat_weights is not None else None
        )
        self.compat_meta: Dict[str, object] = dict(compat_meta or {})
        self.background_profile = background_profile
        self.transport = transport
        self.mutation_target = mutation_target
        if self.mode == REWARD_MODE_BACKGROUND_ADJUSTED:
            if self.background_profile is None:
                raise ValueError("background_adjusted_breadth requires a BackgroundProfile")
            if not self.transport or not self.mutation_target:
                raise ValueError(
                    "background_adjusted_breadth requires transport and mutation_target")

    def _weight(self, cluster: str) -> float:
        
        return self._weights.get(cluster, 0.0)

    def _effective_weights(self, mutation_target: str) -> Dict[str, float]:
        """Resolve shared or target-specific calibrated breadth weights."""
        if (self._compat_weights is not None
                and mutation_target == self.compat_target):
            return self._compat_weights
        return self._weights

    def compat_summary(self) -> Dict[str, object]:
        """Return applied-prior metadata for manifests and reward events."""
        return {
            "applied": self._compat_weights is not None,
            "target": self.compat_target or "",
            **self.compat_meta,
        }

    @property
    def target_mode(self) -> str:
        if (
            self.background_profile is not None
            and self.background_profile.is_passive_target(
                self.transport, self.mutation_target or "")
        ):
            return "passive"
        return "active"

    def evaluate(
        self,
        outcome: PacketOutcome,
        n_touched_fields: int = 1,
    ) -> RewardBreakdown:
        if self.mode == REWARD_MODE_BACKGROUND_ADJUSTED:
            if outcome.mutation_target != self.mutation_target:
                raise ValueError(
                    "background objective target mismatch: "
                    f"engine={self.mutation_target!r}, outcome={outcome.mutation_target!r}"
                )
            if outcome.transport != self.transport:
                raise ValueError(
                    "background objective transport mismatch: "
                    f"engine={self.transport!r}, outcome={outcome.transport!r}"
                )
        reachability = 1.0 if outcome.target_triggered else 0.0

        weighted_breadth = 0.0
        raw_payload_breadth = 0.0
        adjusted_value = 0.0
        selective_extra: Tuple[str, ...] = ()
        threshold = 0.0
        passive_target = False
        if self.mode in (
            REWARD_MODE_TARGET_GATED_BREADTH,
            REWARD_MODE_UNGATED_BREADTH,
            REWARD_MODE_BACKGROUND_ADJUSTED,
        ):
            eff = self._effective_weights(outcome.mutation_target)
            breadth_clusters = (
                outcome.payload_triggered_clusters
                if self.mode == REWARD_MODE_BACKGROUND_ADJUSTED
                else outcome.triggered_clusters
            )
            extra = [
                c for c in breadth_clusters
                if c != outcome.mutation_target
            ]
            denom = sum(
                v for c, v in eff.items()
                if c != outcome.mutation_target
            )
            if denom > 0.0:
                weighted_breadth = sum(eff.get(c, 0.0) for c in extra) / denom
            raw_payload_breadth = weighted_breadth

            if self.mode == REWARD_MODE_BACKGROUND_ADJUSTED:
                profile = self.background_profile
                adjusted_weights = profile.adjusted_weights(self.transport, eff)
                adjusted_value = adjusted_breadth(
                    breadth_clusters, outcome.mutation_target, adjusted_weights)
                selective_extra = tuple(sorted(
                    profile.selective_clusters(self.transport, extra)
                ))
                threshold = profile.null_threshold(
                    self.transport, outcome.mutation_target)
                passive_target = profile.is_passive_target(
                    self.transport, outcome.mutation_target)
                weighted_breadth = adjusted_value

        if self.mode in (
            REWARD_MODE_TARGET_GATED_BREADTH,
            REWARD_MODE_BACKGROUND_ADJUSTED,
        ):
            
            target_gated_breadth = weighted_breadth if outcome.target_triggered else 0.0
        else:
            
            target_gated_breadth = weighted_breadth

        credit_weight = compute_credit_weight(n_touched_fields, self.credit_mode)

        breakdown = RewardBreakdown(
            reachability=reachability,
            weighted_breadth=weighted_breadth,
            target_gated_breadth=target_gated_breadth,
            n_clusters=len(outcome.triggered_clusters),
            n_extra_clusters=len(
                outcome.triggered_clusters - {outcome.mutation_target}
            ),
            credit_weight=credit_weight,
            objective_version=self.objective_version,
            raw_payload_breadth=raw_payload_breadth,
            background_adjusted_breadth=adjusted_value,
            n_selective_extra_clusters=len(selective_extra),
            selective_extra_clusters=selective_extra,
            null_threshold=threshold,
            qualifies_multi_probe=bool(
                self.mode == REWARD_MODE_BACKGROUND_ADJUSTED
                and outcome.target_triggered
                and selective_extra
                and adjusted_value > threshold
            ),
            passive_target=passive_target,
            reachability_credit_weight=0.0 if passive_target else credit_weight,
            background_artifact_hash=(
                self.background_profile.artifact_hash
                if self.background_profile is not None else ""
            ),
        )
        _validate_breakdown(breakdown)
        return breakdown

def _validate_breakdown(b: RewardBreakdown) -> None:
    """Require every reward component to lie in [0, 1]."""
    eps = 1e-9
    for name in (
        "reachability", "weighted_breadth", "target_gated_breadth",
        "credit_weight", "raw_payload_breadth", "background_adjusted_breadth",
        "null_threshold", "reachability_credit_weight",
    ):
        v = getattr(b, name)
        if not (-eps <= v <= 1.0 + eps):
            raise ValueError(f"reward component {name}={v} out of [0,1]")
