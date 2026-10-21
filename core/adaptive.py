"""Adjust service-level mutation budgets using reachability, breadth, new response patterns and stagnation. This controls total attempts independently of the bandit field allocation. Raw-seed baselines do not enter adaptive mutation denominators."""

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)

def compute_hit_rate(
    multi_probe_packets: List[Dict],
    target_service: str,
) -> float:
    """Compute target service hit rate."""
    if not multi_probe_packets:
        return 0.0
    hit_count = sum(
        1 for pkt in multi_probe_packets
        if target_service in pkt['triggered_clusters']
    )
    return hit_count / len(multi_probe_packets)

def adjust_resource_boofuzz(
    current: int,
    hit_rate: float,
    min_val: int,
    max_val: int,
    increase_rate: float = 0.3,
    decrease_rate: float = 0.3,
    upper_threshold: float = 0.5,
    lower_threshold: float = 0.2,
) -> int:
    """
    Adjust the legacy mutation budget using headroom progressive damping.

    The function name is retained for historical runner/API compatibility; the
    current mutation engine is not Boofuzz.

    - hit_rate >= upper_threshold -> easy -> decrease
      delta = decrease_rate * (current - min), diminishes near floor
    - hit_rate <= lower_threshold -> hard -> increase
      delta = increase_rate * (max - current), diminishes near ceiling
    - Otherwise -> no change
    """
    if hit_rate >= upper_threshold:
        headroom = current - min_val
        delta = decrease_rate * headroom
        return max(min_val, int(current - delta))
    elif hit_rate <= lower_threshold:
        headroom = max_val - current
        delta = increase_rate * headroom
        return min(max_val, int(current + delta))
    return current

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

ADAPTIVE_MODE_LEGACY = "legacy_hit_rate"
ADAPTIVE_MODE_MULTIOBJECTIVE = "multiobjective_v1"
VALID_ADAPTIVE_MODES = (ADAPTIVE_MODE_LEGACY, ADAPTIVE_MODE_MULTIOBJECTIVE)

POLICY_WARMUP = "warmup"                        
POLICY_EXPLORE_LOW_REACH = "explore_low_reach"  
POLICY_MAINTAIN_PROGRESS = "maintain_progress"  
POLICY_MAINTAIN_MID = "maintain_mid"            
POLICY_SATURATED_REDUCE = "saturated_reduce"    
POLICY_STALLED_FLOOR = "stalled_floor"          
POLICY_LOW_REACH_HOLD = "low_reach_hold"        

_REACH_ZERO_EPS = 1e-9

def _stable_pattern_hash(pattern_key) -> int:
    """Hash a response pattern consistently across processes."""
    h = hashlib.blake2b(digest_size=8)
    if (isinstance(pattern_key, tuple) and pattern_key
            and pattern_key[0] == "selective"):
        h.update(b"selective\x00")
        for cluster in sorted({str(value) for value in pattern_key[1:]}):
            raw = cluster.encode("utf-8", "surrogatepass")
            h.update(len(raw).to_bytes(4, "big"))
            h.update(raw)
        return int.from_bytes(h.digest(), "big")

    h.update(b"legacy-response\x00")
    for cluster, resp in sorted(pattern_key, key=lambda p: (p[0], p[1])):
        h.update(cluster.encode("utf-8", "surrogatepass"))
        h.update(b"\x00")
        h.update(resp)
        h.update(b"\x01")
    return int.from_bytes(h.digest(), "big")

class AdaptiveMetrics:
    """Mutation-only progress statistics for service-level budget adjustment."""

    def __init__(self, pattern_track_cap: int = 4096):
        if int(pattern_track_cap) < 1:
            raise ValueError(f"pattern_track_cap must be >= 1, got {pattern_track_cap}")
        self.evaluated_mutants = 0
        self.target_hits = 0
        self.breadth_sum_on_target_hits = 0.0
        self.valuable_hits = 0
        self.new_response_patterns = 0
        self.high_value_candidates = 0
        self.consecutive_no_progress_batches = 0
        self._pattern_cap = int(pattern_track_cap)
        self._pattern_hashes: Set[int] = set()
        self._patterns_saturated = False
        
        self._batch_new_patterns = 0
        self._batch_valuable_hits = 0

    @property
    def reach_rate(self) -> float:
        if self.evaluated_mutants <= 0:
            return 0.0
        return self.target_hits / self.evaluated_mutants

    @property
    def breadth_mean(self) -> float:
        if self.target_hits <= 0:
            return 0.0
        return self.breadth_sum_on_target_hits / self.target_hits

    @property
    def valuable_rate(self) -> float:
        if self.evaluated_mutants <= 0:
            return 0.0
        return self.valuable_hits / self.evaluated_mutants

    def observe(
        self,
        *,
        target_triggered: bool,
        target_gated_breadth: float = 0.0,
        stored: bool = False,
        pattern_key: Optional[frozenset] = None,
    ) -> int:
        """Observe."""
        self.evaluated_mutants += 1
        new_patterns = 0
        if target_triggered:
            self.target_hits += 1
            breadth = min(max(float(target_gated_breadth), 0.0), 1.0)
            self.breadth_sum_on_target_hits += breadth
            if breadth > 0.0:
                self.valuable_hits += 1
                self._batch_valuable_hits += 1
            if pattern_key:
                new_patterns = self._track_pattern(pattern_key)
        if stored:
            self.high_value_candidates += 1
        return new_patterns

    def _track_pattern(self, pattern_key: frozenset) -> int:
        if self._patterns_saturated:
            return 0
        h = _stable_pattern_hash(pattern_key)
        if h in self._pattern_hashes:
            return 0
        if len(self._pattern_hashes) >= self._pattern_cap:
            self._patterns_saturated = True
            return 0
        self._pattern_hashes.add(h)
        self.new_response_patterns += 1
        self._batch_new_patterns += 1
        return 1

    def begin_batch(self) -> None:
        self._batch_new_patterns = 0
        self._batch_valuable_hits = 0

    def close_batch(self) -> bool:
        """Finish a batch window and update consecutive stagnation counters."""
        progressed = (self._batch_new_patterns > 0) or (self._batch_valuable_hits > 0)
        if progressed:
            self.consecutive_no_progress_batches = 0
        else:
            self.consecutive_no_progress_batches += 1
        self.begin_batch()
        return progressed

    def snapshot(self) -> Dict[str, float]:
        return {
            "evaluated_mutants": self.evaluated_mutants,
            "target_hits": self.target_hits,
            "breadth_sum_on_target_hits": self.breadth_sum_on_target_hits,
            "valuable_hits": self.valuable_hits,
            "new_response_patterns": self.new_response_patterns,
        }

    def delta_from(self, snap: Dict[str, float]) -> Dict[str, float]:
        return {k: getattr(self, k) - snap[k] for k in snap}

    @classmethod
    def merge_many(
        cls,
        metrics_list: Sequence["AdaptiveMetrics"],
        pattern_track_cap: Optional[int] = None,
    ) -> "AdaptiveMetrics":
        """Merge progress metrics from workers assigned to one service."""
        cap = pattern_track_cap
        if cap is None:
            cap = metrics_list[0]._pattern_cap if metrics_list else 4096
        merged = cls(pattern_track_cap=cap)
        if not metrics_list:
            return merged

        any_saturated = any(m._patterns_saturated for m in metrics_list)
        union: Set[int] = set()
        for m in metrics_list:
            union |= m._pattern_hashes
        pattern_sum = sum(m.new_response_patterns for m in metrics_list)

        merged.evaluated_mutants = sum(m.evaluated_mutants for m in metrics_list)
        merged.target_hits = sum(m.target_hits for m in metrics_list)
        merged.breadth_sum_on_target_hits = sum(
            m.breadth_sum_on_target_hits for m in metrics_list)
        merged.valuable_hits = sum(m.valuable_hits for m in metrics_list)
        merged.high_value_candidates = sum(
            m.high_value_candidates for m in metrics_list)
        merged.consecutive_no_progress_batches = max(
            m.consecutive_no_progress_batches for m in metrics_list)

        if not any_saturated and len(union) <= cap:

            merged.new_response_patterns = len(union)
            merged._pattern_hashes = set(union)
        else:
            
            merged.new_response_patterns = pattern_sum
            merged._pattern_hashes = set(sorted(union)[:cap])
            merged._patterns_saturated = True
        return merged

    def to_dict(self) -> Dict[str, float]:
        out = self.snapshot()
        out.update({
            "high_value_candidates": self.high_value_candidates,
            "consecutive_no_progress_batches": self.consecutive_no_progress_batches,
            "reach_rate": self.reach_rate,
            "breadth_mean": self.breadth_mean,
            "valuable_rate": self.valuable_rate,
            "patterns_saturated": self._patterns_saturated,
        })
        return out

    def summary(self) -> str:
        return (
            f"evaluated={self.evaluated_mutants} reach={self.reach_rate:.3f} "
            f"breadth_mean={self.breadth_mean:.3f} valuable={self.valuable_rate:.3f} "
            f"new_patterns={self.new_response_patterns} "
            f"hvc={self.high_value_candidates} "
            f"no_prog_batch={self.consecutive_no_progress_batches}"
        )

def validate_adaptive_v1_config(
    *,
    reach_low: float,
    reach_high: float,
    breadth_progress_min: float,
    no_progress_patience: int,
    fuzz_min: int,
    fuzz_max: int,
    min_explore: int,
    increase_rate: float,
    decrease_rate: float,
    min_samples: int,
) -> None:
    """Validate adaptive policy boundaries without silently correcting settings."""
    if not 0.0 <= reach_low <= reach_high <= 1.0:
        raise ValueError(
            f"require 0 <= reach_low <= reach_high <= 1, got "
            f"{reach_low}, {reach_high}")
    if breadth_progress_min < 0.0:
        raise ValueError(f"breadth_progress_min must be >= 0, got {breadth_progress_min}")
    if int(no_progress_patience) < 1:
        raise ValueError(f"no_progress_patience must be >= 1, got {no_progress_patience}")
    if int(fuzz_min) < 0 or int(fuzz_max) < int(fuzz_min):
        raise ValueError(f"require 0 <= fuzz_min <= fuzz_max, got {fuzz_min}, {fuzz_max}")
    if not 0 <= int(min_explore) <= int(fuzz_max):
        raise ValueError(
            f"min_explore must be in [0, fuzz_max={fuzz_max}], got {min_explore}")
    if not 0.0 < increase_rate <= 1.0 or not 0.0 < decrease_rate <= 1.0:
        raise ValueError(
            f"rates must be in (0, 1], got increase={increase_rate}, "
            f"decrease={decrease_rate}")
    if int(min_samples) < 1:
        raise ValueError(f"min_samples must be >= 1, got {min_samples}")

def adjust_resource_multiobjective(
    current: int,
    metrics: AdaptiveMetrics,
    *,
    window_new_patterns: int = 0,
    window_valuable_hits: int = 0,
    prev_breadth_mean: Optional[float] = None,
    reach_low: float,
    reach_high: float,
    breadth_progress_min: float,
    no_progress_patience: int,
    fuzz_min: int,
    fuzz_max: int,
    increase_rate: float,
    decrease_rate: float,
    min_explore: int,
    min_samples: int,
    strict_target: bool = False,
    high_weight: bool = False,
) -> Tuple[int, str]:
    """Adjust the service budget conservatively from reach, breadth and stagnation."""
    validate_adaptive_v1_config(
        reach_low=reach_low, reach_high=reach_high,
        breadth_progress_min=breadth_progress_min,
        no_progress_patience=no_progress_patience,
        fuzz_min=fuzz_min, fuzz_max=fuzz_max, min_explore=min_explore,
        increase_rate=increase_rate, decrease_rate=decrease_rate,
        min_samples=min_samples,
    )
    floor = max(fuzz_min, min_explore) if (strict_target or high_weight) else fuzz_min
    cur = int(min(max(int(current), floor), fuzz_max))

    if metrics.evaluated_mutants < min_samples:
        return cur, POLICY_WARMUP

    reach = metrics.reach_rate
    pattern_progress = window_new_patterns > 0
    valuable_progress = window_valuable_hits > 0
    if prev_breadth_mean is None:
        breadth_improved = True
    else:
        breadth_improved = (metrics.breadth_mean - prev_breadth_mean) >= breadth_progress_min

    def _decrease(value: int) -> int:
        headroom = value - floor
        return max(floor, int(value - decrease_rate * headroom))

    def _increase(value: int) -> int:
        headroom = fuzz_max - value
        return min(fuzz_max, int(value + increase_rate * headroom))

    if (reach <= _REACH_ZERO_EPS
            and metrics.consecutive_no_progress_batches >= no_progress_patience
            and not pattern_progress):
        return _decrease(cur), POLICY_STALLED_FLOOR
    if reach <= reach_low:
        if pattern_progress:
            return _increase(cur), POLICY_EXPLORE_LOW_REACH
        return cur, POLICY_LOW_REACH_HOLD
    if reach >= reach_high:

        if breadth_improved or pattern_progress:
            return cur, POLICY_MAINTAIN_PROGRESS
        return _decrease(cur), POLICY_SATURATED_REDUCE
    return cur, POLICY_MAINTAIN_MID

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

@dataclass
class RoundStopMetrics:
    """Snapshot of campaign progress used by the early-stop policy."""

    iteration: int
    new_clusters: int
    new_response_patterns: int
    breadth_mean: float
    breadth_improvement: float
    reach_rate: float
    reach_improvement: float
    stalled: bool
    stalled_reasons: List[str] = field(default_factory=list)
    consecutive_stalled_rounds: int = 0
    should_stop: bool = False
    stop_reason: str = ""

class EarlyStopTracker:
    """Independent conservative early stopping for each transport campaign."""

    def __init__(
        self,
        *,
        enabled: bool,
        patience: int,
        min_rounds: int,
        min_new_clusters: int,
        min_new_patterns: int,
        min_breadth_improvement: float,
        min_reach_improvement: float,
    ):
        if int(patience) < 1:
            raise ValueError(f"patience must be >= 1, got {patience}")
        if int(min_rounds) < 1:
            raise ValueError(f"min_rounds must be >= 1, got {min_rounds}")
        for name, v in (("min_new_clusters", min_new_clusters),
                        ("min_new_patterns", min_new_patterns),
                        ("min_breadth_improvement", min_breadth_improvement),
                        ("min_reach_improvement", min_reach_improvement)):
            if v < 0:
                raise ValueError(f"{name} must be >= 0, got {v}")
        self.enabled = bool(enabled)
        self.patience = int(patience)
        self.min_rounds = int(min_rounds)
        self.min_new_clusters = int(min_new_clusters)
        self.min_new_patterns = int(min_new_patterns)
        self.min_breadth_improvement = float(min_breadth_improvement)
        self.min_reach_improvement = float(min_reach_improvement)

        self.rounds_completed = 0
        self.consecutive_stalled_rounds = 0
        self._prev_breadth_mean: Optional[float] = None
        self._prev_reach_rate: Optional[float] = None
        self.round_metrics: List[RoundStopMetrics] = []

    def observe_round(
        self,
        *,
        iteration: int,
        new_clusters: int,
        new_response_patterns: int,
        breadth_mean: float,
        reach_rate: float,
    ) -> RoundStopMetrics:
        self.rounds_completed += 1
        if self._prev_breadth_mean is None:
            breadth_improvement = float("inf")
        else:
            breadth_improvement = breadth_mean - self._prev_breadth_mean
        if self._prev_reach_rate is None:
            reach_improvement = float("inf")
        else:
            reach_improvement = reach_rate - self._prev_reach_rate

        reasons: List[str] = []
        if new_clusters < self.min_new_clusters:
            reasons.append("no_new_clusters")
        if new_response_patterns < self.min_new_patterns:
            reasons.append("no_new_patterns")
        if breadth_improvement < self.min_breadth_improvement:
            reasons.append("breadth_improvement_below_threshold")
        if reach_improvement < self.min_reach_improvement:
            reasons.append("reach_improvement_below_threshold")

        stalled = (len(reasons) == 4) and self.rounds_completed > 1
        if stalled:
            self.consecutive_stalled_rounds += 1
        else:
            self.consecutive_stalled_rounds = 0

        should_stop = (
            self.enabled
            and self.rounds_completed >= self.min_rounds
            and self.consecutive_stalled_rounds >= self.patience
        )
        stop_reason = ""
        if should_stop:
            stop_reason = (
                f"early_stop after {self.rounds_completed} rounds: "
                f"{self.consecutive_stalled_rounds} consecutive stalled rounds "
                f"(patience={self.patience}, min_rounds={self.min_rounds}); "
                f"stalled_reasons={reasons}"
            )

        m = RoundStopMetrics(
            iteration=iteration,
            new_clusters=new_clusters,
            new_response_patterns=new_response_patterns,
            breadth_mean=breadth_mean,
            breadth_improvement=breadth_improvement,
            reach_rate=reach_rate,
            reach_improvement=reach_improvement,
            stalled=stalled,
            stalled_reasons=reasons,
            consecutive_stalled_rounds=self.consecutive_stalled_rounds,
            should_stop=should_stop,
            stop_reason=stop_reason,
        )
        self.round_metrics.append(m)
        self._prev_breadth_mean = breadth_mean
        self._prev_reach_rate = reach_rate
        return m

class AdaptiveController:
    """
    Manages adaptive mutation resource allocation across services.

    Each service has an independent mutation-budget state.  Budgets are adjusted
    from the configured objective feedback and inherited between iterations.

    The internal ``'boofuzz'`` dictionary key is retained solely for compatibility
    with existing checkpoints; user-facing comments and logs use "mutation budget".
    """

    def __init__(
        self,
        services: List[str],
        # Mutation-budget parameters
        fuzz_initial: int = 2000,
        fuzz_min: int = 100,
        fuzz_max: int = 5000,
        fuzz_increase_rate: float = 0.3,
        fuzz_decrease_rate: float = 0.3,
        # Multi-objective adaptive mode.  The public value remains
        # ``multiobjective_v1`` for checkpoint/config compatibility and is
        # also reused by the current background-adjusted objective.
        mode: str = ADAPTIVE_MODE_LEGACY,
        reach_low: float = 0.05,
        reach_high: float = 0.5,
        breadth_progress_min: float = 0.005,
        no_progress_patience: int = 3,
        strict_reach_threshold: float = 0.05,
        high_weight_threshold: float = 0.05,
        min_explore: int = 1000,
        min_samples: int = 100,
        pattern_track_cap: int = 4096,
        cluster_weights: Optional[Dict[str, float]] = None,
    ):
        if mode not in VALID_ADAPTIVE_MODES:
            raise ValueError(
                f"unknown adaptive mode {mode!r}; expected one of "
                f"{VALID_ADAPTIVE_MODES}")
        self.mode = mode
        self.fuzz_min = fuzz_min
        self.fuzz_max = fuzz_max
        self.fuzz_increase_rate = fuzz_increase_rate
        self.fuzz_decrease_rate = fuzz_decrease_rate

        # Multi-objective parameters (also stored in legacy mode for a stable
        # checkpoint/summary schema).
        self.reach_low = float(reach_low)
        self.reach_high = float(reach_high)
        self.breadth_progress_min = float(breadth_progress_min)
        self.no_progress_patience = int(no_progress_patience)
        self.strict_reach_threshold = float(strict_reach_threshold)
        self.high_weight_threshold = float(high_weight_threshold)
        self.min_explore = int(min_explore)
        self.min_samples = int(min_samples)
        self.pattern_track_cap = int(pattern_track_cap)
        if mode == ADAPTIVE_MODE_MULTIOBJECTIVE:
            validate_adaptive_v1_config(
                reach_low=self.reach_low, reach_high=self.reach_high,
                breadth_progress_min=self.breadth_progress_min,
                no_progress_patience=self.no_progress_patience,
                fuzz_min=fuzz_min, fuzz_max=fuzz_max, min_explore=self.min_explore,
                increase_rate=fuzz_increase_rate,
                decrease_rate=fuzz_decrease_rate,
                min_samples=self.min_samples,
            )
        self.cluster_weights: Dict[str, float] = dict(cluster_weights or {})

        # Checkpoint-compatible state schema: {service: {'boofuzz': int}}.
        self.states: Dict[str, Dict[str, int]] = {}
        for svc in services:
            self.states[svc] = {
                'boofuzz': fuzz_initial,
            }

        # Per-service cumulative metrics / no-progress rounds / latest policy.
        self.metrics: Dict[str, AdaptiveMetrics] = {}
        self.no_progress_iterations: Dict[str, int] = {}
        self.policy_states: Dict[str, str] = {}

        logger.info(
            f"AdaptiveController initialized: {len(services)} services, "
            f"mode={mode}, mutation_budget=[{fuzz_min},{fuzz_max}] "
            f"initial={fuzz_initial}"
        )

    def is_v1(self) -> bool:
        return self.mode == ADAPTIVE_MODE_MULTIOBJECTIVE

    def get_fuzz_resource(self, service: str) -> int:
        """Get the current mutation budget for a service."""
        return self.states.get(service, {}).get('boofuzz', self.fuzz_min)

    def update_from_worker(
        self, service: str, fuzz_resource: int,
    ):
        """Update resource state from worker result (inter-round inheritance)."""
        if service not in self.states:
            self.states[service] = {}
        old_f = self.states[service].get('boofuzz', '?')
        self.states[service]['boofuzz'] = fuzz_resource
        logger.info(
            f"Resource inherited: {service} -> "
            f"mutation_budget {old_f}->{fuzz_resource}"
        )

    def update_from_batches(
        self,
        service: str,
        batch_results: List[Tuple[int, int]],
    ):
        """
        Reconcile resource states from multiple batches of the same service.
        Uses weighted average (weight = seed count per batch).

        Args:
            service: Service name
            batch_results: List of (fuzz_resource, seed_count)
        """
        if not batch_results:
            return

        total_seeds = sum(count for _, count in batch_results)
        if total_seeds == 0:
            return

        fuzz_avg = int(sum(f * c for f, c in batch_results) / total_seeds)

        if service not in self.states:
            self.states[service] = {}
        old_f = self.states[service].get('boofuzz', '?')
        self.states[service]['boofuzz'] = fuzz_avg

        logger.info(
            f"Resource reconciled from {len(batch_results)} batches: {service} -> "
            f"mutation_budget {old_f}->{fuzz_avg}"
        )

    # ------------------------------------------------------------------
    
    # ------------------------------------------------------------------
    def observe_service_round(
        self,
        service: str,
        round_metrics: AdaptiveMetrics,
        adjust: bool = True,
    ) -> Optional[Dict]:
        """Accumulate all workers' progress for this service and round."""
        prev = self.metrics.get(service)
        merged = AdaptiveMetrics.merge_many(
            [prev, round_metrics], pattern_track_cap=self.pattern_track_cap,
        ) if prev is not None else round_metrics
        self.metrics[service] = merged

        delta = (
            merged.delta_from(prev.snapshot()) if prev is not None
            else merged.snapshot()
        )
        progressed = (delta["new_response_patterns"] > 0
                      or delta["valuable_hits"] > 0)
        if progressed:
            self.no_progress_iterations[service] = 0
        else:
            self.no_progress_iterations[service] = (
                self.no_progress_iterations.get(service, 0) + 1)

        if not self.is_v1():
            return None

        strict_target = (
            merged.evaluated_mutants >= self.min_samples
            and merged.reach_rate <= self.strict_reach_threshold
        )
        weight = self.cluster_weights.get(service, 0.0)
        high_weight = bool(weight) and weight >= self.high_weight_threshold
        prev_breadth = (
            prev.breadth_mean if (prev is not None and prev.target_hits > 0)
            else None
        )
        current = self.states.get(service, {}).get('boofuzz', self.fuzz_min)
        new_res, state = adjust_resource_multiobjective(
            current, merged,
            window_new_patterns=delta["new_response_patterns"],
            window_valuable_hits=delta["valuable_hits"],
            prev_breadth_mean=prev_breadth,
            reach_low=self.reach_low,
            reach_high=self.reach_high,
            breadth_progress_min=self.breadth_progress_min,
            no_progress_patience=self.no_progress_patience,
            fuzz_min=self.fuzz_min,
            fuzz_max=self.fuzz_max,
            increase_rate=self.fuzz_increase_rate,
            decrease_rate=self.fuzz_decrease_rate,
            min_explore=self.min_explore,
            min_samples=self.min_samples,
            strict_target=strict_target,
            high_weight=high_weight,
        )
        if service not in self.states:
            self.states[service] = {}
        old = self.states[service].get('boofuzz', '?')
        if adjust:
            self.states[service]['boofuzz'] = new_res
        else:
            new_res = current   
        self.policy_states[service] = state
        logger.info(
            f"[ADAPTIVE] {service} round summary: "
            f"round_delta{{evaluated={delta['evaluated_mutants']}, "
            f"new_patterns={delta['new_response_patterns']}, "
            f"valuable={delta['valuable_hits']}}}, "
            f"policy={state}, mutation_budget {old}->{new_res} "
            f"(strict={strict_target}, high_weight={high_weight}, "
            f"adjust={adjust})"
        )
        return {
            "service": service,
            "round_evaluated_mutants": delta["evaluated_mutants"],
            "round_target_hits": delta["target_hits"],
            "round_breadth_sum": delta["breadth_sum_on_target_hits"],
            "round_valuable_hits": delta["valuable_hits"],
            "round_new_response_patterns": delta["new_response_patterns"],
            "new_resource": new_res,
            "policy_state": state,
            "adjusted": bool(adjust),
        }

    def get_metrics_summary(self) -> Dict[str, Dict]:
        """Return each service's metrics, no-progress count, and policy state."""
        out: Dict[str, Dict] = {}
        for svc, m in self.metrics.items():
            entry = m.to_dict()
            entry["no_progress_iterations"] = self.no_progress_iterations.get(svc, 0)
            entry["policy_state"] = self.policy_states.get(svc, "")
            out[svc] = entry
        return out

    def get_state_summary(self) -> Dict[str, Dict[str, int]]:
        """Return a snapshot of all resource states."""
        return {svc: dict(state) for svc, state in self.states.items()}

    @classmethod
    def from_config(
        cls,
        services: List[str],
        cluster_weights: Optional[Dict[str, float]] = None,
    ) -> 'AdaptiveController':
        """Create controller from config module settings."""
        import config
        return cls(
            services=services,
            fuzz_initial=config.ADAPTIVE_FUZZ_INITIAL,
            fuzz_min=config.ADAPTIVE_FUZZ_MIN,
            fuzz_max=config.ADAPTIVE_FUZZ_MAX,
            fuzz_increase_rate=config.ADAPTIVE_FUZZ_INCREASE_RATE,
            fuzz_decrease_rate=config.ADAPTIVE_FUZZ_DECREASE_RATE,
            mode=getattr(config, 'ADAPTIVE_OBJECTIVE_MODE', ADAPTIVE_MODE_LEGACY),
            reach_low=getattr(config, 'ADAPTIVE_REACH_LOW_THRESHOLD', 0.05),
            reach_high=getattr(config, 'ADAPTIVE_REACH_HIGH_THRESHOLD', 0.5),
            breadth_progress_min=getattr(config, 'ADAPTIVE_BREADTH_PROGRESS_MIN', 0.005),
            no_progress_patience=getattr(config, 'ADAPTIVE_NO_PROGRESS_PATIENCE', 3),
            strict_reach_threshold=getattr(config, 'ADAPTIVE_STRICT_REACH_THRESHOLD', 0.05),
            high_weight_threshold=getattr(config, 'ADAPTIVE_HIGH_WEIGHT_THRESHOLD', 0.05),
            min_explore=getattr(config, 'ADAPTIVE_MIN_EXPLORE_BUDGET', 1000),
            min_samples=getattr(config, 'ADAPTIVE_POLICY_MIN_SAMPLES', 100),
            pattern_track_cap=getattr(config, 'ADAPTIVE_PATTERN_TRACK_CAP', 4096),
            cluster_weights=cluster_weights,
        )
