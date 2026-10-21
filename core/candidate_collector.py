"""Bounded worker-local candidate collection. Formal multi-probes, exploratory multi-probes and target reachability use separate channels. Diagnostic failures contribute statistics only. Semantic top-K retention uses semantic keys and preserves seed ancestry."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set

from core.clustering import (
    cluster_pattern_digest_from_tuples,
    target_pattern_digest_from_responses,
)
from core.objectives import PacketOutcome, packet_hash_of
from core.service_tester import ServiceResponse

CANDIDATE_MULTI_PROBE = "multi_probe"
CANDIDATE_EXPLORATORY_MULTI_PROBE = "exploratory_multi_probe"
CANDIDATE_TARGET_REACHABILITY = "target_reachability"
CANDIDATE_DIAGNOSTIC_ONLY = "diagnostic_only"

VALID_CANDIDATE_TYPES = (
    CANDIDATE_MULTI_PROBE,
    CANDIDATE_EXPLORATORY_MULTI_PROBE,
    CANDIDATE_TARGET_REACHABILITY,
    CANDIDATE_DIAGNOSTIC_ONLY,
)

QUALIFICATION_STRICT = "strict"
QUALIFICATION_EXPLORATORY = "exploratory"
QUALIFICATION_REACHABILITY = "reachability"

SEED_REASON_MULTI_PROBE = "multi_probe_seed"
SEED_REASON_HIGH_BREADTH = "high_breadth_seed"
SEED_REASON_STRICT_TARGET = "strict_target_seed"
SEED_REASON_INITIAL = "initial_seed"
VALID_SEED_REASONS = (
    SEED_REASON_MULTI_PROBE,
    SEED_REASON_HIGH_BREADTH,
    SEED_REASON_STRICT_TARGET,
)

def breadth_rank_key(entry: dict) -> tuple:
    """Order seeds by descending gated breadth, shorter packet length and stable packet hash."""
    packet = entry.get('packet') or b''
    breadth = entry.get('target_gated_breadth') or 0.0
    return (-float(breadth), len(packet), packet_hash_of(packet))

def _attach_lineage(
    d: dict,
    parent_seed_id: Optional[str],
    parent_packet_hash: Optional[str],
) -> None:
    """Attach the actual parent seed ancestry before local top-K replacement."""
    if parent_seed_id:
        d['parent_seed_id'] = parent_seed_id
    if parent_packet_hash:
        d['parent_packet_hash'] = parent_packet_hash

@dataclass
class CollectStats:
    """Compact candidate-channel counters; diagnostic failures are counted but not retained."""

    classified: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    stored_multi_probe: int = 0
    stored_exploratory: int = 0
    stored_target_reachability: int = 0
    dropped_multi_probe_pattern_cap: int = 0
    dropped_exploratory_evicted: int = 0
    dropped_tr_pattern_cap: int = 0
    dropped_tr_service_cap: int = 0
    
    dropped_high_breadth_evicted: int = 0
    new_seeds: int = 0
    
    seeds_by_reason: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def summary(self) -> str:
        reasons = " ".join(
            f"{k}={v}" for k, v in sorted(self.seeds_by_reason.items())
        )
        return (
            f"multi_probe={self.stored_multi_probe} "
            f"exploratory={self.stored_exploratory} "
            f"target_reachability={self.stored_target_reachability} "
            f"diagnostic_only={self.classified[CANDIDATE_DIAGNOSTIC_ONLY]} "
            f"seeds={self.new_seeds}"
            + (f" [{reasons}]" if reasons else "")
        )

class CandidateCollector:
    """Bounded candidate channels for one worker and mutation target."""

    def __init__(
        self,
        mutation_target: str,
        fingerprint_threshold: int,
        seed_threshold: int,
        max_per_pattern: int,
        collect_target_reachability: bool = False,
        max_tr_per_pattern: int = 2,
        max_tr_per_service: int = 100,
        require_target_trigger: bool = True,
        
        seed_high_breadth_enabled: bool = False,
        seed_high_breadth_threshold: float = 0.0,
        max_high_breadth_seeds: int = 2,
        candidate_sink: Optional[Callable[[dict], bool]] = None,
        transport: str = "",
        semantic_top_k: int = 0,

        exploratory_top_k: int = 0,
    ):
        if seed_high_breadth_threshold < 0.0:
            raise ValueError(
                f"seed_high_breadth_threshold must be >= 0, "
                f"got {seed_high_breadth_threshold}")
        self.mutation_target = mutation_target
        self.fingerprint_threshold = int(fingerprint_threshold)
        self.seed_threshold = int(seed_threshold)
        self.max_per_pattern = int(max_per_pattern)
        self.collect_target_reachability = bool(collect_target_reachability)
        self.max_tr_per_pattern = int(max_tr_per_pattern)
        self.max_tr_per_service = int(max_tr_per_service)
        self.require_target_trigger = bool(require_target_trigger)
        self.seed_high_breadth_enabled = bool(seed_high_breadth_enabled)
        self.seed_high_breadth_threshold = float(seed_high_breadth_threshold)
        self.max_high_breadth_seeds = int(max_high_breadth_seeds)
        self.candidate_sink = candidate_sink
        self.transport = transport
        self.semantic_top_k = max(0, int(semantic_top_k))
        self.exploratory_top_k = max(0, int(exploratory_top_k))

        self.stats = CollectStats()
        
        self._mp_pattern_counts: Dict[str, int] = defaultdict(int)
        
        self._tr_pattern_counts: Dict[str, int] = defaultdict(int)
        self._tr_service_count = 0

        self.last_seed_reason: Optional[str] = None

        self.last_stored: bool = False
        
        self._hb_top: List[dict] = []
        self._semantic_top: Dict[tuple, List[dict]] = defaultdict(list)
        
        self._exploratory_top: Dict[tuple, List[dict]] = defaultdict(list)

    # ------------------------------------------------------------------
    
    # ------------------------------------------------------------------
    def classify(
        self,
        outcome: PacketOutcome,
        qualifies_multi_probe: Optional[bool] = None,
        reward_breakdown=None,
    ) -> str:
        """Determine the candidate channel from target and breadth qualification."""
        is_multi_probe = (
            bool(qualifies_multi_probe)
            if qualifies_multi_probe is not None
            else len(outcome.triggered_clusters) >= self.fingerprint_threshold
        )
        if qualifies_multi_probe is not None and reward_breakdown is not None:
            
            if outcome.target_triggered and is_multi_probe:
                return CANDIDATE_MULTI_PROBE
            if outcome.target_triggered and getattr(
                    reward_breakdown, 'selective_extra_clusters', None):
                return CANDIDATE_EXPLORATORY_MULTI_PROBE
            if outcome.target_triggered:
                return CANDIDATE_TARGET_REACHABILITY
            return CANDIDATE_DIAGNOSTIC_ONLY
        if outcome.target_triggered and is_multi_probe:
            return CANDIDATE_MULTI_PROBE
        if (not self.require_target_trigger) and is_multi_probe:
            return CANDIDATE_MULTI_PROBE  
        if outcome.target_triggered:
            return CANDIDATE_TARGET_REACHABILITY
        return CANDIDATE_DIAGNOSTIC_ONLY

    # ------------------------------------------------------------------
    
    # ------------------------------------------------------------------
    def collect(
        self,
        packet: bytes,
        responses: Sequence[ServiceResponse],
        outcome: PacketOutcome,
        iteration: int,
        candidates_data: List[dict],
        new_seeds_data: List[dict],
        multi_probe_packets: Optional[List[dict]] = None,
        collect_new_seeds: bool = True,
        target_gated_breadth: Optional[float] = None,
        parent_seed_id: Optional[str] = None,
        parent_packet_hash: Optional[str] = None,
        qualifies_multi_probe: Optional[bool] = None,
        reward_breakdown=None,
    ) -> str:
        """Record packet responses and seed eligibility; return the candidate type."""
        ctype = self.classify(outcome, qualifies_multi_probe, reward_breakdown)
        self.last_stored = False
        self.stats.classified[ctype] += 1
        qualification_status = self._qualification_status(
            ctype, qualifies_multi_probe, reward_breakdown)

        triggered: Set[str] = set(outcome.triggered_clusters)
        verified_for_seed: Set[str] = triggered
        if reward_breakdown is not None and qualifies_multi_probe is not None:
            # Seeds only claim services observed in the post-send phase.
            # This is a temporal attribution boundary, not proof that the
            # payload semantically caused the bytes.  A passive target is kept
            # as provenance/gate, not mislabeled as post-send verified.
            verified_for_seed = set(outcome.payload_triggered_clusters)
        is_multi_probe = (
            bool(qualifies_multi_probe)
            if qualifies_multi_probe is not None
            else len(triggered) >= self.fingerprint_threshold
        )
        
        save_eligible = (not self.require_target_trigger) or outcome.target_triggered

        valid_responses = [r for r in responses if r.response_bytes]

        if ctype == CANDIDATE_MULTI_PROBE:
            responses_tuples = [
                (r.service_name, r.response_bytes, r.latency_ms)
                for r in valid_responses
            ]
            pkey = cluster_pattern_digest_from_tuples(responses_tuples)
            # Semantic top-K is the authoritative compression key.  The old
            # exact-response pattern cap must not silently reduce top-5 to the
            # legacy per-pattern limit (usually 2).
            if (self.semantic_top_k
                    or self._mp_pattern_counts.get(pkey, 0) < self.max_per_pattern):
                mp_cand = {
                    'packet': packet,
                    'responses': responses_tuples,
                    'mutation_target': self.mutation_target,
                    'iteration': iteration,
                    'triggered_clusters': triggered,
                    'candidate_type': CANDIDATE_MULTI_PROBE,
                }
                self._attach_qualification_metadata(
                    mp_cand, outcome, reward_breakdown, valid_responses)
                if qualification_status:
                    mp_cand['qualification_status'] = qualification_status
                _attach_lineage(mp_cand, parent_seed_id, parent_packet_hash)
                if self._store_candidate(mp_cand, candidates_data):
                    if not self.semantic_top_k:
                        self._mp_pattern_counts[pkey] = self._mp_pattern_counts[pkey] + 1
                    self.stats.stored_multi_probe += 1
            else:
                self.stats.dropped_multi_probe_pattern_cap += 1

        elif ctype == CANDIDATE_EXPLORATORY_MULTI_PROBE:

            expl_cand = {
                'packet': packet,
                'responses': [
                    (r.service_name, r.response_bytes, r.latency_ms)
                    for r in valid_responses
                ],
                'mutation_target': self.mutation_target,
                'iteration': iteration,
                'triggered_clusters': triggered,
                'candidate_type': CANDIDATE_EXPLORATORY_MULTI_PROBE,
            }
            self._attach_qualification_metadata(
                expl_cand, outcome, reward_breakdown, valid_responses)
            if qualification_status:
                expl_cand['qualification_status'] = qualification_status
            _attach_lineage(expl_cand, parent_seed_id, parent_packet_hash)
            self._retain_exploratory_candidate(expl_cand)

        elif (ctype == CANDIDATE_TARGET_REACHABILITY
              and self.collect_target_reachability):
            tr_key = self._target_response_pattern(valid_responses)
            if self._tr_service_count >= self.max_tr_per_service:
                self.stats.dropped_tr_service_cap += 1
            elif self._tr_pattern_counts.get(tr_key, 0) >= self.max_tr_per_pattern:
                self.stats.dropped_tr_pattern_cap += 1
            else:
                tr_cand = {
                    'packet': packet,
                    'responses': [
                        (r.service_name, r.response_bytes, r.latency_ms)
                        for r in valid_responses
                    ],
                    'mutation_target': self.mutation_target,
                    'iteration': iteration,
                    'triggered_clusters': triggered,
                    'candidate_type': CANDIDATE_TARGET_REACHABILITY,
                }
                self._attach_qualification_metadata(
                    tr_cand, outcome, reward_breakdown, valid_responses)
                if qualification_status:
                    tr_cand['qualification_status'] = qualification_status
                _attach_lineage(tr_cand, parent_seed_id, parent_packet_hash)
                if self._store_candidate(tr_cand, candidates_data):
                    self._tr_pattern_counts[tr_key] = self._tr_pattern_counts[tr_key] + 1
                    self._tr_service_count += 1
                    self.stats.stored_target_reachability += 1

        seed_reason: Optional[str] = None
        seed_multi_eligible = (
            is_multi_probe
            if qualifies_multi_probe is not None
            else len(triggered) >= self.seed_threshold
        )
        if save_eligible and collect_new_seeds and seed_multi_eligible:
            seed_reason = SEED_REASON_MULTI_PROBE
        elif (
            collect_new_seeds
            and self.seed_high_breadth_enabled
            and target_gated_breadth is not None
            and outcome.target_triggered
            and not seed_multi_eligible
            and target_gated_breadth >= self.seed_high_breadth_threshold
        ):
            seed_reason = SEED_REASON_HIGH_BREADTH

        if seed_reason == SEED_REASON_MULTI_PROBE:
            seed_dict = {
                'packet': packet,
                'verified_clusters': verified_for_seed,
                'protocol_name': self.mutation_target,
                'seed_reason': seed_reason,
            }
            _attach_lineage(seed_dict, parent_seed_id, parent_packet_hash)
            new_seeds_data.append(seed_dict)
            self.stats.new_seeds += 1
            self.stats.seeds_by_reason[seed_reason] += 1

        elif seed_reason == SEED_REASON_HIGH_BREADTH:
            hb_entry = {
                'packet': packet,
                'verified_clusters': verified_for_seed,
                'protocol_name': self.mutation_target,
                'seed_reason': seed_reason,
                
                'target_gated_breadth': (
                    None if target_gated_breadth is None
                    else float(target_gated_breadth)),
            }
            _attach_lineage(hb_entry, parent_seed_id, parent_packet_hash)

            self._hb_top.append(hb_entry)
            self._hb_top.sort(key=breadth_rank_key)
            if len(self._hb_top) > self.max_high_breadth_seeds:
                evicted = self._hb_top.pop()
                if evicted is not hb_entry:
                    self.stats.dropped_high_breadth_evicted += 1

        self.last_seed_reason = seed_reason

        if multi_probe_packets is not None and is_multi_probe:
            multi_probe_packets.append({'triggered_clusters': triggered})

        return ctype

    @staticmethod
    def _attach_qualification_metadata(
        candidate: dict,
        outcome: PacketOutcome,
        reward,
        responses: Sequence[ServiceResponse],
    ) -> None:
        """Attach qualification facts without changing legacy candidate semantics."""
        if reward is None:
            return
        candidate.update({
            'observed_clusters': set(outcome.observed_clusters),
            'passive_clusters': set(outcome.passive_clusters),
            'payload_triggered_clusters': set(outcome.payload_triggered_clusters),
            'selective_payload_clusters': set(reward.selective_extra_clusters),
            'raw_payload_breadth': float(reward.raw_payload_breadth),
            'background_adjusted_breadth': float(
                reward.background_adjusted_breadth),
            'null_threshold': float(reward.null_threshold),
            'qualifies_multi_probe': bool(reward.qualifies_multi_probe),
            'passive_target': bool(reward.passive_target),
            'background_artifact_hash': reward.background_artifact_hash,
            'response_observations': [
                {
                    'service': r.service_name,
                    'response_bytes': r.response_bytes,
                    'banner_bytes': getattr(r, 'banner_bytes', b''),
                    'response_phase': getattr(r, 'response_phase', 'post_payload'),
                    'latency_ms': r.latency_ms,
                    'banner_latency_ms': getattr(r, 'banner_latency_ms', 0.0),
                    'payload_latency_ms': getattr(r, 'payload_latency_ms', 0.0),
                }
                for r in responses
            ],
        })

    def emit_high_breadth_seeds(self, new_seeds_data: List[dict]) -> int:
        """Emit the locally retained high-breadth seed candidates."""
        for entry in self._hb_top:
            new_seeds_data.append(entry)
            self.stats.new_seeds += 1
            self.stats.seeds_by_reason[SEED_REASON_HIGH_BREADTH] += 1
        emitted = len(self._hb_top)
        self._hb_top = []
        return emitted

    def emit_semantic_candidates(self, candidates_data: List[dict]) -> int:
        """Flush semantic top-K buffers through the configured sink."""
        emitted = 0
        for key in sorted(self._semantic_top, key=repr):
            for candidate in self._semantic_top[key]:
                if self._persist_candidate(candidate, candidates_data):
                    emitted += 1
        self._semantic_top.clear()
        return emitted

    def emit_exploratory_candidates(self, candidates_data: List[dict]) -> int:
        """Flush retained exploratory top-K candidates through the configured sink."""
        seen_hashes: Set[str] = set()
        unique: List[dict] = []
        for key in sorted(self._exploratory_top, key=repr):
            for candidate in self._exploratory_top[key]:
                digest = packet_hash_of(candidate.get('packet') or b'')
                if digest in seen_hashes:
                    continue
                seen_hashes.add(digest)
                unique.append(candidate)
        unique.sort(key=self._semantic_rank_key)
        self._exploratory_top.clear()
        emitted = 0
        for candidate in unique:
            if self._persist_candidate(candidate, candidates_data):
                emitted += 1
        return emitted

    def _retain_exploratory_candidate(self, candidate: dict) -> bool:
        """Retain a candidate in bounded per-extra-service top-K buckets."""
        extras = sorted(set(candidate.get('selective_payload_clusters') or ()))
        if self.exploratory_top_k <= 0 or not extras:
            
            self.stats.dropped_exploratory_evicted += 1
            self.last_stored = False
            return False
        retained_any = False
        for extra in extras:
            bucket = self._exploratory_top[
                (self.transport, self.mutation_target, extra)]
            bucket.append(candidate)
            bucket.sort(key=self._semantic_rank_key)
            evicted = bucket[self.exploratory_top_k:]
            del bucket[self.exploratory_top_k:]
            if any(item is candidate for item in bucket):
                retained_any = True
            for item in evicted:
                if item is candidate:
                    continue
                if not self._exploratory_is_retained(item):
                    
                    self.stats.stored_exploratory = max(
                        0, self.stats.stored_exploratory - 1)
                    self.stats.dropped_exploratory_evicted += 1
        if retained_any:
            self.stats.stored_exploratory += 1
        else:
            self.stats.dropped_exploratory_evicted += 1
        self.last_stored = retained_any
        return retained_any

    def _exploratory_is_retained(self, candidate: dict) -> bool:
        """Check object identity across the exploratory retention buckets."""
        return any(
            item is candidate
            for bucket in self._exploratory_top.values()
            for item in bucket
        )

    @staticmethod
    def _qualification_status(
        ctype: str,
        qualifies_multi_probe: Optional[bool],
        reward_breakdown,
    ) -> Optional[str]:
        """Return qualification metadata; omit it for legacy records."""
        if qualifies_multi_probe is None or reward_breakdown is None:
            return None
        if ctype == CANDIDATE_MULTI_PROBE:
            return QUALIFICATION_STRICT
        if ctype == CANDIDATE_EXPLORATORY_MULTI_PROBE:
            return QUALIFICATION_EXPLORATORY
        if ctype == CANDIDATE_TARGET_REACHABILITY:
            return QUALIFICATION_REACHABILITY
        return None

    def _store_candidate(self, candidate: dict, candidates_data: List[dict]) -> bool:
        """Persist through the worker stream when configured, else use legacy IPC.

        A sink failure falls back to the in-memory list so data is not silently lost.
        """
        if self.semantic_top_k and candidate.get('candidate_type') == CANDIDATE_MULTI_PROBE:
            key = (
                self.transport,
                self.mutation_target,
                candidate.get('candidate_type'),
                tuple(sorted(candidate.get('selective_payload_clusters') or ())),
            )
            bucket = self._semantic_top[key]
            previous_ids = {id(item) for item in bucket}
            bucket.append(candidate)
            bucket.sort(key=self._semantic_rank_key)
            retained = any(
                item is candidate for item in bucket[:self.semantic_top_k]
            )
            del bucket[self.semantic_top_k:]
            if retained and previous_ids and len(previous_ids) >= self.semantic_top_k:
                # One previously counted retained candidate was evicted.  The
                # caller increments for the new retained candidate after return.
                self.stats.stored_multi_probe = max(
                    0, self.stats.stored_multi_probe - 1)
            self.last_stored = retained
            return retained
        return self._persist_candidate(candidate, candidates_data)

    def _persist_candidate(self, candidate: dict, candidates_data: List[dict]) -> bool:
        if self.candidate_sink is not None:
            try:
                if self.candidate_sink(candidate):
                    self.last_stored = True
                    return True
            except Exception:
                pass
        candidates_data.append(candidate)
        self.last_stored = True
        return True

    @staticmethod
    def _semantic_rank_key(candidate: dict) -> tuple:
        packet = candidate.get('packet') or b''
        return (
            -float(candidate.get('background_adjusted_breadth') or 0.0),
            -len(candidate.get('selective_payload_clusters') or ()),
            len(packet),
            packet_hash_of(packet),
        )

    def _target_response_pattern(
        self, valid_responses: Sequence[ServiceResponse]
    ) -> str:
        """Return the target service's implementation/response pattern."""
        return target_pattern_digest_from_responses(
            list(valid_responses), self.mutation_target)
