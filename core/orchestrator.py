"""
Fuzzing Orchestrator

Main orchestration for the fuzzing campaign.
All mutation generation uses reinforcement learning via BatchMutationGenerator.
"""

from typing import Any, List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
import logging
import json
import hashlib
import math
import multiprocessing
import os
import pickle
import time
from collections import Counter, defaultdict
from tqdm import tqdm

import config
from protocol.field import UnifiedProtocolSpec
from core.mutator import FastMutator
from core.service_tester import ServiceTester, ServiceResponse, shutdown_shared_pool
from core.clustering import (
    cluster_of,
    cluster_pattern_key,
    observed_clusters_from,
    passive_clusters_from,
    payload_triggered_clusters_from,
    triggered_clusters_from,
)
from core.candidate_collector import (
    CANDIDATE_MULTI_PROBE,
    SEED_REASON_HIGH_BREADTH,
    SEED_REASON_INITIAL,
    SEED_REASON_MULTI_PROBE,
    SEED_REASON_STRICT_TARGET,
    CandidateCollector,
    breadth_rank_key,
)
from core.objectives import (
    REWARD_MODE_BACKGROUND_ADJUSTED,
    REWARD_MODE_TARGET_ONLY,
    MultiObjectiveReward,
    PacketOutcome,
    build_packet_outcome,
    packet_hash_of,
)
from core.background_model import BackgroundProfile, service_topology_hash
from core.bandit_state import StateMetadata as BanditStateMetadata
from core.bandit_state import load_transport as load_v3_transport_state
from core.bandit_state import save_transport as save_v3_transport_state
from core.service_weights import (
    compute_cluster_weights,
    weight_config_hash,
)
from core.compatibility_calibration import (
    COMPAT_MODE_CALIBRATED,
    COMPAT_MODE_HEURISTIC,
    COMPAT_MODE_NONE,
    VALID_COMPAT_MODES,
    HEURISTIC_ALGORITHM_VERSION,
    heuristic_config_hash,
    heuristic_spec_digests,
    load_calibration_artifact,
    runtime_compat_breadth_weights,
    validate_epsilon,
)
from core.reward_logging import RewardEventLogger
from core.candidate_stream import CandidateStreamWriter
from core.campaign_checkpoint import (
    CampaignCheckpoint,
    build_campaign_signature,
)
from core.adaptive import (
    ADAPTIVE_MODE_LEGACY,
    ADAPTIVE_MODE_MULTIOBJECTIVE,
    AdaptiveMetrics,
    EarlyStopTracker,
    adjust_resource_multiobjective,
)

logger = logging.getLogger(__name__)

_worker_protocol_specs: Dict[str, UnifiedProtocolSpec] = {}
_worker_services: Dict[str, tuple] = {}

def _init_worker(protocol_specs: Dict[str, UnifiedProtocolSpec], services: Dict[str, tuple]):
    """Initialize process-local campaign state."""
    global _worker_protocol_specs, _worker_services
    _worker_protocol_specs = protocol_specs
    _worker_services = services
    import atexit
    atexit.register(shutdown_shared_pool)

def _services_for_task(
    services: Dict[str, tuple], task_meta: Dict[str, Any]
) -> Dict[str, tuple]:
    """Honor the public offline-generation switch inside forked workers.

    Legacy/standalone task tuples do not carry ``test_packets`` and therefore
    retain the historical online default.  An explicit false value must make
    the worker socket-free even though the process inherited the global
    service registry.
    """
    return services if bool(task_meta.get("test_packets", True)) else {}

def _malloc_trim() -> None:
    """Best-effort release of unused glibc heap pages on Linux."""
    try:
        import ctypes
        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except Exception:
        pass

@dataclass
class SeedRecord:
    """Seed bytes, verified services, completed mutation targets and explicit ancestry. The line format is hex[,services[,protocols[,meta]]]; initial seeds are never mislabeled as generated multi-probes."""
    packet: bytes
    verified_services: Set[str] = field(default_factory=set)
    fuzzed_protocols: Set[str] = field(default_factory=set)

    seed_reason: str = SEED_REASON_INITIAL

    strict_seed_target: Optional[str] = None

    def hex(self) -> str:
        """Return the seed packet as hexadecimal text."""
        return self.packet.hex()

    def _meta_segment(self) -> str:
        parts = []
        if self.seed_reason and self.seed_reason != SEED_REASON_INITIAL:
            parts.append(f"seed_reason={self.seed_reason}")
        if self.strict_seed_target:
            parts.append(f"strict_seed_target={self.strict_seed_target}")
        return ";".join(parts)

    def to_file_line(self) -> str:
        """Serialize the seed and its optional continuation metadata."""
        services_str = ";".join(sorted(self.verified_services))
        protocols_str = ";".join(sorted(self.fuzzed_protocols))
        meta_str = self._meta_segment()
        
        if services_str or protocols_str or meta_str:
            line = f"{self.hex()},{services_str},{protocols_str}"
            if meta_str:
                line += f",{meta_str}"
            return line
        return self.hex()

    @classmethod
    def from_file_line(cls, line: str) -> Optional['SeedRecord']:
        """Parse a seed line, treating missing reason metadata as an initial seed."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        parts = line.split(",")
        if not 1 <= len(parts) <= 4:
            return None
        hex_str = parts[0]

        try:
            packet = bytes.fromhex(hex_str.strip())
        except ValueError:
            return None

        verified_services = set()
        if len(parts) >= 2 and parts[1].strip():
            verified_services = set(s.strip() for s in parts[1].split(";") if s.strip())

        fuzzed_protocols = set()
        if len(parts) >= 3 and parts[2].strip():
            fuzzed_protocols = set(s.strip() for s in parts[2].split(";") if s.strip())

        seed_reason = SEED_REASON_INITIAL
        strict_seed_target: Optional[str] = None
        if len(parts) >= 4 and parts[3].strip():
            for token in parts[3].split(";"):
                if "=" not in token:
                    continue
                key, _, value = token.partition("=")
                key, value = key.strip(), value.strip()
                if not value:
                    continue
                if key == "seed_reason":
                    seed_reason = value
                elif key == "strict_seed_target":
                    strict_seed_target = value

        return cls(
            packet=packet,
            verified_services=verified_services,
            fuzzed_protocols=fuzzed_protocols,
            seed_reason=seed_reason,
            strict_seed_target=strict_seed_target,
        )

def load_seeds_from_file(filepath: str) -> List[SeedRecord]:
    """Parse seed lines while retaining explicit continuation metadata."""
    seeds = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                record = SeedRecord.from_file_line(line)
                if record:
                    seeds.append(record)
        logger.info(f"Loaded {len(seeds)} seeds from {filepath}")
    except FileNotFoundError:
        logger.warning(f"Seed file not found: {filepath}")
    except Exception as e:
        logger.error(f"Error loading seeds: {e}")

    return seeds

def save_seeds_to_file(seeds: List[SeedRecord], filepath: str, append: bool = False):
    """Write seed packets and continuation metadata."""
    mode = 'a' if append else 'w'
    with open(filepath, mode) as f:
        for seed in seeds:
            f.write(seed.to_file_line() + "\n")
    logger.info(f"Saved {len(seeds)} seeds to {filepath}")

def select_diverse_seeds(
    seeds: List[SeedRecord],
    max_per_group: int = 5,
    strategy: str = 'hash'
) -> List[SeedRecord]:
    """Select a bounded set of diverse seed packet identities."""
    if len(seeds) <= max_per_group:
        return seeds

    if strategy == 'hash':
        
        scored = []
        for s in seeds:
            h = hashlib.md5(s.packet).hexdigest()
            scored.append((h, s))
        scored.sort(key=lambda x: x[0])
        
        step = len(scored) / max_per_group
        return [scored[int(i * step)][1] for i in range(max_per_group)]

    elif strategy == 'random':
        import random
        random.shuffle(seeds)
        return seeds[:max_per_group]

    return seeds[:max_per_group]  # fallback

def get_response_pattern_key(responses: List['ServiceResponse']) -> frozenset:
    """Group candidates by service-level response-byte patterns."""
    return cluster_pattern_key(responses)

def deduplicate_candidates(
    candidates: List['FingerprintCandidate'],
    max_per_pattern: int = 5,
    strategy: str = 'hash'
) -> List['FingerprintCandidate']:
    """Keep a bounded number of packets per service/response pattern."""
    if not candidates or max_per_pattern <= 0:
        return candidates

    pattern_groups: Dict[frozenset, List['FingerprintCandidate']] = {}
    for c in candidates:
        pattern_key = get_response_pattern_key(c.responses)
        if pattern_key not in pattern_groups:
            pattern_groups[pattern_key] = []
        pattern_groups[pattern_key].append(c)

    result = []
    for pattern_key, group in pattern_groups.items():
        if len(group) <= max_per_pattern:
            result.extend(group)
        else:
            
            if strategy == 'hash':
                
                scored = []
                for c in group:
                    h = hashlib.md5(c.packet).hexdigest()
                    scored.append((h, c))
                scored.sort(key=lambda x: x[0])
                
                step = len(scored) / max_per_pattern
                selected = [scored[int(i * step)][1] for i in range(max_per_pattern)]
                result.extend(selected)
            elif strategy == 'random':
                import random
                random.shuffle(group)
                result.extend(group[:max_per_pattern])
            else:
                result.extend(group[:max_per_pattern])

    return result

def _select_diverse_seeds(seeds_data: List[Dict], max_count: int) -> List[Dict]:
    """Prefer distinct packet hashes when retaining seeds."""
    if len(seeds_data) <= max_count:
        return seeds_data

    by_response_group = defaultdict(list)
    for seed in seeds_data:
        group_key = frozenset(seed['verified_clusters'])
        by_response_group[group_key].append(seed)

    selected = []
    groups = list(by_response_group.values())

    round_num = 0
    while len(selected) < max_count and any(len(g) > round_num * 2 for g in groups):
        for group in groups:
            start = round_num * 2
            end = min(start + 2, len(group))
            for i in range(start, end):
                if len(selected) < max_count:
                    selected.append(group[i])
        round_num += 1

    return selected

@dataclass
class ServiceTaskResult:
    """Results and accounting returned by a service mutation worker."""
    service_name: str
    candidates: List
    new_seeds: List
    final_fuzz_resource: int
    # Pickled ReinforcementLearningBandit state (None if RL_ENABLED=False or no updates)
    final_bandit_state: Optional[bytes] = None
    # Worker-owned metadata. seed_count avoids pairing imap_unordered results
    # with svc_tasks by list index; reward log fields feed the parent manifest.
    seed_count: int = 0
    task_id: str = ""
    reward_log_path: str = ""
    reward_log_events: int = 0
    reward_log_errors: int = 0
    # Worker-owned candidate stream.  Only a normally returned entry is
    # authoritative; orphan/truncated files from killed workers are ignored.
    candidate_stream_path: str = ""
    candidate_stream_records: int = 0
    candidate_stream_errors: int = 0

    compat_mode: str = ""
    compat_weight_hash: str = ""

    metrics: Optional[AdaptiveMetrics] = None

    target_hit_clusters: Set[str] = field(default_factory=set)
    
    generated_mutants: int = 0
    sent_mutants: int = 0
    dedup_skips: int = 0

    phase0_generated_packets: int = 0
    phase0_sent_packets: int = 0
    phase0_dedup_skips: int = 0
    
    worker_failed: bool = False
    worker_error: str = ""

def require_complete_worker_transactions(
    results: List[ServiceTaskResult], reward_mode: str
) -> None:
    """Reject a partially successful search round before state/checkpoint merge."""
    if reward_mode != REWARD_MODE_BACKGROUND_ADJUSTED:
        return
    failures = [result for result in results if result.worker_failed]
    if not failures:
        return
    details = "; ".join(
        f"{r.task_id or r.service_name}: {r.worker_error}"
        for r in failures[:8]
    )
    raise RuntimeError(
        f"background-adjusted search worker transaction failed ({len(failures)}/"
        f"{len(results)} tasks): {details}"
    )

def _apply_loaded_bandit_decay(bandit: Any, decay: float) -> bool:
    """Apply configured cross-campaign forgetting to any loaded state schema."""
    if not 0.0 <= decay <= 1.0:
        raise ValueError(f"RL_DECAY must be in [0,1], got {decay}")
    if decay >= 1.0:
        return False
    bandit.decay_toward_prior(decay)
    return True

def _allow_sequential_pool_fallback(reward_mode: str) -> bool:
    """Background-adjusted search must preserve ledger transactions during retries."""
    return reward_mode != REWARD_MODE_BACKGROUND_ADJUSTED

def build_send_dedup_manifest(
    results: List[ServiceTaskResult],
    *,
    enabled: bool,
    attempt_epoch: str,
) -> Dict[str, Any]:
    """Describe the current send ledger and deduplication policy."""
    generated = sum(r.generated_mutants for r in results)
    sent = sum(r.sent_mutants for r in results)
    skips = sum(r.dedup_skips for r in results)
    phase0_generated = sum(r.phase0_generated_packets for r in results)
    phase0_sent = sum(r.phase0_sent_packets for r in results)
    phase0_skips = sum(r.phase0_dedup_skips for r in results)
    return {
        "enabled": bool(enabled),
        "attempt_epoch": attempt_epoch,
        "generated_mutants": generated,
        "sent_mutants": sent,
        "dedup_skips": skips,
        "phase0_generated_packets": phase0_generated,
        "phase0_sent_packets": phase0_sent,
        "phase0_dedup_skips": phase0_skips,
        "ledger_completed_expected": sent + phase0_sent,
        "total_dedup_skips": skips + phase0_skips,
        "mutation_balanced": generated == sent + skips,
        "phase0_balanced": phase0_generated == phase0_sent + phase0_skips,
    }

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def should_emit_strict_target_seed(
    metrics: AdaptiveMetrics,
    *,
    enabled: bool,
    reach_threshold: float,
    best_exists: bool,
) -> bool:
    """Decide whether a low-reach target needs a bounded continuation seed."""
    if not enabled or not best_exists:
        return False
    if metrics.evaluated_mutants <= 0:
        return False
    return metrics.reach_rate <= reach_threshold

def pick_breadth_ranked_seeds(
    entries: List[dict],
    max_count: int,
) -> List[dict]:
    """Keep the highest-ranked breadth seeds under a deterministic total order."""
    if max_count <= 0 or not entries:
        return []
    ranked = sorted(entries, key=breadth_rank_key)
    return ranked[:max_count]

def pick_strict_target_seeds(
    entries: List[dict],
    max_count: int = 1,
) -> List[dict]:
    """Merge strict-target seed candidates across workers for one service."""
    return pick_breadth_ranked_seeds(entries, max_count)

def pick_high_breadth_seeds(
    entries: List[dict],
    max_count: int,
    exclude_packet_hashes: Optional[Set[str]] = None,
) -> List[dict]:
    """Apply the per-target, per-round high-breadth seed cap."""
    if max_count <= 0 or not entries:
        return []
    seen = set(exclude_packet_hashes or ())
    unique_entries = []
    for e in entries:
        h = packet_hash_of(e['packet'])
        if h in seen:
            continue
        seen.add(h)
        unique_entries.append(e)
    return pick_breadth_ranked_seeds(unique_entries, max_count)

def seed_eligible_for_protocol(seed_record: SeedRecord, protocol_name: str) -> bool:
    """Check seed eligibility, including explicit strict-target continuation."""
    strict_bypass = (
        seed_record.seed_reason == SEED_REASON_STRICT_TARGET
        and seed_record.strict_seed_target == protocol_name
    )
    if protocol_name in seed_record.fuzzed_protocols and not strict_bypass:
        return False
    if protocol_name in seed_record.verified_services and not strict_bypass:
        return False
    return True

def build_service_seeds(
    seeds_by_response_group: Dict[frozenset, List[SeedRecord]],
    protocol_names: List[str],
    protocol_specs: Dict[str, UnifiedProtocolSpec],
) -> Dict[str, List[Tuple[bytes, SeedRecord]]]:
    """Build this round's eligible seed list for each mutation service."""
    service_seeds: Dict[str, List[Tuple[bytes, SeedRecord]]] = {}
    for protocol_name in protocol_names:
        if protocol_name not in protocol_specs:
            continue
        for seeds in seeds_by_response_group.values():
            for seed_record in seeds:
                if not seed_eligible_for_protocol(seed_record, protocol_name):
                    continue
                if protocol_name not in service_seeds:
                    service_seeds[protocol_name] = []
                service_seeds[protocol_name].append(
                    (seed_record.packet, seed_record)
                )
    return service_seeds

def resolve_parent_seed(
    s_data: Dict,
    parent_by_id: Dict[str, SeedRecord],
    parent_by_hash: Dict[str, SeedRecord],
    fallback: Optional[SeedRecord],
) -> Optional[SeedRecord]:
    """Resolve the true parent packet for generated seed ancestry."""
    parent_id = s_data.get('parent_seed_id')
    if parent_id and parent_id in parent_by_id:
        return parent_by_id[parent_id]
    parent_hash = s_data.get('parent_packet_hash')
    if parent_hash:
        parent = parent_by_hash.get(parent_hash)
        if parent is not None:
            return parent
    return fallback

def seed_record_from_worker_dict(
    s_data: Dict,
    svc_name: str,
    parent_by_id: Dict[str, SeedRecord],
    parent_by_hash: Dict[str, SeedRecord],
    fallback_parent: Optional[SeedRecord],
) -> SeedRecord:
    """Restore a worker-emitted seed with its actual selection reason."""
    parent = resolve_parent_seed(s_data, parent_by_id, parent_by_hash,
                                 fallback_parent)
    new_fuzzed = set(parent.fuzzed_protocols) if parent else set()
    new_fuzzed.add(svc_name)
    reason = s_data.get('seed_reason') or SEED_REASON_MULTI_PROBE
    return SeedRecord(
        packet=s_data['packet'],
        verified_services=set(s_data['verified_clusters']),
        fuzzed_protocols=new_fuzzed,
        seed_reason=reason,
        strict_seed_target=(
            svc_name if reason == SEED_REASON_STRICT_TARGET else None),
    )

def update_target_hit_clusters(
    acc: Set[str], outcome: PacketOutcome, *, payload_only: bool = False
) -> bool:
    """Accumulate observed services only from packets that reached their target."""
    if outcome.target_triggered:
        acc.update(
            outcome.payload_triggered_clusters
            if payload_only else outcome.triggered_clusters
        )
        return True
    return False

def collect_round_useful_clusters(results: List['ServiceTaskResult']) -> Set[str]:
    """Union useful service coverage across workers without double counting."""
    seen: Set[str] = set()
    for r in results:
        seen |= set(r.target_hit_clusters or ())
    return seen

def responses_from_candidate_data(c_data: dict) -> List[ServiceResponse]:
    """Rebuild worker IPC responses without erasing phase attribution."""
    observations = c_data.get("response_observations")
    if observations is not None:
        return [
            ServiceResponse(
                service_name=item.get("service", ""),
                response_bytes=bytes(item.get("response_bytes") or b""),
                latency_ms=float(item.get("latency_ms", 0.0)),
                timestamp=time.time(),
                response_phase=item.get("response_phase", "post_payload"),
                banner_bytes=bytes(item.get("banner_bytes") or b""),
                banner_latency_ms=float(item.get("banner_latency_ms", 0.0)),
                payload_latency_ms=float(item.get("payload_latency_ms", 0.0)),
            )
            for item in observations
        ]
    return [
        ServiceResponse(
            service_name=srv_name,
            response_bytes=srv_resp,
            latency_ms=srv_latency,
            timestamp=time.time(),
            response_phase="legacy_unknown",
        )
        for srv_name, srv_resp, srv_latency in c_data.get("responses", ())
    ]

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def build_reward_engine_for_universe(
    services: Dict[str, tuple],
    reward_mode: Optional[str] = None,
    objective_version: Optional[str] = None,
    credit_mode: Optional[str] = None,
    lambda_breadth: Optional[float] = None,
    mutation_target: Optional[str] = None,
    transport: str = "",
    specs: Optional[Dict[str, UnifiedProtocolSpec]] = None,
    compat_mode: Optional[str] = None,
    background_profile: Optional[BackgroundProfile] = None,
) -> MultiObjectiveReward:
    """Build the objective over testable service clusters, not endpoint counts."""
    mode = reward_mode if reward_mode is not None else getattr(
        config, 'REWARD_MODE', REWARD_MODE_TARGET_ONLY)
    resolved_compat = (compat_mode if compat_mode is not None
                       else getattr(config, 'COMPATIBILITY_PRIOR_MODE', COMPAT_MODE_NONE))
    if resolved_compat not in VALID_COMPAT_MODES:
        raise ValueError(
            f"COMPATIBILITY_PRIOR_MODE must be one of {VALID_COMPAT_MODES}, "
            f"got {resolved_compat!r}")
    resolved_objective_version = (
        objective_version if objective_version is not None
        else getattr(config, 'OBJECTIVE_VERSION', None))
    if resolved_compat != COMPAT_MODE_NONE:
        
        validate_epsilon(getattr(config, 'COMPATIBILITY_EPSILON', 0.1))
        if mode == REWARD_MODE_TARGET_ONLY:
            logger.warning(
                "[COMPAT] COMPATIBILITY_PRIOR_MODE=%s has no effect under "
                "reward_mode=target_only (no breadth head) — ignoring",
                resolved_compat)

    cluster_weights = None
    compat_weights = None
    compat_meta: Dict[str, object] = {}
    if mode != REWARD_MODE_TARGET_ONLY:
        universe = {cluster_of(name) for name in services} if services else set()
        cluster_weights = compute_cluster_weights(
            universe,
            prevalence_alpha=getattr(config, 'SERVICE_WEIGHT_PREVALENCE_ALPHA', 0.7),
        )
        if (resolved_compat != COMPAT_MODE_NONE and universe
                and mutation_target):

            compat_weights, compat_info = runtime_compat_breadth_weights(
                cluster_weights,
                target=mutation_target,
                transport=transport,
                mode=resolved_compat,
                specs=specs,
                expected_objective_version=resolved_objective_version
                if resolved_compat == COMPAT_MODE_CALIBRATED else None,
                expected_spec_digests=(
                    heuristic_spec_digests(specs)
                    if resolved_compat == COMPAT_MODE_CALIBRATED and specs
                    else None),
                expected_heuristic_algorithm_version=(
                    HEURISTIC_ALGORITHM_VERSION
                    if resolved_compat == COMPAT_MODE_CALIBRATED else None),
            )
            compat_meta = compat_info.as_dict()
            if compat_weights is not None:
                logger.info(
                    "[COMPAT] target=%s transport=%s applied prior=%s "
                    "epsilon=%.3f n_clusters=%d weight_hash=%s%s",
                    mutation_target, transport or "n/a",
                    compat_info.applied_mode, compat_info.epsilon,
                    compat_info.n_clusters, compat_info.weight_hash,
                    (f" artifact={compat_info.artifact_hash}"
                     if compat_info.artifact_hash else ""),
                )
    resolved_background = background_profile
    if mode == REWARD_MODE_BACKGROUND_ADJUSTED and resolved_background is None:
        profile_path = getattr(config, "BACKGROUND_PROFILE_FILE", "")
        if not profile_path or not os.path.isfile(profile_path):
            raise ValueError(
                "background_adjusted_breadth requires an existing "
                f"BACKGROUND_PROFILE_FILE, got {profile_path!r}"
            )
        resolved_background = BackgroundProfile.load(
            profile_path,
            expected_objective_version=resolved_objective_version,
            expected_service_topology_hash=service_topology_hash(config.SERVICES),
            expected_weight_config_hash=weight_config_hash(
                prevalence_alpha=float(getattr(
                    config, "SERVICE_WEIGHT_PREVALENCE_ALPHA", 0.7))),
        )
    return MultiObjectiveReward(
        cluster_weights=cluster_weights,
        mode=mode,
        objective_version=resolved_objective_version,
        credit_mode=credit_mode if credit_mode is not None
        else getattr(config, 'MULTI_FIELD_CREDIT_MODE', 'shared'),
        lambda_breadth=lambda_breadth if lambda_breadth is not None
        else getattr(config, 'LAMBDA_BREADTH', 0.5),
        compat_target=mutation_target if compat_weights is not None else None,
        compat_weights=compat_weights,
        compat_meta=compat_meta,
        background_profile=resolved_background,
        transport=transport,
        mutation_target=mutation_target,
    )

def update_bandit_from_reward(
    bandit,
    service_name: str,
    touched_plans: List,
    reward,
    reward_mode: str,
) -> None:
    """Apply one packet's bounded Reach/Breadth feedback to touched fields."""
    if reward_mode == REWARD_MODE_TARGET_ONLY:
        r = bool(reward.reachability)
        for p in touched_plans:
            bandit.update(service_name, p.field.name, r)
    else:
        for p in touched_plans:
            bandit.update_multi(
                service_name, p.field.name,
                reachability_reward=reward.reachability,
                breadth_reward=reward.target_gated_breadth,
                observation_weight=reward.credit_weight,
                reachability_weight=getattr(
                    reward, "reachability_credit_weight", reward.credit_weight),
                breadth_weight=reward.credit_weight,
            )

def service_fuzz_worker(task_data: Tuple) -> ServiceTaskResult:
    """Mutate all assigned seeds for one service with per-batch feedback and adaptive budgets."""
    global _worker_protocol_specs, _worker_services

    (service_name, seeds_data, fuzz_resource,
     iteration, fingerprint_threshold, seed_threshold,
     max_seeds_per_seed, bandit_state_bytes) = task_data[:8]
    task_meta = task_data[8] if len(task_data) > 8 else {}
    run_id = task_meta.get("run_id", "standalone")
    task_id = task_meta.get("task_id", f"{service_name}_{iteration}")
    transport = task_meta.get("transport", "")
    attempt_epoch = task_meta.get("attempt_epoch", "")
    dedup_ledger_path = task_meta.get("dedup_ledger_path", "")

    parent_seed_ids = task_meta.get("parent_seed_ids") or []

    spec = _worker_protocol_specs.get(service_name)
    services = _services_for_task(_worker_services, task_meta)

    # Restore reinforcement-learning bandit (if any)
    bandit = None
    if bandit_state_bytes is not None and getattr(config, 'RL_ENABLED', False):
        try:
            from core.reinforcement_learning import ReinforcementLearningBandit
            bandit = pickle.loads(bandit_state_bytes)
            from core.reinforcement_learning import stable_experiment_seed
            _base_seed = getattr(config, "RL_RANDOM_SEED", None)
            if _base_seed is not None:
                bandit.reseed(stable_experiment_seed(
                    _base_seed, transport, service_name, task_id, "bandit"
                ))
            logger.info(
                f"[SVC-WORKER] Restored ReinforcementLearningBandit for {service_name}: "
                f"{len(bandit.state)} arms"
            )
        except Exception as e:
            logger.warning(f"[SVC-WORKER] Failed to restore bandit: {e}")
            bandit = None

    logger.info(
        f"[SVC-WORKER] Starting service task: {service_name}, "
        f"{len(seeds_data)} seeds, mutation_budget={fuzz_resource}"
    )

    if spec is None:
        logger.warning(f"[SVC-WORKER] Protocol spec not found for {service_name}")
        return ServiceTaskResult(
            service_name=service_name,
            candidates=[],
            new_seeds=[],
            final_fuzz_resource=fuzz_resource,
            seed_count=len(seeds_data),
            task_id=task_id,
        )

    # Import adaptive adjustment functions
    from core.adaptive import compute_hit_rate, adjust_resource_boofuzz

    candidates_data = []
    new_seeds_data = []

    _max_per_pattern = 2 * int(getattr(config, 'MAX_FINGERPRINTS_PER_RESPONSE_PATTERN', 1))

    _adaptive_mode = getattr(config, 'ADAPTIVE_OBJECTIVE_MODE', ADAPTIVE_MODE_LEGACY)
    _v1_adaptive = _adaptive_mode == ADAPTIVE_MODE_MULTIOBJECTIVE
    reward_mode = getattr(config, 'REWARD_MODE', REWARD_MODE_TARGET_ONLY)
    collector = CandidateCollector(
        mutation_target=service_name,
        fingerprint_threshold=fingerprint_threshold,
        seed_threshold=seed_threshold,
        max_per_pattern=_max_per_pattern,
        collect_target_reachability=getattr(config, 'COLLECT_TARGET_REACHABILITY', False),
        max_tr_per_pattern=getattr(config, 'MAX_TARGET_REACHABILITY_PER_PATTERN', 2),
        max_tr_per_service=getattr(config, 'MAX_TARGET_REACHABILITY_PER_SERVICE', 100),
        require_target_trigger=getattr(config, 'REQUIRE_ORIGIN_TRIGGER', True),
        seed_high_breadth_enabled=(
            _v1_adaptive and bool(getattr(config, 'SEED_HIGH_BREADTH_ENABLED', True))
        ),
        seed_high_breadth_threshold=float(
            getattr(config, 'SEED_HIGH_BREADTH_THRESHOLD', 0.1)),
        max_high_breadth_seeds=int(
            getattr(config, 'SEED_HIGH_BREADTH_MAX_PER_SERVICE', 2)),
        transport=transport,
        semantic_top_k=(
            int(getattr(config, 'SEMANTIC_CANDIDATE_TOP_K', 5))
            if reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED else 0
        ),
        
        exploratory_top_k=(
            int(getattr(config, 'EXPLORATORY_TOP_K_PER_EXTRA', 3))
            if reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED else 0
        ),
    )

    reward_engine = build_reward_engine_for_universe(
        services, reward_mode=reward_mode,
        mutation_target=service_name, transport=transport,
        specs=_worker_protocol_specs,
    )
    worker_compat = reward_engine.compat_summary()
    if bandit is not None:
        bandit.set_passive(service_name, reward_engine.target_mode == "passive")
    worker_weight_hash = weight_config_hash(
        prevalence_alpha=float(getattr(config, "SERVICE_WEIGHT_PREVALENCE_ALPHA", 0.7))
    )
    reward_logger = RewardEventLogger(
        enabled=getattr(config, "REWARD_LOG_ENABLED", False),
        log_dir=getattr(
            config, "REWARD_LOG_DIR",
            os.path.join(getattr(config, "CACHE_DIR", ".cache"), "reward_events"),
        ),
        run_id=run_id,
        task_id=task_id,
        mutation_target=service_name,
        iteration=iteration,
    )
    candidate_writer = CandidateStreamWriter(
        enabled=bool(services) and bool(getattr(
            config, "CANDIDATE_STREAM_ENABLED", False)),
        stream_dir=getattr(
            config, "CANDIDATE_STREAM_DIR",
            os.path.join(getattr(config, "CACHE_DIR", ".cache"), "candidate_streams"),
        ),
        run_id=run_id,
        task_id=task_id,
        transport=transport,
        objective_version=getattr(config, "OBJECTIVE_VERSION", ""),
        weight_config_hash=worker_weight_hash,
    )
    if candidate_writer.enabled:
        collector.candidate_sink = candidate_writer.write
    dedup_ledger = None
    generated_mutants = 0
    sent_mutants = 0
    dedup_skips = 0

    phase0_generated_packets = 0
    phase0_sent_packets = 0
    phase0_dedup_skips = 0
    pending_completion_hashes: Set[str] = set()
    last_lease_renewal = time.time()
    worker_failed = False
    logger.info(
        f"[SVC-WORKER] {service_name} reward config: "
        f"objective_version={reward_engine.objective_version} "
        f"reward_mode={reward_mode} "
        f"credit={getattr(config, 'MULTI_FIELD_CREDIT_MODE', 'shared')} "
        f"lambda_breadth={getattr(config, 'LAMBDA_BREADTH', 0.5)} "
        f"breadth_universe={len(reward_engine._weights) if reward_mode != REWARD_MODE_TARGET_ONLY else 'n/a (V0)'} "
        f"compat_applied={worker_compat.get('applied')} "
        f"compat_mode={worker_compat.get('applied_mode', COMPAT_MODE_NONE)} "
        f"compat_weight_hash={worker_compat.get('weight_hash', '')}"
    )

    adaptive_mode, v1_adaptive = _adaptive_mode, _v1_adaptive
    metrics = AdaptiveMetrics(
        pattern_track_cap=int(getattr(config, 'ADAPTIVE_PATTERN_TRACK_CAP', 4096)),
    )
    
    _v1_params = dict(
        reach_low=float(getattr(config, 'ADAPTIVE_REACH_LOW_THRESHOLD', 0.05)),
        reach_high=float(getattr(config, 'ADAPTIVE_REACH_HIGH_THRESHOLD', 0.5)),
        breadth_progress_min=float(getattr(config, 'ADAPTIVE_BREADTH_PROGRESS_MIN', 0.005)),
        no_progress_patience=int(getattr(config, 'ADAPTIVE_NO_PROGRESS_PATIENCE', 3)),
        fuzz_min=config.ADAPTIVE_FUZZ_MIN,
        fuzz_max=config.ADAPTIVE_FUZZ_MAX,
        increase_rate=config.ADAPTIVE_FUZZ_INCREASE_RATE,
        decrease_rate=config.ADAPTIVE_FUZZ_DECREASE_RATE,
        min_explore=int(getattr(config, 'ADAPTIVE_MIN_EXPLORE_BUDGET', 1000)),
        min_samples=int(getattr(config, 'ADAPTIVE_POLICY_MIN_SAMPLES', 100)),
    )
    _v1_strict_reach = float(getattr(config, 'ADAPTIVE_STRICT_REACH_THRESHOLD', 0.05))
    _v1_high_weight_thr = float(getattr(config, 'ADAPTIVE_HIGH_WEIGHT_THRESHOLD', 0.05))
    _target_cluster_weight = float(reward_engine._weights.get(service_name, 0.0))
    _strict_seed_cfg = dict(
        enabled=bool(getattr(config, 'SEED_STRICT_TARGET_ENABLED', True)),
        reach_threshold=float(getattr(config, 'SEED_STRICT_TARGET_REACH_THRESHOLD', 0.05)),
    )
    
    _best_strict = None  # {'packet', 'triggered_clusters', 'breadth', 'parent_packet_hash', 'parent_seed_id'}
    _prev_breadth_mean = None  

    _target_hit_clusters: Set[str] = set()


    # Current resource (updated after each seed)
    cur_fuzz_res = fuzz_resource

    worker_error = ""
    try:


        target_services = {name: svc for name, svc in services.items() if name == service_name}
        has_services = bool(services)

        if has_services and not target_services:
            logger.warning(f"[SVC-WORKER] No target service for {service_name}")
            reward_logger.close()
            candidate_writer.close()
            reward_log = reward_logger.manifest_entry()
            candidate_stream = candidate_writer.manifest_entry()
            return ServiceTaskResult(
                service_name=service_name,
                candidates=[],
                new_seeds=[],
                final_fuzz_resource=cur_fuzz_res,
                seed_count=len(seeds_data),
                task_id=task_id,
                reward_log_path=reward_log["path"],
                reward_log_events=reward_log["events"],
                reward_log_errors=reward_log["errors"],
                candidate_stream_path=candidate_stream["path"],
                candidate_stream_records=candidate_stream["records"],
                candidate_stream_errors=candidate_stream["errors"],
                metrics=metrics,
            )

        if (
            has_services
            and reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED
            and bool(getattr(config, "DEDUP_ENABLED", True))
        ):
            if not attempt_epoch or not dedup_ledger_path:
                raise ValueError("background-adjusted search worker is missing attempt_epoch/dedup_ledger_path")
            from core.dedup_ledger import DedupLedger
            dedup_ledger = DedupLedger(
                dedup_ledger_path,
                lease_seconds=float(getattr(config, "DEDUP_LEASE_SECONDS", 900.0)),
                owner=f"{run_id}:{task_id}:pid{os.getpid()}",
            )

        tester = ServiceTester(
            services,
            timeout=config.SERVICE_TIMEOUT,
            banner_timeout=config.BANNER_TIMEOUT,
        ) if has_services else None

        def _claim_send_indices(packets, *, scope: str, touched_plans=None):
            """Batch-local dedup followed by one SQLite claim transaction."""
            nonlocal last_lease_renewal
            if dedup_ledger is None:
                return list(range(len(packets))), [packet_hash_of(p) for p in packets], 0
            now = time.time()
            renew_interval = max(5.0, dedup_ledger.lease_seconds / 3.0)
            if (pending_completion_hashes
                    and now - last_lease_renewal >= renew_interval):
                renewed = dedup_ledger.renew_pending(
                    attempt_epoch=attempt_epoch,
                    transport=transport,
                    mutation_target=service_name,
                    now=now,
                )
                if renewed != len(pending_completion_hashes):
                    raise RuntimeError(
                        "dedup lease renewal mismatch: "
                        f"{renewed}/{len(pending_completion_hashes)}"
                    )
                last_lease_renewal = now
            unique_indices = []
            unique_hashes = []
            seen_hashes = set()
            skipped = []
            for idx, packet in enumerate(packets):
                digest = packet_hash_of(packet)
                if digest in seen_hashes:
                    skipped.append((idx, digest, "batch_duplicate"))
                    continue
                seen_hashes.add(digest)
                unique_indices.append(idx)
                unique_hashes.append(digest)
            claims = dedup_ledger.claim_hashes(
                unique_hashes,
                attempt_epoch=attempt_epoch,
                transport=transport,
                mutation_target=service_name,
            )
            claimed_indices, claimed_hashes = [], []
            for idx, claim in zip(unique_indices, claims):
                if claim.claimed:
                    claimed_indices.append(idx)
                    claimed_hashes.append(claim.packet_hash)
                    pending_completion_hashes.add(claim.packet_hash)
                else:
                    skipped.append((idx, claim.packet_hash, claim.reason))
            for idx, digest, reason in skipped:
                reward_logger.write({
                    "event_type": "dedup_skip",
                    "run_id": run_id,
                    "task_id": task_id,
                    "iteration": iteration,
                    "mutation_target": service_name,
                    "transport": transport,
                    "packet_hash": digest,
                    "scope": scope,
                    "reason": reason,
                    "fields": (
                        [p.field.name for p in touched_plans[idx]]
                        if (scope == "mutation" and touched_plans is not None
                            and idx < len(touched_plans) and touched_plans[idx])
                        else []
                    ),
                    "objective_version": reward_engine.objective_version,
                    "background_artifact_hash": (
                        reward_engine.background_profile.artifact_hash
                        if reward_engine.background_profile is not None else ""
                    ),
                })
            return claimed_indices, claimed_hashes, len(skipped)

        if (iteration == 0 and has_services and seeds_data
                and getattr(config, 'RAW_SEED_BASELINE_TEST', True)):
            phase0_start = time.time()
            seen_raw, unique_raw = set(), []
            for sb in seeds_data:
                b = bytes(sb)
                if b not in seen_raw:
                    seen_raw.add(b)
                    unique_raw.append(b)

            phase0_generated_packets += len(unique_raw)
            _phase0_indices, _phase0_hashes, _phase0_skipped = _claim_send_indices(
                unique_raw, scope="phase0")
            phase0_dedup_skips += _phase0_skipped
            unique_raw = [unique_raw[i] for i in _phase0_indices]
            phase0_sent_packets += len(unique_raw)
            phase0_results = tester.test_packets_parallel(
                unique_raw,
                max_workers=config.PHASE2_PARALLEL_WORKERS,
                batch_size=config.PHASE2_BATCH_SIZE,
            )
            target_hits, raw_multiprobe = 0, 0
            for i, responses in enumerate(phase0_results):

                outcome = build_packet_outcome(
                    unique_raw[i], responses,
                    mutation_target=service_name,
                    transport=transport,
                    target_mode=reward_engine.target_mode,
                )
                phase0_reward = reward_engine.evaluate(outcome, n_touched_fields=0)
                collector.collect(
                    unique_raw[i], responses, outcome, iteration,
                    candidates_data, new_seeds_data,
                    multi_probe_packets=None,        
                    collect_new_seeds=False,         
                    qualifies_multi_probe=(
                        phase0_reward.qualifies_multi_probe
                        if reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED else None),
                    reward_breakdown=phase0_reward,
                )
                if outcome.target_triggered:
                    target_hits += 1
                if (
                    phase0_reward.qualifies_multi_probe
                    if reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED
                    else len(outcome.triggered_clusters) >= fingerprint_threshold
                ):
                    raw_multiprobe += 1
            dt = time.time() - phase0_start
            if target_hits == 0 and unique_raw:
                logger.warning(
                    f"[SVC-WORKER] {service_name} Phase 0 (raw): target gate passed "
                    f"for 0/{len(unique_raw)} raw seeds ({dt:.1f}s). This does not "
                    f"imply the server is down; inspect phase-aware observations.")
            else:
                logger.info(
                    f"[SVC-WORKER] {service_name} Phase 0 (raw): tested {len(unique_raw)} "
                    f"seeds → target gate passed for {target_hits}, "
                    f"{raw_multiprobe} multi-probe ({dt:.1f}s)")

        for seed_idx, seed_bytes in enumerate(seeds_data):
            logger.info(
                f"[SVC-WORKER] {service_name} seed {seed_idx+1}/{len(seeds_data)}: "
                f"mutation_budget={cur_fuzz_res}"
            )
            
            seed_metrics_snap = metrics.snapshot()

            _seed_parent_hash = packet_hash_of(seed_bytes)
            _seed_parent_id = (
                parent_seed_ids[seed_idx]
                if seed_idx < len(parent_seed_ids) else None
            )

            # ---- Set up bandit for this seed ----
            use_bandit = False
            mutator = FastMutator(spec)
            batch_gen = None

            if bandit is not None:
                try:
                    from core.reinforcement_learning import (
                        BatchMutationGenerator, stable_experiment_seed,
                    )
                    batch_gen = BatchMutationGenerator(
                        spec, seed_bytes, mutator,
                        seed=stable_experiment_seed(
                            getattr(config, "RL_RANDOM_SEED", None),
                            transport, service_name, task_id, _seed_parent_hash,
                            seed_idx, "mutation",
                        ),
                    )
                    if batch_gen._feasible:
                        bandit.register_all(
                            service_name, batch_gen.mutable, batch_gen.length_fields,
                            default_length_score=1,
                        )
                        use_bandit = True
                    else:
                        logger.warning(
                            f"  [SVC-WORKER] {service_name}: no mutable fields, skipping seed"
                        )
                        continue
                except Exception as e:
                    logger.warning(f"  [SVC-WORKER] BatchMutationGenerator init failed: {e}")
                    continue

            if not use_bandit:
                logger.warning(
                    f"  [SVC-WORKER] {service_name}: bandit not available, skipping seed"
                )
                continue

            # ---- Compute batch layout ----
            batch_size = max(config.RL_BATCH_MIN, config.RL_BATCH_SIZE)
            total_batches = max(1, cur_fuzz_res // batch_size)
            per_batch = batch_size

            multi_probe_packets = []

            load_only = getattr(config, 'RL_LOAD_ONLY', False)

            for batch_idx in range(total_batches):
                # --- Generate mutations via reinforcement learning ---
                mutants, touched = batch_gen.generate(
                    bandit=bandit, service=service_name,
                    batch_size=per_batch,
                    max_fields=config.RL_MAX_FIELDS,
                    batch_idx=batch_idx, total_batches=total_batches,
                    phase1_ratio=config.RL_PHASE1_RATIO,
                )
                logger.debug(
                    f"  [SVC-WORKER] batch {batch_idx+1}/{total_batches} "
                    f"(reinforcement learning): {len(mutants)} mutants"
                )

                if not mutants:
                    continue

                generated_mutants += len(mutants)
                _claimed_hashes = []
                if dedup_ledger is not None:
                    _keep_indices, _claimed_hashes, _skipped = _claim_send_indices(
                        mutants, scope="mutation", touched_plans=touched)
                    dedup_skips += _skipped
                    mutants = [mutants[i] for i in _keep_indices]
                    touched = [touched[i] for i in _keep_indices]
                    if not mutants:
                        continue

                # --- Test all services ---
                if not has_services:
                    # Offline mode: just record all mutants as candidates
                    
                    for mutant in mutants:
                        offline_cand = {
                            'packet': mutant,
                            'responses': [],
                            'mutation_target': service_name,
                            'iteration': iteration,
                            'triggered_clusters': set(),
                            'candidate_type': CANDIDATE_MULTI_PROBE,
                        }
                        if _seed_parent_id:
                            offline_cand['parent_seed_id'] = _seed_parent_id
                        if _seed_parent_hash:
                            offline_cand['parent_packet_hash'] = _seed_parent_hash
                        candidates_data.append(offline_cand)
                    continue

                phase2_start = time.time()
                batch_results = tester.test_packets_parallel(
                    mutants,
                    max_workers=config.PHASE2_PARALLEL_WORKERS,
                    batch_size=config.PHASE2_BATCH_SIZE,
                )
                sent_mutants += len(mutants)

                metrics.begin_batch()

                for pkt_idx, responses in enumerate(batch_results):

                    outcome = build_packet_outcome(
                        mutants[pkt_idx], responses,
                        mutation_target=service_name,
                        transport=transport,
                        target_mode=reward_engine.target_mode,
                    )
                    n_touched = len(touched[pkt_idx]) if touched[pkt_idx] else 0
                    reward = reward_engine.evaluate(outcome, n_touched_fields=n_touched)
                    candidate_type = collector.collect(
                        mutants[pkt_idx], responses, outcome, iteration,
                        candidates_data, new_seeds_data,
                        multi_probe_packets=multi_probe_packets,
                        
                        target_gated_breadth=(
                            reward.target_gated_breadth if v1_adaptive else None),
                        
                        parent_seed_id=_seed_parent_id,
                        parent_packet_hash=_seed_parent_hash,
                        qualifies_multi_probe=(
                            reward.qualifies_multi_probe
                            if reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED else None),
                        reward_breakdown=reward,
                    )
                    stored = collector.last_stored

                    update_target_hit_clusters(
                        _target_hit_clusters, outcome,
                        payload_only=(
                            reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED),
                    )


                    new_packet_patterns = metrics.observe(
                        target_triggered=outcome.target_triggered,
                        target_gated_breadth=reward.target_gated_breadth,
                        stored=stored,
                        pattern_key=(
                            ("selective", *reward.selective_extra_clusters)
                            if reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED
                            else get_response_pattern_key(responses)
                        ),
                    )

                    if (v1_adaptive and outcome.target_triggered
                            and collector.last_seed_reason is None):
                        _b = reward.target_gated_breadth
                        if (_best_strict is None
                                or _b > _best_strict["breadth"]
                                or (_b == _best_strict["breadth"]
                                    and len(mutants[pkt_idx]) < len(_best_strict["packet"]))):
                            _best_strict = {
                                "packet": mutants[pkt_idx],
                                "triggered_clusters": set(
                                    outcome.payload_triggered_clusters
                                    if reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED
                                    else outcome.triggered_clusters
                                ),
                                "breadth": _b,
                                "parent_packet_hash": _seed_parent_hash,
                                "parent_seed_id": _seed_parent_id,
                            }

                    # Update bandit for each mutation (per-batch feedback).

                    if touched[pkt_idx]:
                        if not load_only:
                            update_bandit_from_reward(
                                bandit, service_name, touched[pkt_idx],
                                reward, reward_mode,
                            )
                        reward_logger.write({
                            "run_id": run_id,
                            "task_id": task_id,
                            "iteration": iteration,
                            "seed_index": seed_idx,
                            "batch_index": batch_idx,
                            "packet_hash": outcome.packet_hash,
                            "mutation_target": service_name,
                            "transport": transport,
                            "fields": [p.field.name for p in touched[pkt_idx]],
                            "field_count": len(touched[pkt_idx]),
                            "triggered_clusters": sorted(outcome.triggered_clusters),
                            "observed_clusters": sorted(outcome.observed_clusters),
                            "passive_clusters": sorted(outcome.passive_clusters),
                            "payload_triggered_clusters": sorted(
                                outcome.payload_triggered_clusters),
                            "target_triggered": outcome.target_triggered,
                            "reachability_reward": reward.reachability,
                            "weighted_breadth": reward.weighted_breadth,
                            "breadth_reward": reward.target_gated_breadth,
                            "raw_payload_breadth": reward.raw_payload_breadth,
                            "background_adjusted_breadth": (
                                reward.background_adjusted_breadth),
                            "selective_extra_clusters": list(
                                reward.selective_extra_clusters),
                            "null_threshold": reward.null_threshold,
                            "qualifies_multi_probe": reward.qualifies_multi_probe,
                            "passive_target": reward.passive_target,
                            "reachability_credit_weight": (
                                reward.reachability_credit_weight),
                            "background_artifact_hash": (
                                reward.background_artifact_hash),
                            "credit_weight": reward.credit_weight,
                            "candidate_type": candidate_type,
                            "objective_version": reward.objective_version,
                            "reward_mode": reward_mode,
                            "sampling_policy": getattr(
                                bandit, "sampling_policy", "objective"),
                            "weight_config_hash": worker_weight_hash,
                            
                            "compat_mode": worker_compat.get("applied_mode",
                                                             COMPAT_MODE_NONE),
                            "compat_weight_hash": worker_compat.get("weight_hash", ""),
                            
                            "new_response_patterns": new_packet_patterns,
                            "stored_candidate": stored,
                            "seed_reason": collector.last_seed_reason or "",
                            "reach_rate_cum": metrics.reach_rate,
                            "breadth_mean_cum": metrics.breadth_mean,
                            "valuable_rate_cum": metrics.valuable_rate,
                        })



                metrics.close_batch()
                phase2_elapsed = time.time() - phase2_start
                logger.debug(
                    f"  [SVC-WORKER] batch {batch_idx+1}/{total_batches} "
                    f"Phase 2 done in {phase2_elapsed:.2f}s: "
                    f"{len(multi_probe_packets)} multi-probe"
                )

            _seeds_target = max_seeds_per_seed * len(seeds_data)
            if _seeds_target > 0 and len(new_seeds_data) > _seeds_target * 4:
                new_seeds_data = _select_diverse_seeds(new_seeds_data, _seeds_target)

            # --- Adaptive: per-seed resource adjustment ---
            if v1_adaptive:

                win = metrics.delta_from(seed_metrics_snap)
                cur_fuzz_res, _policy_state = adjust_resource_multiobjective(
                    cur_fuzz_res, metrics,
                    window_new_patterns=win["new_response_patterns"],
                    window_valuable_hits=win["valuable_hits"],
                    prev_breadth_mean=_prev_breadth_mean,
                    strict_target=(
                        metrics.evaluated_mutants >= _v1_params["min_samples"]
                        and metrics.reach_rate <= _v1_strict_reach
                    ),
                    high_weight=(
                        bool(_target_cluster_weight)
                        and _target_cluster_weight >= _v1_high_weight_thr
                    ),
                    **_v1_params,
                )
                if metrics.target_hits > 0:
                    _prev_breadth_mean = metrics.breadth_mean
                logger.info(
                    f"  [SVC-WORKER] {service_name} seed {seed_idx+1} done: "
                    f"{metrics.summary()}, policy={_policy_state}, "
                    f"{len(multi_probe_packets)} multi-probe, "
                    f"mutation_budget→{cur_fuzz_res}"
                )
            else:
                
                hit_rate = compute_hit_rate(multi_probe_packets, service_name)

                cur_fuzz_res = adjust_resource_boofuzz(
                    cur_fuzz_res, hit_rate,
                    config.ADAPTIVE_FUZZ_MIN, config.ADAPTIVE_FUZZ_MAX,
                    config.ADAPTIVE_FUZZ_INCREASE_RATE,
                    config.ADAPTIVE_FUZZ_DECREASE_RATE,
                    config.ADAPTIVE_UPPER_THRESHOLD,
                    config.ADAPTIVE_LOWER_THRESHOLD,
                )

                logger.info(
                    f"  [SVC-WORKER] {service_name} seed {seed_idx+1} done: "
                    f"hit_rate={hit_rate:.2f}, "
                    f"{len(multi_probe_packets)} multi-probe, "
                    f"mutation_budget→{cur_fuzz_res}"
                )

        # Limit new seeds
        if len(new_seeds_data) > max_seeds_per_seed * len(seeds_data):
            limit = max_seeds_per_seed * len(seeds_data)
            logger.info(
                f"[SVC-WORKER] Limiting new seeds: "
                f"{len(new_seeds_data)} → {limit}"
            )
            new_seeds_data = _select_diverse_seeds(new_seeds_data, limit)

        _hb_emitted = collector.emit_high_breadth_seeds(new_seeds_data)
        if _hb_emitted:
            logger.info(
                f"[SVC-WORKER] {service_name}: emitted {_hb_emitted} "
                f"high_breadth seed(s) (worker-local top-K)"
            )

        if v1_adaptive and should_emit_strict_target_seed(
                metrics,
                enabled=_strict_seed_cfg["enabled"],
                reach_threshold=_strict_seed_cfg["reach_threshold"],
                best_exists=_best_strict is not None):
            new_seeds_data.append({
                'packet': _best_strict['packet'],
                'verified_clusters': _best_strict['triggered_clusters'],
                'protocol_name': service_name,
                'seed_reason': SEED_REASON_STRICT_TARGET,
                'target_gated_breadth': _best_strict['breadth'],
                'parent_packet_hash': _best_strict['parent_packet_hash'],
                'parent_seed_id': _best_strict['parent_seed_id'],
            })
            logger.info(
                f"[SVC-WORKER] {service_name}: injected strict_target_seed "
                f"(reach={metrics.reach_rate:.3f} ≤ "
                f"{_strict_seed_cfg['reach_threshold']}, "
                f"breadth={_best_strict['breadth']:.3f})"
            )

        _semantic_emitted = collector.emit_semantic_candidates(candidates_data)
        if _semantic_emitted:
            logger.info(
                f"[SVC-WORKER] {service_name}: emitted {_semantic_emitted} "
                "semantic multi-probe candidate(s)"
            )

        _exploratory_emitted = collector.emit_exploratory_candidates(candidates_data)
        if _exploratory_emitted:
            logger.info(
                f"[SVC-WORKER] {service_name}: emitted {_exploratory_emitted} "
                "exploratory multi-probe candidate(s)"
            )

    except Exception as e:
        worker_failed = True
        worker_error = repr(e)
        candidate_writer.errors += 1
        logger.error(f"[SVC-WORKER] Error in {service_name}: {e}")
        import traceback
        logger.error(f"[SVC-WORKER] Traceback: {traceback.format_exc()}")

    logger.info(
        f"[SVC-WORKER] {service_name} complete: "
        f"{len(candidates_data) + candidate_writer.records} candidates, "
        f"{len(new_seeds_data)} seeds, "
        f"final mutation_budget={cur_fuzz_res}"
        f" | collect[{collector.stats.summary()}]"
    )



    reward_logger.close()
    reward_log = reward_logger.manifest_entry()
    candidate_writer.close()
    candidate_stream = candidate_writer.manifest_entry()
    if dedup_ledger is not None:
        # A claim becomes completed only after all worker-local durable streams
        # and deferred semantic top-K candidates have been finalized.  On any
        # worker error claims remain pending and become recoverable by lease.
        if not worker_failed:
            completed = dedup_ledger.complete_hashes(
                sorted(pending_completion_hashes),
                attempt_epoch=attempt_epoch,
                transport=transport,
                mutation_target=service_name,
            )
            if completed != len(pending_completion_hashes):
                dedup_ledger.close()
                raise RuntimeError(
                    "dedup final completion mismatch: "
                    f"{completed}/{len(pending_completion_hashes)}"
                )
        dedup_ledger.close()


    return ServiceTaskResult(
        service_name=service_name,
        candidates=candidates_data,
        new_seeds=new_seeds_data,
        final_fuzz_resource=cur_fuzz_res,
        final_bandit_state=(
            pickle.dumps(bandit) if bandit is not None else None
        ),
        seed_count=len(seeds_data),
        task_id=task_id,
        reward_log_path=reward_log["path"],
        reward_log_events=reward_log["events"],
        reward_log_errors=reward_log["errors"],
        candidate_stream_path=candidate_stream["path"],
        candidate_stream_records=candidate_stream["records"],
        candidate_stream_errors=candidate_stream["errors"],
        compat_mode=str(worker_compat.get("applied_mode", COMPAT_MODE_NONE)),
        compat_weight_hash=str(worker_compat.get("weight_hash", "")),
        metrics=metrics,
        target_hit_clusters=_target_hit_clusters,
        generated_mutants=generated_mutants,
        sent_mutants=sent_mutants,
        dedup_skips=dedup_skips,
        phase0_generated_packets=phase0_generated_packets,
        phase0_sent_packets=phase0_sent_packets,
        phase0_dedup_skips=phase0_dedup_skips,
        worker_failed=worker_failed,
        worker_error=worker_error,
    )

@dataclass
class FingerprintCandidate:
    """
    A packet that triggered responses from multiple services
    """
    packet: bytes
    responses: List[ServiceResponse]
    origin_protocol: str
    iteration: int
    transport: str = ""  
    triggered_services: Set[str] = field(default_factory=set)
    triggered_clusters: Set[str] = field(default_factory=set)
    observed_clusters: Set[str] = field(default_factory=set)
    passive_clusters: Set[str] = field(default_factory=set)
    payload_triggered_clusters: Set[str] = field(default_factory=set)

    mutation_target: str = ""
    candidate_type: str = CANDIDATE_MULTI_PROBE

    def __post_init__(self):
        """Derive observed, passive and post-send service sets from the actual responses."""
        self.triggered_services = {r.service_name for r in self.responses if r.response_bytes}
        self.observed_clusters = observed_clusters_from(self.responses)
        self.passive_clusters = passive_clusters_from(self.responses)
        self.payload_triggered_clusters = payload_triggered_clusters_from(self.responses)
        self.triggered_clusters = set(self.observed_clusters)

class FuzzingOrchestrator:
    """
    Main orchestrator for fuzzing campaigns.

    Manages the entire process:
    1. Generate mutations via reinforcement learning
    2. Test mutations against services
    3. Collect successful candidates
    4. Adaptively adjust resources per service
    """

    def __init__(
        self,
        protocol_specs: Dict[str, UnifiedProtocolSpec],
        services: Dict[str, tuple],
        max_iterations: int = 3,
        max_mutations_per_seed: int = 1000,
        seeds_file: str = None,
        test_packets: bool = True,
        # Multi-round iteration settings
        fingerprint_collection_threshold: int = 2,
        seed_selection_threshold: int = 2,
        max_seeds_per_group: int = 5,
        seed_selection_strategy: str = 'hash',
        transport: str = ""
    ):
        """
        Args:
            protocol_specs: Dict of protocol_name -> spec
            services: Dict of service_name -> (host, port)
            max_iterations: Max fuzzing iterations
            max_mutations_per_seed: Mutations to generate per seed
            seeds_file: File path to save candidate seeds (optional)
            test_packets: If True, send packets to services and collect records under
                         the campaign's resolved qualification. If False, return mutations.
            fingerprint_collection_threshold: Static V0/legacy observed-cluster threshold;
                         Background-adjusted search uses RewardBreakdown.qualifies_multi_probe.
            seed_selection_threshold: Minimum responses to select as seed for next round
            max_seeds_per_group: Maximum seeds to keep per response group
            seed_selection_strategy: Strategy for selecting seeds ('hash' or 'random')
        """
        # main.py already selects profiles; enforce the same boundary for
        # embedding/offline callers. Selection is idempotent for pinned specs.
        self.protocol_specs = {
            name: (spec.for_transport(transport)
                   if transport in ("tcp", "udp")
                   and getattr(spec, "profile_version", "legacy") != "legacy"
                   else spec)
            for name, spec in protocol_specs.items()
        }
        self.services = services
        self.max_iterations = max_iterations
        self.max_mutations = max_mutations_per_seed
        self.seeds_file = seeds_file
        self.test_packets = test_packets

        # Multi-round iteration settings
        self.fingerprint_collection_threshold = fingerprint_collection_threshold
        self.seed_selection_threshold = seed_selection_threshold
        self.max_seeds_per_group = max_seeds_per_group
        self.seed_selection_strategy = seed_selection_strategy

        self._transport = transport

    def run_campaign(
        self,
        initial_seeds: List[SeedRecord],
        protocol_names: Optional[List[str]] = None,
        num_workers: int = 4
    ) -> List[FingerprintCandidate]:
        """
        Run fuzzing campaign with response-based grouping and selection

        Args:
            initial_seeds: Starting seed records (with verified services)
            protocol_names: Protocols to fuzz with (None = all)
            num_workers: Number of parallel workers for fuzzing

        Returns:
            In-memory candidate records (streamed records are exported separately)
        """
        if protocol_names is None:
            protocol_names = list(self.protocol_specs.keys())

        run_id = (
            f"{time.strftime('%Y%m%dT%H%M%S')}_pid{os.getpid()}_"
            f"{time.time_ns() % 1_000_000_000:09d}"
        )
        reward_log_entries: List[Dict] = []

        logger.info(f"Starting campaign with {len(initial_seeds)} seeds")
        logger.info(f"Mutation targets: {protocol_names}")
        logger.info(f"Test packets: {self.test_packets}")
        logger.info(
            f"Legacy/static collection threshold: "
            f"{self.fingerprint_collection_threshold} observed clusters")
        logger.info(
            f"Legacy/static seed threshold: {self.seed_selection_threshold} "
            "observed clusters")
        logger.info(f"Max seeds per group: {self.max_seeds_per_group}")
        logger.info(f"Parallel workers: {num_workers}")

        reward_mode = getattr(config, 'REWARD_MODE', REWARD_MODE_TARGET_ONLY)
        _w_alpha = float(getattr(config, 'SERVICE_WEIGHT_PREVALENCE_ALPHA', 0.7))
        weight_hash = weight_config_hash(prevalence_alpha=_w_alpha)
        _universe = ({cluster_of(name) for name in self.services}
                     if self.services else set())
        _universe_n = len(_universe)

        background_profile = None
        background_manifest = {
            "enabled": False,
            "artifact_path": "",
            "artifact_hash": "",
            "service_topology_hash": "",
            "response_phase_schema_version": int(getattr(
                config, "RESPONSE_PHASE_SCHEMA_VERSION", 2)),
        }
        state_metadata = None
        if reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED:
            if self._transport not in ("tcp", "udp"):
                raise ValueError(
                    "background_adjusted_breadth requires an explicit tcp/udp campaign"
                )
            _background_path = getattr(config, "BACKGROUND_PROFILE_FILE", "")
            if not _background_path:
                raise ValueError("BACKGROUND_PROFILE_FILE is required for background-adjusted search")
            _topology_hash = service_topology_hash(config.SERVICES)
            background_profile = BackgroundProfile.load(
                _background_path,
                expected_objective_version=getattr(config, "OBJECTIVE_VERSION", None),
                expected_service_topology_hash=_topology_hash,
                expected_weight_config_hash=weight_hash,
            )
            if self._transport not in background_profile.entries:
                raise ValueError(
                    f"background profile has no {self._transport!r} calibration"
                )
            background_manifest.update({
                "enabled": True,
                "artifact_path": _background_path,
                "artifact_hash": background_profile.artifact_hash,
                "service_topology_hash": _topology_hash,
            })
            state_metadata = BanditStateMetadata(
                objective_version=getattr(config, "OBJECTIVE_VERSION", ""),
                service_topology_hash=_topology_hash,
                weight_config_hash=weight_hash,
                background_artifact_hash=background_profile.artifact_hash,
                response_phase_schema_version=background_manifest[
                    "response_phase_schema_version"],
            )

        # （schema/model/hash/transport/universe/objective_version/heuristic

        _compat_mode = getattr(config, 'COMPATIBILITY_PRIOR_MODE', COMPAT_MODE_NONE)
        if _compat_mode not in VALID_COMPAT_MODES:
            raise ValueError(
                f"COMPATIBILITY_PRIOR_MODE must be one of {VALID_COMPAT_MODES}, "
                f"got {_compat_mode!r}")
        _compat_epsilon = float(getattr(config, 'COMPATIBILITY_EPSILON', 0.1))
        if _compat_mode != COMPAT_MODE_NONE:
            validate_epsilon(_compat_epsilon)
        _compat_artifact_hash = ""
        _compat_artifact_objective_version = ""
        _compat_artifact_heuristic_hash = ""
        _compat_artifact_algorithm_version = None
        _compat_expected_subset_digests: Dict[str, str] = {}
        _compat_expected_subset_digest_hash = ""
        _compat_effective_mode = _compat_mode
        if _compat_mode != COMPAT_MODE_NONE and reward_mode == REWARD_MODE_TARGET_ONLY:
            logger.warning(
                "[COMPAT] COMPATIBILITY_PRIOR_MODE=%s has no effect under "
                "reward_mode=target_only (no breadth head) — manifest "
                "records effective_mode=none", _compat_mode)
            _compat_effective_mode = COMPAT_MODE_NONE
        if (_compat_mode == COMPAT_MODE_CALIBRATED
                and reward_mode != REWARD_MODE_TARGET_ONLY):
            _artifact_path = getattr(config, 'COMPATIBILITY_PRIOR_ARTIFACT', '')

            _compat_expected_subset_digests = heuristic_spec_digests(
                self.protocol_specs)
            _compat_expected_subset_digest_hash = heuristic_config_hash(
                self.protocol_specs)

            _artifact = load_calibration_artifact(
                _artifact_path,
                transport=self._transport,
                expected_universe=_universe,
                strict=bool(getattr(
                    config, 'COMPATIBILITY_STRICT_VALIDATION', True)),
                expected_objective_version=getattr(
                    config, 'OBJECTIVE_VERSION', None),
                expected_spec_digests=_compat_expected_subset_digests,
                expected_heuristic_algorithm_version=HEURISTIC_ALGORITHM_VERSION,
            )
            if _artifact is not None:
                _compat_artifact_hash = _artifact.artifact_hash
                _compat_artifact_objective_version = \
                    _artifact.objective_version or ""
                _compat_artifact_heuristic_hash = \
                    _artifact.heuristic_config_hash
                _compat_artifact_algorithm_version = \
                    _artifact.heuristic_algorithm_version
            else:
                _compat_effective_mode = COMPAT_MODE_NONE
        compat_manifest = {
            "mode": _compat_mode,
            "effective_mode": _compat_effective_mode,
            "epsilon": _compat_epsilon,
            "artifact_path": (getattr(config, 'COMPATIBILITY_PRIOR_ARTIFACT', '')
                              if _compat_mode == COMPAT_MODE_CALIBRATED else ""),
            "artifact_hash": _compat_artifact_hash,
            
            "artifact_objective_version": _compat_artifact_objective_version,
            "artifact_heuristic_config_hash": _compat_artifact_heuristic_hash,
            "artifact_heuristic_algorithm_version":
                _compat_artifact_algorithm_version,
            "expected_objective_version": getattr(
                config, 'OBJECTIVE_VERSION', '') or '',
            "expected_heuristic_algorithm_version": HEURISTIC_ALGORITHM_VERSION,

            "expected_subset_spec_digest_hash": _compat_expected_subset_digest_hash,
            "expected_subset_spec_count": len(_compat_expected_subset_digests),
            "strict_validation": bool(getattr(
                config, 'COMPATIBILITY_STRICT_VALIDATION', True)),
            "target_weight_hashes": {},   
        }
        logger.info(
            f"[OBJECTIVE] objective_version={getattr(config, 'OBJECTIVE_VERSION', 'target_only_v0')} "
            f"reward_mode={reward_mode} "
            f"lambda_breadth={getattr(config, 'LAMBDA_BREADTH', 0.5)} "
            f"credit={getattr(config, 'MULTI_FIELD_CREDIT_MODE', 'shared')} "
            f"weight_hash={weight_hash} (alpha={_w_alpha}, "
            f"probe_universe={_universe_n} clusters, transport={self._transport or 'n/a'}) "
            f"compat_mode={_compat_mode} (effective={_compat_effective_mode}, "
            f"epsilon={_compat_epsilon}, "
            f"artifact={_compat_artifact_hash or 'n/a'})"
        )

        # ========== Track seeds grouped by response combination ==========
        # key: frozenset of service names (e.g., frozenset({'mqtt', 'amqp'}))
        # value: List[SeedRecord]
        seeds_by_response_group: Dict[frozenset, List[SeedRecord]] = {}

        # Initialize: put initial seeds in empty response group
        if initial_seeds:
            seeds_by_response_group[frozenset()] = initial_seeds

        # Collect in-memory candidate records (streamed records remain on disk).
        all_candidates: List[FingerprintCandidate] = []

        # All collected mutations (when test_packets=False)
        all_mutations: List[SeedRecord] = []

        # Per-service ReinforcementLearningBandit state, inherited across iterations
        self._bandits: Dict[str, 'ReinforcementLearningBandit'] = {}

        # Load persisted bandit state (if any).  Background-adjusted search uses
        # the transport-separated schema-v3 envelope and full artifact identity;
        # legacy/target-gated profiles use ReinforcementLearningBandit's schema version 2 envelope.
        # Legacy flat state is admitted only behind the explicit migration gate.
        state_file = getattr(config, 'RL_STATE_FILE', None)
        # Field anchors/encodings changed in documented profiles. Old posteriors
        # must not silently become evidence about new fields.
        _documented_specs = any(getattr(s, "profile_version", "legacy") != "legacy"
                                for s in self.protocol_specs.values())
        _state_spec_digests = heuristic_spec_digests(self.protocol_specs) if _documented_specs else None
        if (state_file and reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED
                and state_metadata is not None):
            from core.reinforcement_learning import ReinforcementLearningBandit
            # Missing file/namespace is a valid cold start.  An existing but
            # incompatible envelope raises from load_v3_transport_state and is
            # intentionally not caught here.
            loaded = load_v3_transport_state(
                state_file,
                transport=self._transport,
                expected=state_metadata,
                reward_mode=reward_mode,
                expected_spec_digests=_state_spec_digests,
            )
            if loaded is not None:
                decay = float(getattr(config, 'RL_DECAY', 1.0))
                if _apply_loaded_bandit_decay(loaded, decay):
                    logger.info(
                        "[BANDIT] Applied decay=%s to loaded schema-v3 %s state",
                        decay, self._transport,
                    )
                for (svc, _), _arm in loaded.state.items():
                    if svc not in self._bandits:
                        self._bandits[svc] = ReinforcementLearningBandit(
                            reward_mode=reward_mode,
                            objective_version=getattr(config, 'OBJECTIVE_VERSION', None),
                        )
                for (svc, fname), arm in loaded.state.items():
                    self._bandits[svc].state[(svc, fname)] = arm
                logger.info(
                    "[BANDIT] Loaded schema-v3 %s state from %s: %d arms",
                    self._transport, state_file, len(loaded.state),
                )
        elif state_file and os.path.exists(state_file):
            if _state_spec_digests is not None:
                with open(state_file, encoding="utf-8") as _state_handle:
                    _state_envelope = json.load(_state_handle)
                if _state_envelope.get("spec_digests") != _state_spec_digests:
                    raise ValueError("Legacy/V1 state lacks matching repaired spec digests; use a fresh state file")
            try:
                from core.reinforcement_learning import ReinforcementLearningBandit
                loaded = ReinforcementLearningBandit.load_from_file(
                    state_file,
                    expected_objective_version=getattr(config, 'OBJECTIVE_VERSION', None),
                    expected_weight_hash=weight_hash,
                    allow_legacy_migration=getattr(
                        config, 'RL_STATE_ALLOW_LEGACY_MIGRATION', False),
                    strict=getattr(config, 'RL_STATE_STRICT_VALIDATION', True),
                )
                for (svc, _), _ in loaded.state.items():
                    if svc not in self._bandits:
                        self._bandits[svc] = ReinforcementLearningBandit()
                for (svc, fname), arm in loaded.state.items():
                    self._bandits[svc].state[(svc, fname)] = arm
                logger.info(
                    f"[BANDIT] Loaded state from {state_file}: "
                    f"{len(loaded.state)} arms across {len(self._bandits)} services "
                    f"(objective_version={loaded.objective_version}, "
                    f"weight_config_hash={loaded.weight_config_hash or 'n/a'})"
                )

                # Scheme B: decay learned observations toward prior so past
                # campaigns' failures don't permanently suppress fields.
                decay = float(getattr(config, 'RL_DECAY', 1.0))
                if decay < 1.0 and self._bandits:
                    for b in self._bandits.values():
                        b.decay_toward_prior(decay)
                    logger.info(
                        f"[BANDIT] Applied decay={decay} to loaded state "
                        f"(each arm's learned obs retained at {decay:.0%})"
                    )
            except Exception as e:
                logger.warning(f"[BANDIT] Failed to load state from {state_file}: {e}")

        self.stop_round_metrics: List = []
        stop_tracker = None
        covered_clusters: Set[str] = set()
        if getattr(config, 'ADAPTIVE_OBJECTIVE_MODE', ADAPTIVE_MODE_LEGACY) == ADAPTIVE_MODE_MULTIOBJECTIVE:
            stop_tracker = EarlyStopTracker(
                enabled=bool(getattr(config, 'EARLY_STOP_ENABLED', True)),
                patience=int(getattr(config, 'EARLY_STOP_PATIENCE', 2)),
                min_rounds=int(getattr(config, 'EARLY_STOP_MIN_ROUNDS', 2)),
                min_new_clusters=int(getattr(config, 'EARLY_STOP_MIN_NEW_CLUSTERS', 1)),
                min_new_patterns=int(getattr(config, 'EARLY_STOP_MIN_NEW_PATTERNS', 1)),
                min_breadth_improvement=float(
                    getattr(config, 'EARLY_STOP_MIN_BREADTH_IMPROVEMENT', 0.005)),
                min_reach_improvement=float(
                    getattr(config, 'EARLY_STOP_MIN_REACH_IMPROVEMENT', 0.005)),
            )

        # ===== Round-boundary recovery =====
        # Checkpoint compatibility intentionally excludes max_iterations, so a
        # validated MAX_ITERATIONS=1 run can later continue with 2.
        checkpoint = None
        checkpoint_enabled = bool(getattr(
            config, "CAMPAIGN_CHECKPOINT_ENABLED", False)) and self.test_packets
        checkpoint_signature = build_campaign_signature(
            transport=self._transport,
            protocols=list(protocol_names),
            services=list(self.services.keys()),
            objective_version=getattr(config, "OBJECTIVE_VERSION", ""),
            weight_config_hash=weight_hash,
            fingerprint_threshold=self.fingerprint_collection_threshold,
            seed_threshold=self.seed_selection_threshold,
            spec_digests=_state_spec_digests,
            state_identity=(state_metadata.to_dict()
                            if _documented_specs and state_metadata is not None
                            else None),
        )
        if checkpoint_enabled:
            checkpoint = CampaignCheckpoint(
                getattr(
                    config, "CAMPAIGN_CHECKPOINT_DIR",
                    os.path.join(getattr(config, "CACHE_DIR", ".cache"),
                                 "campaign_checkpoints"),
                ),
                checkpoint_signature,
            )

        # Controller must exist before a resumed iteration > 0 starts.
        from core.adaptive import AdaptiveController
        if not hasattr(self, '_adaptive_controller'):
            _v1_weights = None
            if (getattr(config, 'ADAPTIVE_OBJECTIVE_MODE', ADAPTIVE_MODE_LEGACY)
                    == ADAPTIVE_MODE_MULTIOBJECTIVE and self.services):
                _v1_weights = compute_cluster_weights(
                    {cluster_of(name) for name in self.services},
                    prevalence_alpha=float(getattr(
                        config, 'SERVICE_WEIGHT_PREVALENCE_ALPHA', 0.7)),
                )
            self._adaptive_controller = AdaptiveController.from_config(
                list(self.protocol_specs.keys()), cluster_weights=_v1_weights)

        self.candidate_stream_entries: List[Dict] = []
        start_iteration = 0
        if (checkpoint is not None
                and bool(getattr(config, "CAMPAIGN_RESUME", False))):
            restored = checkpoint.load()
            if restored is not None:
                run_id = restored.get("run_id") or run_id
                start_iteration = int(restored.get("next_iteration", 0))
                seeds_by_response_group = restored.get(
                    "seeds_by_response_group", seeds_by_response_group)
                self._bandits = restored.get("bandits", self._bandits)
                self._adaptive_controller = restored.get(
                    "adaptive_controller", self._adaptive_controller)
                stop_tracker = restored.get("stop_tracker", stop_tracker)
                covered_clusters = set(restored.get("covered_clusters", set()))
                self.stop_round_metrics = restored.get("stop_round_metrics", [])
                reward_log_entries = restored.get("reward_log_entries", [])
                self.candidate_stream_entries = restored.get(
                    "candidate_stream_entries", [])
                logger.info(
                    "[CHECKPOINT] resumed %s at iteration %d with %d seeds, "
                    "%d candidate streams",
                    checkpoint.state_path,
                    start_iteration + 1,
                    sum(len(items) for items in seeds_by_response_group.values()),
                    len(self.candidate_stream_entries),
                )

        for iteration in range(start_iteration, self.max_iterations):
            logger.info(f"\n{'='*60}")
            logger.info(f"ITERATION {iteration + 1}/{self.max_iterations}")
            logger.info(f"{'='*60}")
            # A failed/incomplete run gets a new run_id on restart and therefore
            # a fresh epoch; a checkpoint-resumed run retains run_id but advances
            # iteration.  Old pending/completed claims can never suppress data
            # belonging to a different complete-round attempt.
            _attempt_epoch = f"{run_id}:{self._transport}:iteration-{iteration:04d}"
            # Count total seeds and summarize groups
            total_seeds = sum(len(seeds) for seeds in seeds_by_response_group.values())
            non_empty_groups = sum(1 for key in seeds_by_response_group if key)
            logger.info(f"Starting with {len(seeds_by_response_group)} response groups ({non_empty_groups} non-empty), {total_seeds} seeds total")

            # Track new seeds for next iteration (grouped by response combination)
            new_seeds_by_group: Dict[frozenset, List[SeedRecord]] = {}
            
            stop_info = None

            # ========== PARALLEL PROCESSING ==========
            
            global _worker_protocol_specs, _worker_services
            _worker_protocol_specs = self.protocol_specs
            _worker_services = self.services

            # ============================================================
            
            # ============================================================
            
            if not hasattr(self, '_adaptive_controller'):

                _v1_weights = None
                if (getattr(config, 'ADAPTIVE_OBJECTIVE_MODE', ADAPTIVE_MODE_LEGACY)
                        == ADAPTIVE_MODE_MULTIOBJECTIVE and self.services):
                    _v1_weights = compute_cluster_weights(
                        {cluster_of(name) for name in self.services},
                        prevalence_alpha=float(getattr(
                            config, 'SERVICE_WEIGHT_PREVALENCE_ALPHA', 0.7)),
                    )
                self._adaptive_controller = AdaptiveController.from_config(
                    list(self.protocol_specs.keys()),
                    cluster_weights=_v1_weights,
                )

            controller = self._adaptive_controller

            service_seeds = build_service_seeds(
                seeds_by_response_group, protocol_names, self.protocol_specs)

            if not service_seeds:
                logger.info("No tasks to process, stopping early")
                break

            svc_tasks = []

            parent_records_by_id: Dict[str, Dict[str, SeedRecord]] = {}
            parent_records_by_hash: Dict[str, Dict[str, SeedRecord]] = {}
            for svc_name, svc_seed_list in service_seeds.items():
                fuzz_res = controller.get_fuzz_resource(svc_name)
                seeds_data = [pkt for pkt, _ in svc_seed_list]
                seed_ids = [
                    f"it{iteration:02d}:{svc_name}:{i:05d}"
                    for i in range(len(svc_seed_list))
                ]
                by_id: Dict[str, SeedRecord] = {}
                by_hash: Dict[str, SeedRecord] = {}
                for pid, (_pkt, _rec) in zip(seed_ids, svc_seed_list):
                    by_id[pid] = _rec
                    by_hash.setdefault(packet_hash_of(_pkt), _rec)  
                parent_records_by_id[svc_name] = by_id
                parent_records_by_hash[svc_name] = by_hash

                # Pickle this service's bandit for the worker
                # If this is a new service (no prior bandit), create a fresh one
                bandit_bytes = None
                if getattr(config, 'RL_ENABLED', False):
                    from core.reinforcement_learning import ReinforcementLearningBandit
                    existing = self._bandits.get(svc_name)
                    if existing is None:
                        existing = ReinforcementLearningBandit()
                        self._bandits[svc_name] = existing
                        logger.info(
                            f"  [BANDIT] Created fresh bandit for new service: {svc_name}"
                        )
                    bandit_bytes = pickle.dumps(existing)

                batch_count = getattr(config, 'SEED_BATCH_COUNT', 1)
                if batch_count <= 1 or len(seeds_data) <= 1:
                    task_meta = {
                        "run_id": run_id,
                        "task_id": f"iter{iteration:02d}_task{len(svc_tasks):05d}",
                        "transport": self._transport,
                        "parent_seed_ids": seed_ids,
                        "attempt_epoch": _attempt_epoch,
                        "dedup_ledger_path": getattr(
                            config, "DEDUP_LEDGER_FILE", ""),
                        "test_packets": self.test_packets,
                    }
                    task = (
                        svc_name,
                        seeds_data,
                        fuzz_res,
                        iteration,
                        self.fingerprint_collection_threshold,
                        self.seed_selection_threshold,
                        self.max_seeds_per_group,
                        bandit_bytes,
                        task_meta,
                    )
                    svc_tasks.append(task)
                else:
                    seeds_per_batch = math.ceil(len(seeds_data) / batch_count)
                    for i in range(0, len(seeds_data), seeds_per_batch):
                        batch = seeds_data[i:i + seeds_per_batch]
                        task_meta = {
                            "run_id": run_id,
                            "task_id": f"iter{iteration:02d}_task{len(svc_tasks):05d}",
                            "transport": self._transport,
                            "parent_seed_ids": seed_ids[i:i + seeds_per_batch],
                            "attempt_epoch": _attempt_epoch,
                            "dedup_ledger_path": getattr(
                                config, "DEDUP_LEDGER_FILE", ""),
                            "test_packets": self.test_packets,
                        }
                        task = (
                            svc_name,
                            batch,
                            fuzz_res,
                            iteration,
                            self.fingerprint_collection_threshold,
                            self.seed_selection_threshold,
                            self.max_seeds_per_group,
                            bandit_bytes,
                            task_meta,
                        )
                        svc_tasks.append(task)

            logger.info(
                f"Adaptive mode: {len(svc_tasks)} service-level tasks, "
                f"resources: {controller.get_state_summary()}"
            )

            effective_workers = min(num_workers, len(svc_tasks))

            start_time = time.time()
            svc_results: List[ServiceTaskResult] = []

            if effective_workers > 1 and len(svc_tasks) > 1:
                try:
                    ctx = multiprocessing.get_context('fork')
                    with ctx.Pool(
                        processes=effective_workers,
                        initializer=_init_worker,
                        initargs=(self.protocol_specs, self.services)
                    ) as pool:
                        svc_results = list(tqdm(
                            pool.imap_unordered(service_fuzz_worker, svc_tasks),
                            total=len(svc_tasks),
                            desc="Fuzzing (adaptive)",
                            unit="svc",
                            ncols=80, leave=True, mininterval=2,
                            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
                        ))
                except Exception as e:
                    logger.error(f"Parallel processing error: {e}")
                    if not _allow_sequential_pool_fallback(reward_mode):
                        raise RuntimeError(
                            "background-adjusted search parallel worker pool failed; refusing a "
                            "sequential replay because prior workers may have "
                            "already completed send-ledger transactions"
                        ) from e
                    logger.warning(
                        "Legacy reward mode: retrying all tasks sequentially "
                        "after worker-pool failure"
                    )
                    for task in tqdm(svc_tasks, desc="Fuzzing (adaptive)",
                                     ncols=100, leave=True):
                        svc_results.append(service_fuzz_worker(task))
            else:
                for task in tqdm(svc_tasks, desc="Fuzzing (adaptive)",
                                 ncols=100, leave=True):
                    svc_results.append(service_fuzz_worker(task))

            elapsed = time.time() - start_time
            logger.info(
                f"Mutation task processing completed in {elapsed:.2f}s "
                f"({len(svc_tasks)} service/seed-batch tasks)"
            )

            require_complete_worker_transactions(svc_results, reward_mode)

            svc_batch_results = defaultdict(list)

            svc_round_metrics: Dict[str, List[AdaptiveMetrics]] = defaultdict(list)
            strict_seed_pool: Dict[str, List[dict]] = defaultdict(list)
            high_breadth_pool: Dict[str, List[dict]] = defaultdict(list)
            mp_seed_hashes: Dict[str, Set[str]] = defaultdict(set)

            for svc_result in svc_results:
                svc_name = svc_result.service_name
                parent_seeds = service_seeds.get(svc_name, [])
                parent_by_id = parent_records_by_id.get(svc_name, {})
                parent_by_hash = parent_records_by_hash.get(svc_name, {})
                fallback_parent = parent_seeds[0][1] if parent_seeds else None
                if svc_result.metrics is not None:
                    svc_round_metrics[svc_name].append(svc_result.metrics)

                batch_seed_count = svc_result.seed_count
                svc_batch_results[svc_name].append((
                    svc_result.final_fuzz_resource,
                    batch_seed_count,
                ))
                if svc_result.reward_log_path or svc_result.reward_log_errors:
                    reward_log_entries.append({
                        "task_id": svc_result.task_id,
                        "service": svc_name,
                        "iteration": iteration,
                        "transport": self._transport,
                        "seed_count": svc_result.seed_count,
                        "path": svc_result.reward_log_path,
                        "events": svc_result.reward_log_events,
                        "errors": svc_result.reward_log_errors,
                    })
                if svc_result.candidate_stream_path:
                    stream_entry = {
                        "task_id": svc_result.task_id,
                        "service": svc_name,
                        "iteration": iteration,
                        "transport": self._transport,
                        "path": svc_result.candidate_stream_path,
                        "records": svc_result.candidate_stream_records,
                        "errors": svc_result.candidate_stream_errors,
                    }
                    if svc_result.candidate_stream_errors:
                        logger.warning(
                            "[CANDIDATE-STREAM] task=%s completed with %d errors; "
                            "file is not authoritative",
                            svc_result.task_id,
                            svc_result.candidate_stream_errors,
                        )
                    else:
                        self.candidate_stream_entries.append(stream_entry)

                if svc_result.compat_weight_hash:
                    compat_manifest["target_weight_hashes"][svc_name] = \
                        svc_result.compat_weight_hash

                for c_data in svc_result.candidates:
                    if not self.test_packets or not c_data.get('responses'):
                        parent = resolve_parent_seed(
                            c_data, parent_by_id, parent_by_hash,
                            fallback_parent)
                        new_record = SeedRecord(
                            packet=c_data['packet'],
                            verified_services=set(),
                            fuzzed_protocols=(
                                parent.fuzzed_protocols | {svc_name}
                                if parent else {svc_name}
                            ),
                        )
                        all_mutations.append(new_record)
                        continue

                    responses = responses_from_candidate_data(c_data)

                    mt = str(c_data.get('mutation_target') or '')
                    candidate = FingerprintCandidate(
                        packet=c_data['packet'],
                        responses=responses,
                        origin_protocol=mt,
                        iteration=c_data['iteration'],
                        transport=self._transport,
                        mutation_target=mt,
                        candidate_type=c_data.get('candidate_type', CANDIDATE_MULTI_PROBE),
                    )
                    all_candidates.append(candidate)

                if self.test_packets:
                    for s_data in svc_result.new_seeds:
                        reason = s_data.get('seed_reason') or SEED_REASON_MULTI_PROBE
                        
                        if reason == SEED_REASON_STRICT_TARGET:
                            strict_seed_pool[svc_name].append(s_data)
                            continue
                        if reason == SEED_REASON_HIGH_BREADTH:
                            high_breadth_pool[svc_name].append(s_data)
                            continue
                        group_key = frozenset(s_data['verified_clusters'])
                        record = seed_record_from_worker_dict(
                            s_data, svc_name, parent_by_id, parent_by_hash,
                            fallback_parent)
                        new_seeds_by_group.setdefault(group_key, []).append(record)
                        
                        mp_seed_hashes[svc_name].add(packet_hash_of(s_data['packet']))

            if self.test_packets and controller.is_v1() and (strict_seed_pool or high_breadth_pool):
                strict_cap = int(getattr(
                    config, 'SEED_STRICT_TARGET_MAX_PER_SERVICE_PER_ROUND', 1))
                hb_cap = int(getattr(
                    config, 'SEED_HIGH_BREADTH_MAX_PER_SERVICE', 2))
                for svc_name in set(strict_seed_pool) | set(high_breadth_pool):
                    parent_by_id = parent_records_by_id.get(svc_name, {})
                    parent_by_hash = parent_records_by_hash.get(svc_name, {})
                    parent_seeds = service_seeds.get(svc_name, [])
                    fallback_parent = parent_seeds[0][1] if parent_seeds else None

                    strict_entries = strict_seed_pool.get(svc_name, [])
                    strict_kept = pick_strict_target_seeds(strict_entries, strict_cap)
                    for s_data in strict_kept:
                        record = seed_record_from_worker_dict(
                            s_data, svc_name, parent_by_id, parent_by_hash,
                            fallback_parent)
                        new_seeds_by_group.setdefault(
                            frozenset(s_data['verified_clusters']), []).append(record)
                    if len(strict_entries) > len(strict_kept):
                        logger.info(
                            f"[SEED] {svc_name}: strict_target_seed "
                            f"{len(strict_entries)} → {len(strict_kept)} (per-round cap)"
                        )

                    hb_entries = high_breadth_pool.get(svc_name, [])
                    hb_kept = pick_high_breadth_seeds(
                        hb_entries, hb_cap,
                        exclude_packet_hashes=mp_seed_hashes.get(svc_name))
                    for s_data in hb_kept:
                        record = seed_record_from_worker_dict(
                            s_data, svc_name, parent_by_id, parent_by_hash,
                            fallback_parent)
                        new_seeds_by_group.setdefault(
                            frozenset(s_data['verified_clusters']), []).append(record)
                    if len(hb_entries) > len(hb_kept):
                        logger.info(
                            f"[SEED] {svc_name}: high_breadth_seed "
                            f"{len(hb_entries)} → {len(hb_kept)} "
                            f"(per-service-per-round global cap)"
                        )

            if getattr(config, "REWARD_LOG_ENABLED", False) and reward_log_entries:
                try:
                    import json as _json
                    manifest_dir = os.path.join(
                        getattr(config, "REWARD_LOG_DIR", os.path.join(config.CACHE_DIR, "reward_events")),
                        run_id,
                    )
                    os.makedirs(manifest_dir, exist_ok=True)
                    manifest_path = os.path.join(manifest_dir, "manifest.json")
                    with open(manifest_path, "w", encoding="utf-8") as fh:
                        _json.dump({
                            "run_id": run_id,
                            "objective_version": getattr(config, "OBJECTIVE_VERSION", ""),
                            "reward_mode": reward_mode,
                            "sampling_policy": getattr(
                                config, "RL_SAMPLING_POLICY", "objective"),
                            "weight_config_hash": weight_hash,
                            "background": background_manifest,
                            "send_dedup": build_send_dedup_manifest(
                                svc_results,
                                enabled=bool(
                                    reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED
                                    and getattr(config, "DEDUP_ENABLED", True)
                                ),
                                attempt_epoch=_attempt_epoch,
                            ),

                            "compat": compat_manifest,
                            "entries": sorted(reward_log_entries, key=lambda e: e["task_id"]),
                        }, fh, indent=2, ensure_ascii=False)
                    logger.info(
                        "[REWARD-LOG] manifest=%s files=%d events=%d errors=%d",
                        manifest_path,
                        len(reward_log_entries),
                        sum(e["events"] for e in reward_log_entries),
                        sum(e["errors"] for e in reward_log_entries),
                    )
                except Exception as exc:
                    logger.warning("[REWARD-LOG] failed to write manifest: %s", exc)

            for svc_name, batches in svc_batch_results.items():
                if len(batches) == 1:
                    controller.update_from_worker(
                        svc_name, batches[0][0]
                    )
                else:
                    controller.update_from_batches(svc_name, batches)

            if controller.is_v1() and svc_round_metrics:
                _pattern_cap = int(getattr(config, 'ADAPTIVE_PATTERN_TRACK_CAP', 4096))
                round_eval = round_hits = 0
                round_breadth_sum = 0.0
                round_patterns = 0
                for svc_name, mlist in svc_round_metrics.items():
                    merged_round = AdaptiveMetrics.merge_many(
                        mlist, pattern_track_cap=_pattern_cap)

                    summary = controller.observe_service_round(
                        svc_name, merged_round, adjust=False)
                    if summary:
                        round_eval += summary["round_evaluated_mutants"]
                        round_hits += summary["round_target_hits"]
                        round_breadth_sum += summary["round_breadth_sum"]
                        round_patterns += summary["round_new_response_patterns"]

                round_useful_clusters = collect_round_useful_clusters(svc_results)
                new_clusters = len(round_useful_clusters - covered_clusters)
                covered_clusters |= round_useful_clusters
                round_reach = (round_hits / round_eval) if round_eval > 0 else 0.0
                round_breadth_mean = (
                    round_breadth_sum / round_hits) if round_hits > 0 else 0.0

                logger.info(
                    f"[ADAPTIVE] campaign round {iteration + 1}: "
                    f"evaluated={round_eval}, reach={round_reach:.3f}, "
                    f"breadth_mean={round_breadth_mean:.3f}, "
                    f"new_patterns={round_patterns}, new_clusters={new_clusters}"
                )
                if stop_tracker is not None:
                    stop_info = stop_tracker.observe_round(
                        iteration=iteration,
                        new_clusters=new_clusters,
                        new_response_patterns=round_patterns,
                        breadth_mean=round_breadth_mean,
                        reach_rate=round_reach,
                    )
                    self.stop_round_metrics.append(stop_info)
                    logger.info(
                        f"[EARLY-STOP] round {iteration + 1}: "
                        f"stalled={stop_info.stalled} "
                        f"streak={stop_info.consecutive_stalled_rounds}"
                        f"/patience={stop_tracker.patience} "
                        f"(new_clusters={new_clusters} "
                        f"new_patterns={round_patterns} "
                        f"breadth_imprv={stop_info.breadth_improvement:.4f} "
                        f"reach_imprv={stop_info.reach_improvement:.4f})"
                    )
                logger.info(
                    f"[ADAPTIVE] per-service metrics after iteration: "
                    f"{controller.get_metrics_summary()}"
                )

            logger.info(
                f"Adaptive resources after iteration: "
                f"{controller.get_state_summary()}"
            )

            if getattr(config, 'RL_ENABLED', False):
                from core.reinforcement_learning import ReinforcementLearningBandit
                bandit_per_svc: dict = defaultdict(list)
                for idx, svc_result in enumerate(svc_results):
                    if svc_result.final_bandit_state is None:
                        continue
                    try:
                        b = pickle.loads(svc_result.final_bandit_state)
                        bandit_per_svc[svc_result.service_name].append(b)
                    except Exception as e:
                        logger.warning(
                            f"  [BANDIT] Failed to unpickle bandit "
                            f"for {svc_result.service_name}: {e}"
                        )
                for svc_name, bandits in bandit_per_svc.items():

                    merged = ReinforcementLearningBandit.merge_bandits(
                        bandits,
                        base_bandit=self._bandits.get(svc_name),
                    )
                    self._bandits[svc_name] = merged
                    logger.info(
                        f"  [BANDIT] {svc_name} reconciled from "
                        f"{len(bandits)} batch(es), "
                        f"{len(merged.field_names(svc_name))} arms"
                    )

            # Save after every iteration.  The formal background-adjusted
            # profile writes transport-separated schema v3; compatibility
            # profiles write the schema version 2 dual-posterior envelope.  Both bind
            # objective/weight identities and are validated on the next load.
            if self._bandits and state_file:
                try:
                    from core.reinforcement_learning import ReinforcementLearningBandit
                    combined = ReinforcementLearningBandit(
                        reward_mode=reward_mode,
                        objective_version=getattr(config, 'OBJECTIVE_VERSION', None),
                    )
                    for svc, b in self._bandits.items():
                        for key, arm in b.state.items():
                            combined.state[key] = arm
                    if (reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED
                            and state_metadata is not None):
                        save_v3_transport_state(
                            state_file,
                            transport=self._transport,
                            bandit=combined,
                            metadata=state_metadata,
                            spec_digests=_state_spec_digests,
                        )
                    else:
                        combined.save_to_file(
                            state_file,
                            objective_version=getattr(config, 'OBJECTIVE_VERSION', None),
                            weight_config_hash=weight_hash,
                            spec_digests=_state_spec_digests,
                        )
                    logger.info(
                        f"[BANDIT] Saved state to {state_file} "
                        f"(objective_version={getattr(config, 'OBJECTIVE_VERSION', '')}, "
                        f"weight_config_hash={weight_hash})"
                    )
                except Exception as e:
                    if reward_mode == REWARD_MODE_BACKGROUND_ADJUSTED:
                        raise
                    logger.warning(f"[BANDIT] Failed to save state: {e}")

            # ========== Bound all_candidates each iteration (anti-OOM) ==========

            if all_candidates:
                _before = len(all_candidates)
                all_candidates = deduplicate_candidates(
                    all_candidates,
                    max_per_pattern=int(getattr(config, 'MAX_FINGERPRINTS_PER_RESPONSE_PATTERN', 1)),
                    strategy=getattr(config, 'SEED_SELECTION_STRATEGY', 'hash'),
                )
                if len(all_candidates) < _before:
                    logger.info(
                        f"  [DEDUP] all_candidates bounded (iter {iteration+1}): "
                        f"{_before} -> {len(all_candidates)}"
                    )

            _malloc_trim()

            # ========== Keep only top N seeds per group ==========
            # Only do seed selection for online mode (with responses)
            stop_after_round = False
            checkpoint_status = "round_complete"
            if self.test_packets:
                seeds_by_response_group = {}
                for group_key, group_seeds in new_seeds_by_group.items():
                    if not group_seeds:
                        continue

                    selected = select_diverse_seeds(
                        group_seeds,
                        max_per_group=self.max_seeds_per_group,
                        strategy=self.seed_selection_strategy
                    )
                    seeds_by_response_group[group_key] = selected

                    if group_key:  # Only log non-empty groups
                        logger.info(
                            f"Group {set(group_key)}: {len(group_seeds)} -> {len(selected)} seeds "
                            f"(retained {len(selected)/len(group_seeds)*100:.1f}%)"
                        )

                # Check if there are new seeds
                total_new_seeds = sum(len(s) for s in seeds_by_response_group.values())
                if total_new_seeds == 0:
                    logger.info("No new seeds generated, stopping early")
                    stop_after_round = True
                    checkpoint_status = "no_new_seeds"
            else:
                # Offline mode: no need for multi-round iteration, stop after first iteration
                logger.info("Offline mode - stopping after first iteration")
                stop_after_round = True
                checkpoint_status = "offline_complete"

            if stop_info is not None and stop_info.should_stop:
                logger.info(f"[EARLY-STOP] stopping campaign: {stop_info.stop_reason}")
                stop_after_round = True
                checkpoint_status = "early_stop"

            if checkpoint is not None:
                manifest = checkpoint.save({
                    "run_id": run_id,
                    "next_iteration": iteration + 1,
                    "seeds_by_response_group": seeds_by_response_group,
                    "bandits": self._bandits,
                    "adaptive_controller": self._adaptive_controller,
                    "stop_tracker": stop_tracker,
                    "covered_clusters": covered_clusters,
                    "stop_round_metrics": self.stop_round_metrics,
                    "reward_log_entries": reward_log_entries,
                    "candidate_stream_entries": self.candidate_stream_entries,
                }, status=checkpoint_status)
                logger.info(
                    "[CHECKPOINT] committed round %d: %s (%d streams, %d records, %d seeds)",
                    iteration + 1,
                    checkpoint.state_path,
                    manifest["candidate_stream_files"],
                    manifest["candidate_stream_records"],
                    manifest["next_seed_count"],
                )

            # Drop every round-sized parent object before a future fork.  This is
            # the critical CoW/OOM boundary: workers in the next round must not
            # inherit ServiceTaskResult lists or deserialized Bandit copies.
            del svc_results
            if 'bandit_per_svc' in locals():
                del bandit_per_svc
            _malloc_trim()

            if stop_after_round:
                break

        if self.test_packets:
            streamed = sum(
                int(entry.get("records", 0))
                for entry in self.candidate_stream_entries)
            logger.info(
                f"\nCampaign complete. Found {len(all_candidates)} in-memory + "
                f"{streamed} streamed candidate records")

            group_counter = Counter()
            for c in all_candidates:
                group_key = tuple(sorted(c.triggered_clusters))
                group_counter[group_key] += 1

            logger.info("\nIn-memory candidates by observed-cluster set:")
            for group, count in group_counter.most_common(20):
                logger.info(f"  {list(group)}: {count} candidates")

            return all_candidates
        else:
            logger.info(f"Campaign complete. Generated {len(all_mutations)} total mutations")
            return all_mutations
