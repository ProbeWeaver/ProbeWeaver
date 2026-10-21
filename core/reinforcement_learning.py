"""Field-level posterior sampling with Reach and Breadth Beta utility heads. Static field scores add Reach prior mass; sampling combines theta_R * (1 + lambda * theta_B). Both heads use the same observations and are not statistically independent. Merge and decay operate on observations above each prior. Selected lengths are deliberately wrong, unselected lengths are repaired, and checksums are always repaired."""

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, TYPE_CHECKING

import numpy as np

from protocol.field import SurvivalType
from core.priority_mapper import PriorityMapper, FieldPlan, encode_int, calc_checksum
from protocol.length_codec import encode_length, decode_length, wrong_lengths
from core.objectives import (
    REWARD_MODE_TARGET_ONLY,
    VALID_REWARD_MODES,
)

if TYPE_CHECKING:
    from core.mutator import FastMutator

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2

_EPS = 1e-9

SAMPLING_POLICY_OBJECTIVE = "objective"
SAMPLING_POLICY_UNIFORM = "uniform"
SAMPLING_POLICY_STATIC_PRIOR = "static_prior"
SAMPLING_POLICY_REACH = "reach_posterior"
SAMPLING_POLICY_DUAL = "dual_posterior"
VALID_SAMPLING_POLICIES = (
    SAMPLING_POLICY_OBJECTIVE,
    SAMPLING_POLICY_UNIFORM,
    SAMPLING_POLICY_STATIC_PRIOR,
    SAMPLING_POLICY_REACH,
    SAMPLING_POLICY_DUAL,
)

def stable_experiment_seed(base_seed: Optional[int], *parts: object) -> Optional[int]:
    """Derive a reproducible independent RNG seed for paired experiments.

    ``None`` deliberately preserves normal non-deterministic operation.  The
    derivation excludes run id so different policy arms can share the same
    random seed while still separating transport/target/task/parent streams.
    """
    if base_seed is None:
        return None
    payload = "\x1f".join([str(int(base_seed)), *(str(part) for part in parts)])
    return int.from_bytes(
        hashlib.sha256(payload.encode("utf-8")).digest()[:8], "big"
    )

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
@dataclass
class BetaArm:
    """One bounded Beta utility head with separately tracked prior mass."""

    alpha: float = 1.0
    beta: float = 1.0
    prior_alpha: float = 1.0
    prior_beta: float = 1.0

    def sample(self, rng: np.random.Generator, temperature: float = 1.0) -> float:
        """Draw one posterior sample from the Beta posterior.

        temperature > 1 widens the distribution (more exploration) by sampling
        from Beta(α/T, β/T) — mean is preserved, variance scales with T.
        See config.RL_TEMPERATURE.
        """
        if temperature == 1.0:
            return float(rng.beta(self.alpha, self.beta))
        return float(rng.beta(self.alpha / temperature, self.beta / temperature))

    @property
    def expectation(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    def update(self, reward: float, weight: float = 1.0) -> None:
        """Update."""
        if not (-_EPS <= reward <= 1.0 + _EPS):
            raise ValueError(f"reward {reward!r} out of [0,1]")
        if not (-_EPS <= weight <= 1.0 + _EPS):
            raise ValueError(f"observation weight {weight!r} out of [0,1]")
        r = min(max(float(reward), 0.0), 1.0)
        w = min(max(float(weight), 0.0), 1.0)
        self.alpha += w * r
        self.beta += w * (1.0 - r)

    def net_observation(self) -> Tuple[float, float]:
        """Return accumulated evidence above the prior for merge and decay."""
        return (self.alpha - self.prior_alpha, self.beta - self.prior_beta)

FieldArm = BetaArm

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
@dataclass
class MultiObjectiveFieldArm:
    """Reach and Breadth state for one service/field pair."""

    reachability: BetaArm
    breadth: BetaArm

    @classmethod
    def from_priors(
        cls,
        reach_prior: Tuple[float, float],
        breadth_prior: Tuple[float, float],
    ) -> "MultiObjectiveFieldArm":
        return cls(
            reachability=BetaArm(
                alpha=reach_prior[0], beta=reach_prior[1],
                prior_alpha=reach_prior[0], prior_beta=reach_prior[1],
            ),
            breadth=BetaArm(
                alpha=breadth_prior[0], beta=breadth_prior[1],
                prior_alpha=breadth_prior[0], prior_beta=breadth_prior[1],
            ),
        )

    def decay_toward_prior(self, decay: float) -> None:
        """Shrink each head toward its own prior without mixing the heads."""
        for head in (self.reachability, self.breadth):
            head.alpha = head.prior_alpha + (head.alpha - head.prior_alpha) * decay
            head.beta = head.prior_beta + (head.beta - head.prior_beta) * decay

    def reset_uniform(self) -> None:
        """Reset both utility heads to Beta(1, 1)."""
        for head in (self.reachability, self.breadth):
            head.alpha = head.beta = head.prior_alpha = head.prior_beta = 1.0

# ---------------------------------------------------------------------------
# Per-service field bandit registry
# ---------------------------------------------------------------------------
class ReinforcementLearningBandit:
    """Per-service, per-field registry of paired utility heads."""

    def __init__(
        self,
        seed: Optional[int] = None,
        reward_mode: Optional[str] = None,
        lambda_breadth: Optional[float] = None,
        breadth_prior: Optional[Tuple[float, float]] = None,
        objective_version: Optional[str] = None,
        sampling_policy: Optional[str] = None,
    ):
        import config as _cfg
        resolved_seed = (
            seed if seed is not None
            else getattr(_cfg, "RL_RANDOM_SEED", None)
        )
        self.rng = np.random.default_rng(resolved_seed)
        policy = (
            sampling_policy if sampling_policy is not None
            else getattr(_cfg, "RL_SAMPLING_POLICY", SAMPLING_POLICY_OBJECTIVE)
        )
        if policy not in VALID_SAMPLING_POLICIES:
            raise ValueError(
                f"unknown posterior sampling policy {policy!r}; expected one of "
                f"{VALID_SAMPLING_POLICIES}"
            )
        self.sampling_policy = policy
        # Sampling-time temperature; 1.0 = untempered posterior sampling.
        self._temperature = float(getattr(_cfg, "RL_TEMPERATURE", 1.0))
        if self._temperature <= 0.0:
            raise ValueError("RL_TEMPERATURE must be > 0")

        mode = reward_mode if reward_mode is not None else getattr(
            _cfg, "REWARD_MODE", REWARD_MODE_TARGET_ONLY)
        if mode not in VALID_REWARD_MODES:
            raise ValueError(
                f"unknown reward mode {mode!r}; expected one of {VALID_REWARD_MODES}")
        self.reward_mode = mode
        self.lambda_breadth = float(
            lambda_breadth if lambda_breadth is not None
            else getattr(_cfg, "LAMBDA_BREADTH", 0.5))
        if self.lambda_breadth < 0.0:
            raise ValueError("lambda_breadth must be >= 0")
        bp = breadth_prior if breadth_prior is not None else getattr(
            _cfg, "BREADTH_PRIOR", (1.0, 1.0))
        if len(bp) != 2:
            raise ValueError("breadth_prior must contain two positive values")
        self.breadth_prior = (float(bp[0]), float(bp[1]))
        if self.breadth_prior[0] <= 0.0 or self.breadth_prior[1] <= 0.0:
            raise ValueError("breadth_prior must contain two positive values")
        self.objective_version = objective_version if objective_version is not None \
            else getattr(_cfg, "OBJECTIVE_VERSION", "target_only_v0")

        self.weight_config_hash: str = ""
        # background-adjusted search: banner-first targets keep mutation tasks but freeze the reach
        # head; their proposal score is driven by breadth only.
        self.passive_services: set[str] = set()

        # (service, field_name) -> MultiObjectiveFieldArm
        self.state: Dict[Tuple[str, str], MultiObjectiveFieldArm] = {}

    # -- arm management ------------------------------------------------------
    def register(self, service: str, field_name: str, score: int) -> None:
        """Idempotent arm registration. Reach prior looked up from score;"""
        key = (service, field_name)
        if key not in self.state:
            self.state[key] = MultiObjectiveFieldArm.from_priors(
                self._score_to_prior(score), self.breadth_prior,
            )

    @staticmethod
    def _score_to_prior(score: int) -> Tuple[float, float]:
        """Map a static priority score to an initial Beta prior (α, β)."""
        import config as _cfg
        mapping = getattr(_cfg, "RL_PRIOR_BY_SCORE", {})
        return mapping.get(score, getattr(_cfg, "RL_PRIOR_DEFAULT", (1.0, 1.0)))

    def register_all(
        self,
        service: str,
        field_plans: List[FieldPlan],
        length_plans: Optional[List[FieldPlan]] = None,
        default_length_score: int = 1,
    ) -> None:
        """Register all manual + length field plans under one service."""
        for p in field_plans:
            self.register(service, p.field.name, p.score or 2)
        for p in (length_plans or []):
            self.register(service, p.field.name, default_length_score)

    # -- sampling ------------------------------------------------------------
    def sample_weights(
        self, service: str, field_names: List[str]
    ) -> List[float]:
        """One posterior sample per field."""
        if self.sampling_policy == SAMPLING_POLICY_UNIFORM:
            return [
                1.0 if (service, field_name) in self.state else 0.0
                for field_name in field_names
            ]
        if self.sampling_policy == SAMPLING_POLICY_STATIC_PRIOR:
            return [
                (
                    arm.reachability.prior_alpha
                    / (arm.reachability.prior_alpha + arm.reachability.prior_beta)
                ) if (arm := self.state.get((service, field_name))) is not None else 0.0
                for field_name in field_names
            ]
        if self.sampling_policy == SAMPLING_POLICY_REACH:
            return [
                self.state[(service, field_name)].reachability.sample(
                    self.rng, self._temperature
                ) if (service, field_name) in self.state else 0.0
                for field_name in field_names
            ]
        if self.sampling_policy == SAMPLING_POLICY_DUAL:
            return self.sample_scores(service, field_names, self.lambda_breadth)
        if self.reward_mode == REWARD_MODE_TARGET_ONLY:
            return [
                self.state[(service, f)].reachability.sample(self.rng, self._temperature)
                if (service, f) in self.state
                else 0.0
                for f in field_names
            ]
        return self.sample_scores(service, field_names, self.lambda_breadth)

    def sample_scores(
        self,
        service: str,
        field_names: List[str],
        lambda_breadth: Optional[float] = None,
    ) -> List[float]:
        """Combine sampled utilities as theta_R * (1 + lambda * theta_B)."""
        lam = self.lambda_breadth if lambda_breadth is None else float(lambda_breadth)
        arms = [self.state.get((service, f)) for f in field_names]
        theta_r = [
            a.reachability.sample(self.rng, self._temperature) if a is not None else 0.0
            for a in arms
        ]
        theta_b = [
            a.breadth.sample(self.rng, self._temperature) if a is not None else 0.0
            for a in arms
        ]
        if service in self.passive_services:
            return [
                1.0 + lam * b if arm is not None else 0.0
                for arm, b in zip(arms, theta_b)
            ]
        return [r * (1.0 + lam * b) for r, b in zip(theta_r, theta_b)]

    def set_passive(self, service: str, passive: bool = True) -> None:
        if passive:
            self.passive_services.add(service)
        else:
            self.passive_services.discard(service)

    def reseed(self, seed: Optional[int]) -> None:
        """Reset only the RNG stream; posterior state and policy are unchanged."""
        self.rng = np.random.default_rng(seed)

    # -- updates -------------------------------------------------------------
    def update(self, service: str, field_name: str, reward: bool) -> None:
        """Update."""
        arm = self.state[(service, field_name)]
        if reward:
            arm.reachability.alpha += 1
        else:
            arm.reachability.beta += 1

    def update_batch(
        self,
        service: str,
        field_names: List[str],
        rewards: List[bool],
    ) -> None:
        assert len(field_names) == len(rewards)
        for f, r in zip(field_names, rewards):
            self.update(service, f, r)

    def update_multi(
        self,
        service: str,
        field_name: str,
        reachability_reward: float,
        breadth_reward: float,
        observation_weight: float = 1.0,
        reachability_weight: Optional[float] = None,
        breadth_weight: Optional[float] = None,
    ) -> None:
        """Apply bounded soft observations separately to Reach and Breadth."""
        arm = self.state[(service, field_name)]
        rw = observation_weight if reachability_weight is None else reachability_weight
        bw = observation_weight if breadth_weight is None else breadth_weight
        if not 0.0 <= rw <= 1.0 or not 0.0 <= bw <= 1.0:
            raise ValueError("head-specific observation weights must be in [0,1]")
        arm.reachability.update(reachability_reward, rw)
        arm.breadth.update(breadth_reward, bw)

    # -- introspection -------------------------------------------------------
    def state_snapshot(self, service: str) -> Dict[str, Dict[str, Dict[str, float]]]:
        """Return both heads for every field of one service."""
        out: Dict[str, Dict[str, Dict[str, float]]] = {}
        for (svc, f), arm in self.state.items():
            if svc != service:
                continue
            out[f] = {
                "reachability": {
                    "alpha": arm.reachability.alpha,
                    "beta": arm.reachability.beta,
                    "prior_alpha": arm.reachability.prior_alpha,
                    "prior_beta": arm.reachability.prior_beta,
                    "expectation": arm.reachability.expectation,
                },
                "breadth": {
                    "alpha": arm.breadth.alpha,
                    "beta": arm.breadth.beta,
                    "prior_alpha": arm.breadth.prior_alpha,
                    "prior_beta": arm.breadth.prior_beta,
                    "expectation": arm.breadth.expectation,
                },
            }
        return out

    def field_names(self, service: str) -> List[str]:
        return [f for (svc, f) in self.state.keys() if svc == service]

    # -- batch reconciliation ------------------------------------------------
    @classmethod
    def merge_bandits(
        cls,
        bandits: List["ReinforcementLearningBandit"],
        base_bandit: Optional["ReinforcementLearningBandit"] = None,
    ) -> "ReinforcementLearningBandit":
        """Merge worker evidence conjugately, adding each prior only once."""
        first = base_bandit or (bandits[0] if bandits else None)
        merged = cls(
            reward_mode=first.reward_mode if first is not None else None,
            lambda_breadth=first.lambda_breadth if first is not None else None,
            breadth_prior=first.breadth_prior if first is not None else None,
            objective_version=first.objective_version if first is not None else None,
            sampling_policy=first.sampling_policy if first is not None else None,
        )
        if first is not None:
            merged.weight_config_hash = first.weight_config_hash
            merged.passive_services = set(first.passive_services)

        def _copy_arm(arm: MultiObjectiveFieldArm) -> MultiObjectiveFieldArm:
            return MultiObjectiveFieldArm(
                reachability=BetaArm(
                    alpha=arm.reachability.alpha,
                    beta=arm.reachability.beta,
                    prior_alpha=arm.reachability.prior_alpha,
                    prior_beta=arm.reachability.prior_beta,
                ),
                breadth=BetaArm(
                    alpha=arm.breadth.alpha,
                    beta=arm.breadth.beta,
                    prior_alpha=arm.breadth.prior_alpha,
                    prior_beta=arm.breadth.prior_beta,
                ),
            )

        if base_bandit is not None:
            merged.state = {
                key: _copy_arm(arm) for key, arm in base_bandit.state.items()
            }

        for b in bandits:
            if first is not None:
                config_tuple = (
                    b.reward_mode, b.lambda_breadth, b.breadth_prior,
                    b.objective_version, b.weight_config_hash, b.sampling_policy,
                )
                first_tuple = (
                    first.reward_mode, first.lambda_breadth, first.breadth_prior,
                    first.objective_version, first.weight_config_hash,
                    first.sampling_policy,
                )
                if config_tuple != first_tuple:
                    raise ValueError(
                        "cannot merge ReinforcementLearningBandit states with different "
                        f"objective/weight configuration: {config_tuple!r} != {first_tuple!r}"
                    )
            for (svc, fname), arm in b.state.items():
                key = (svc, fname)
                if key not in merged.state:
                    merged.state[key] = MultiObjectiveFieldArm.from_priors(
                        (arm.reachability.prior_alpha, arm.reachability.prior_beta),
                        (arm.breadth.prior_alpha, arm.breadth.prior_beta),
                    )

                baseline = base_bandit.state.get(key) if base_bandit is not None else None
                m = merged.state[key]
                for head_name in ("reachability", "breadth"):
                    source_head = getattr(arm, head_name)
                    merged_head = getattr(m, head_name)
                    baseline_head = (
                        getattr(baseline, head_name) if baseline is not None else None
                    )
                    alpha_base = (
                        baseline_head.alpha if baseline_head is not None
                        else source_head.prior_alpha
                    )
                    beta_base = (
                        baseline_head.beta if baseline_head is not None
                        else source_head.prior_beta
                    )
                    da = source_head.alpha - alpha_base
                    db = source_head.beta - beta_base
                    if da < -_EPS or db < -_EPS:
                        raise ValueError(
                            f"worker state regressed below merge baseline for {key}/{head_name}: "
                            f"delta=({da}, {db})"
                        )
                    merged_head.alpha += max(0.0, da)
                    merged_head.beta += max(0.0, db)
        return merged

    def decay_toward_prior(self, decay: float) -> None:
        """Shrink each head toward its own prior without mixing the heads."""
        if not 0.0 <= decay <= 1.0:
            raise ValueError(f"decay must be in [0,1], got {decay}")
        for arm in self.state.values():
            arm.decay_toward_prior(decay)

    # -- persistence ----------------------------------------------------------
    def save_to_file(
        self,
        filepath: str,
        objective_version: Optional[str] = None,
        weight_config_hash: Optional[str] = None,
        spec_digests: Optional[dict] = None,
    ) -> None:
        """Persist utility and prior parameters in a versioned JSON envelope."""
        ov = objective_version if objective_version is not None else self.objective_version
        wh = weight_config_hash if weight_config_hash is not None else self.weight_config_hash
        services: Dict[str, Dict[str, Dict[str, Dict[str, float]]]] = {}
        for (svc, fname), arm in self.state.items():
            services.setdefault(svc, {})[fname] = {
                "reachability": {
                    "alpha": arm.reachability.alpha,
                    "beta": arm.reachability.beta,
                    "prior_alpha": arm.reachability.prior_alpha,
                    "prior_beta": arm.reachability.prior_beta,
                },
                "breadth": {
                    "alpha": arm.breadth.alpha,
                    "beta": arm.breadth.beta,
                    "prior_alpha": arm.breadth.prior_alpha,
                    "prior_beta": arm.breadth.prior_beta,
                },
            }
        payload = {
            "schema_version": SCHEMA_VERSION,
            "objective_version": ov,
            "weight_config_hash": wh,
            "sampling_policy": self.sampling_policy,
            "services": services,
        }
        if spec_digests is not None:
            payload["spec_digests"] = spec_digests
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)

    @classmethod
    def load_from_file(
        cls,
        filepath: str,
        *,
        expected_objective_version: Optional[str] = None,
        expected_weight_hash: Optional[str] = None,
        allow_legacy_migration: bool = False,
        strict: bool = True,
    ) -> "ReinforcementLearningBandit":
        """Validate and restore state with explicitly gated legacy migration."""
        with open(filepath) as f:
            data = json.load(f)

        if isinstance(data, dict) and "schema_version" in data:
            sv = data.get("schema_version")
            if sv != SCHEMA_VERSION:
                raise ValueError(
                    f"unsupported bandit state schema_version={sv!r} "
                    f"(expected {SCHEMA_VERSION}) at {filepath}"
                )
            bandit = cls(sampling_policy=data.get("sampling_policy"))
            file_ov = data.get("objective_version", "")
            exp_ov = expected_objective_version if expected_objective_version is not None \
                else bandit.objective_version
            if file_ov != exp_ov:
                msg = (
                    f"bandit state objective_version mismatch: file={file_ov!r} "
                    f"expected={exp_ov!r} ({filepath})"
                )
                if strict:
                    raise ValueError(msg)
                logger.warning("%s; proceeding (strict=False)", msg)
            file_wh = data.get("weight_config_hash", "")
            exp_wh = expected_weight_hash if expected_weight_hash is not None \
                else bandit.weight_config_hash
            if exp_wh and file_wh != exp_wh:
                msg = (
                    f"bandit state weight_config_hash mismatch: file={file_wh!r} "
                    f"expected={exp_wh!r} ({filepath})"
                )
                if strict:
                    raise ValueError(msg)
                logger.warning("%s; proceeding (strict=False)", msg)
            bandit.weight_config_hash = file_wh
            for svc, fields in data.get("services", {}).items():
                for fname, heads in fields.items():
                    bandit.state[(svc, fname)] = MultiObjectiveFieldArm(
                        reachability=BetaArm(
                            alpha=heads["reachability"]["alpha"],
                            beta=heads["reachability"]["beta"],
                            prior_alpha=heads["reachability"]["prior_alpha"],
                            prior_beta=heads["reachability"]["prior_beta"],
                        ),
                        breadth=BetaArm(
                            alpha=heads["breadth"]["alpha"],
                            beta=heads["breadth"]["beta"],
                            prior_alpha=heads["breadth"]["prior_alpha"],
                            prior_beta=heads["breadth"]["prior_beta"],
                        ),
                    )
            return bandit

        # ---- legacy V0 flat format: {svc: {field: {alpha, beta, ...}}} ----
        if not allow_legacy_migration:
            raise ValueError(
                f"refusing to load legacy (unversioned) bandit state at {filepath} "
                f"without explicit opt-in: pass allow_legacy_migration=True or set "
                f"config.RL_STATE_ALLOW_LEGACY_MIGRATION=True. Migration "
                f"moves V0 observations into the reachability head only; breadth "
                f"restarts from the neutral prior."
            )
        bandit = cls()
        n_arms = 0
        for svc, fields in data.items():
            for fname, params in fields.items():
                pa = params.get("prior_alpha")
                pb = params.get("prior_beta")
                if pa is None or pb is None:
                    # Legacy state file upgrade: recompute prior from stored score
                    score = params.get("static_score", 2)
                    pa, pb = cls._score_to_prior(score)
                bandit.state[(svc, fname)] = MultiObjectiveFieldArm(
                    reachability=BetaArm(
                        alpha=params["alpha"],
                        beta=params["beta"],
                        prior_alpha=pa,
                        prior_beta=pb,
                    ),
                    breadth=BetaArm(
                        alpha=bandit.breadth_prior[0],
                        beta=bandit.breadth_prior[1],
                        prior_alpha=bandit.breadth_prior[0],
                        prior_beta=bandit.breadth_prior[1],
                    ),
                )
                n_arms += 1
        logger.warning(
            "[BANDIT] Migrated %d legacy V0 arms from %s: observations moved into "
            "reachability head ONLY; breadth head reset to neutral prior %s",
            n_arms, filepath, bandit.breadth_prior,
        )
        return bandit

    def to_priority_map(self) -> Dict[str, Dict[str, int]]:
        """Distill learned α/(α+β) into 1-10 integer priority scores."""
        result: Dict[str, Dict[str, int]] = {}
        for (svc, fname), arm in self.state.items():
            exp = arm.reachability.expectation
            score = max(1, min(10, round(exp * 10)))
            result.setdefault(svc, {})[fname] = score
        return result

# ---------------------------------------------------------------------------
# LENGTH field helpers
# ---------------------------------------------------------------------------
def length_mutation_values(real_length: int) -> List[bytes]:
    """Candidate wrong LENGTH values per proposal §2.6.3.

    Returns sorted unique list of byte values (each big-endian, minimal
    length to represent the value).
    """
    candidates = sorted(
        {0, 1, max(0, real_length - 1), real_length + 1, 255, 65535}
    )
    return [
        v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        for v in candidates
    ]

# ---------------------------------------------------------------------------
# Weighted-sampling batch mutation generator
# ---------------------------------------------------------------------------
class BatchMutationGenerator:
    """Generate `batch_size` mutated packets per call via bandit-weighted"""

    def __init__(
        self,
        spec,
        seed_bytes: bytes,
        mutator: "FastMutator",
        seed: Optional[int] = None,
    ):
        self.spec = spec
        self.seed = bytearray(seed_bytes)
        self.mutator = mutator
        self.rng = np.random.default_rng(seed)

        # Pre-compute plans (mirrors FastMutator.generate_mutants step 1-4)
        self.plans = mutator._mapper.analyze(spec, seed_bytes)
        manual, auto = PriorityMapper.separate(self.plans)
        # mutable: manual fields with >1 candidate (BLOCK_BEGIN/END already
        # excluded by analyze() at priority_mapper.py:104-106)
        self.mutable: List[FieldPlan] = [
            p for p in manual if len(p.candidates) > 1
        ]
        # length_fields: auto-calc LENGTH only (CHECKSUM auto-calc excluded
        # from bandit per proposal §2.6.5)
        self.length_fields: List[FieldPlan] = [
            p for p in auto if p.field.survival_type == SurvivalType.LENGTH
        ]
        self.auto_fields: List[FieldPlan] = auto
        self.blocks = PriorityMapper.resolve_blocks(spec, self.plans)

        # Pre-compute actual nominal block lengths, not arbitrary seed bytes.
        self._length_real: Dict[str, int] = {
            p.field.name: self._compute_real_length(p)
            for p in self.length_fields
        }

        self._feasible: bool = bool(self.mutable) or bool(self.length_fields)

        # Touched-field registry, updated by generate() for the caller
        # to feed back into bandit updates.
        self.last_touched: List[List[FieldPlan]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate(
        self,
        bandit: ReinforcementLearningBandit,
        service: str,
        batch_size: int,
        max_fields: int,
        batch_idx: int,
        total_batches: int,
        phase1_ratio: float = 0.3,
    ) -> Tuple[List[bytes], List[List[FieldPlan]]]:
        """Generate batch_size mutations; return (mutants, touched_per_mutation)."""
        

        if not self._feasible or batch_size <= 0:
            self.last_touched = []
            return [], []

        phase1 = batch_idx < total_batches * phase1_ratio
        # max_fields < 1 → force single-field path
        effective_max = max(1, int(max_fields))

        mutants: List[bytes] = []
        touched: List[List[FieldPlan]] = []

        for _ in range(batch_size):
            plans = self._sample_fields(
                bandit, service, phase1=phase1, max_fields=effective_max
            )
            pkt = bytearray(self.seed)
            selected_names: set = set()

            for idx, p in enumerate(plans):
                
                start = p.positioned.start_byte
                end = p.positioned.end_byte
                original_value = bytes(self.seed[start:end])

                if p.field.survival_type == SurvivalType.LENGTH:
                    choices = wrong_lengths(self._length_real[p.field.name], p.field)
                    # numpy.choice(bytes[]) coerces to np.bytes_ and strips
                    # trailing NULs. Choose an index, retaining the full width.
                    written_value = choices[int(self.rng.integers(len(choices)))]
                    self.mutator.write_field(pkt, p, written_value)
                    selected_names.add(p.field.name)
                else:
                    # Normal mutable field: pick a non-seed candidate at random
                    alt = p.candidates[1:] if len(p.candidates) > 1 else p.candidates
                    new_val = alt[self.rng.integers(len(alt))]
                    written_value = new_val
                    self.mutator.write_field(pkt, p, new_val)


            # auto-calc unselected LENGTH fields
            for p in self.length_fields:
                if p.field.name not in selected_names:
                    self._auto_calc_length(pkt, p)

            # auto-calc all CHECKSUM fields
            for p in self.auto_fields:
                if p.field.survival_type == SurvivalType.CHECKSUM:
                    self._auto_calc_checksum(pkt, p)

            mutants.append(bytes(pkt))
            touched.append(plans)

        self.last_touched = touched
        return mutants, touched

    # ------------------------------------------------------------------
    # Field sampling
    # ------------------------------------------------------------------
    def _sample_fields(
        self,
        bandit: ReinforcementLearningBandit,
        service: str,
        phase1: bool,
        max_fields: int,
    ) -> List[FieldPlan]:
        pool = self.mutable + self.length_fields
        if not pool:
            return []
        weights = bandit.sample_weights(
            service, [p.field.name for p in pool]
        )
        # Degenerate case: all weights zero (no registration) → uniform
        total = sum(weights)
        if total <= 0:
            weights = [1.0] * len(pool)
            total = float(len(pool))
        probs = np.array(weights) / total

        if phase1 or max_fields == 1:
            idx = int(self.rng.choice(len(pool), p=probs))
            return [pool[idx]]

        import config as _cfg
        multi_ratio = getattr(_cfg, "RL_PHASE2_MULTI_FIELD_RATIO", 0.5)
        if self.rng.random() >= multi_ratio or len(pool) == 1:
            idx = int(self.rng.choice(len(pool), p=probs))
            return [pool[idx]]

        # Multi-field: weighted sampling without replacement
        n = int(self.rng.integers(2, max_fields + 1))
        n = min(n, len(pool))
        avail = list(range(len(pool)))
        w = list(probs)
        chosen: List[FieldPlan] = []
        for _ in range(n):
            s = sum(w[i] for i in avail)
            if s <= 0:
                # remaining weights are zero → uniform over avail
                sub = [1.0 / len(avail)] * len(avail)
            else:
                sub = [w[i] / s for i in avail]
            idx_in_avail = int(self.rng.choice(len(avail), p=sub))
            chosen.append(pool[avail[idx_in_avail]])
            del avail[idx_in_avail]
        return chosen

    # ------------------------------------------------------------------
    # LENGTH / CHECKSUM auto-calc helpers (mirror FastMutator internals)
    # ------------------------------------------------------------------
    def _compute_real_length(self, plan: FieldPlan) -> int:
        """Use the block extent; decode seed only for legacy unbound fields."""
        block = self.blocks.get(plan.field.block_name)
        if block is not None:
            return max(0, block.end_byte - block.start_byte)
        start = plan.positioned.start_byte
        end = plan.positioned.end_byte
        raw = bytes(self.seed[start:end])
        if not raw:
            return 0
        try:
            return decode_length(raw, plan.field)
        except ValueError:
            # Arbitrary cross-protocol seeds can contain non-numeric bytes.
            block = self.blocks.get(plan.field.block_name)
            return max(0, block.end_byte - block.start_byte) if block else 0

    def _auto_calc_length(self, pkt: bytearray, plan: FieldPlan) -> None:
        """Recalculate one LENGTH field from the (possibly mutated) block."""
        bn = plan.field.block_name
        if not bn or bn not in self.blocks:
            return
        block = self.blocks[bn]
        block_len = max(0, block.end_byte - block.start_byte)
        encoded = encode_length(block_len, plan.field)
        pos_start = plan.positioned.start_byte
        pos_end = plan.positioned.end_byte
        if pos_end <= len(pkt):
            pkt[pos_start:pos_end] = encoded

    def _auto_calc_checksum(self, pkt: bytearray, plan: FieldPlan) -> None:
        """Recalculate one CHECKSUM field."""
        bn = plan.field.block_name
        if not bn or bn not in self.blocks:
            return
        block = self.blocks[bn]
        block_data = bytes(pkt[block.start_byte:block.end_byte])
        checksum = calc_checksum(
            block_data,
            plan.field.algorithm or "crc32",
            plan.field.length,
            plan.field.endian,
        )
        pos_start = plan.positioned.start_byte
        pos_end = plan.positioned.end_byte
        if pos_end <= len(pkt):
            pkt[pos_start:pos_end] = checksum

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
