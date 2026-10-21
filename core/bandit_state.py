"""Transport-isolated reinforcement-learning state envelope for background-adjusted search.

Schema v3 deliberately stores TCP and UDP below separate namespaces and binds
the state to every artifact that changes reward semantics. Callers must
not silently reinterpret an older state file.
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Dict, Mapping, Optional

from core.reinforcement_learning import BetaArm, MultiObjectiveFieldArm, ReinforcementLearningBandit

SCHEMA_VERSION = 3
VALID_TRANSPORTS = ("tcp", "udp")

@dataclass(frozen=True)
class StateMetadata:
    objective_version: str
    service_topology_hash: str
    weight_config_hash: str
    background_artifact_hash: str
    response_phase_schema_version: int

    def to_dict(self) -> dict:
        return {
            "objective_version": self.objective_version,
            "service_topology_hash": self.service_topology_hash,
            "weight_config_hash": self.weight_config_hash,
            "background_artifact_hash": self.background_artifact_hash,
            "response_phase_schema_version": self.response_phase_schema_version,
        }

def _validate_transport(transport: str) -> str:
    normalized = str(transport).lower()
    if normalized not in VALID_TRANSPORTS:
        raise ValueError(f"transport must be one of {VALID_TRANSPORTS}, got {transport!r}")
    return normalized

def _validate_envelope(data: Mapping[str, object], expected: StateMetadata) -> None:
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            "background-adjusted search requires reinforcement-learning state schema_version=3; "
            f"got {data.get('schema_version')!r}"
        )
    for key, expected_value in expected.to_dict().items():
        actual = data.get(key)
        if actual != expected_value:
            raise ValueError(
                f"reinforcement-learning state metadata mismatch for {key}: "
                f"file={actual!r}, expected={expected_value!r}"
            )
    transports = data.get("transports")
    if not isinstance(transports, dict):
        raise ValueError("reinforcement-learning state schema v3 is missing transports mapping")

def _arm_to_dict(arm: MultiObjectiveFieldArm) -> dict:
    def head(value: BetaArm) -> dict:
        return {
            "alpha": value.alpha,
            "beta": value.beta,
            "prior_alpha": value.prior_alpha,
            "prior_beta": value.prior_beta,
        }

    return {"reachability": head(arm.reachability), "breadth": head(arm.breadth)}

def _head_from_dict(data: Mapping[str, object]) -> BetaArm:
    return BetaArm(
        alpha=float(data["alpha"]),
        beta=float(data["beta"]),
        prior_alpha=float(data["prior_alpha"]),
        prior_beta=float(data["prior_beta"]),
    )

def bandit_to_services(bandit: ReinforcementLearningBandit) -> dict:
    services: Dict[str, dict] = {}
    for (service, field_name), arm in sorted(bandit.state.items()):
        services.setdefault(service, {})[field_name] = _arm_to_dict(arm)
    return services

def services_to_bandit(
    services: Mapping[str, object],
    *,
    reward_mode: str,
    objective_version: str,
    weight_config_hash: str,
) -> ReinforcementLearningBandit:
    bandit = ReinforcementLearningBandit(
        reward_mode=reward_mode,
        objective_version=objective_version,
    )
    bandit.weight_config_hash = weight_config_hash
    for service, fields in services.items():
        if not isinstance(fields, dict):
            raise ValueError(f"invalid fields mapping for service {service!r}")
        for field_name, heads in fields.items():
            if not isinstance(heads, dict):
                raise ValueError(f"invalid arm entry for {(service, field_name)!r}")
            bandit.state[(service, field_name)] = MultiObjectiveFieldArm(
                reachability=_head_from_dict(heads["reachability"]),
                breadth=_head_from_dict(heads["breadth"]),
            )
    return bandit

def load_transport(
    filepath: str,
    *,
    transport: str,
    expected: StateMetadata,
    reward_mode: str,
    expected_spec_digests: Optional[dict] = None,
) -> Optional[ReinforcementLearningBandit]:
    """Load one transport namespace, returning None when the file/namespace is absent."""
    transport = _validate_transport(transport)
    if not os.path.exists(filepath):
        return None
    with open(filepath, encoding="utf-8") as handle:
        data = json.load(handle)
    _validate_envelope(data, expected)
    namespace = data["transports"].get(transport)
    if namespace is None:
        return None
    if not isinstance(namespace, dict) or not isinstance(namespace.get("services"), dict):
        raise ValueError(f"invalid reinforcement-learning state namespace for {transport}")
    if expected_spec_digests is not None and namespace.get("spec_digests") != expected_spec_digests:
        raise ValueError("reinforcement-learning state spec_digests mismatch; use a fresh state file after spec repair")
    return services_to_bandit(
        namespace["services"],
        reward_mode=reward_mode,
        objective_version=expected.objective_version,
        weight_config_hash=expected.weight_config_hash,
    )

def save_transport(
    filepath: str,
    *,
    transport: str,
    bandit: ReinforcementLearningBandit,
    metadata: StateMetadata,
    spec_digests: Optional[dict] = None,
) -> None:
    """Atomically update one namespace while preserving the other transport.

    A sidecar flock protects sequential TCP/UDP campaigns and any future
    parallel group scheduling from lost updates.
    """
    transport = _validate_transport(transport)
    directory = os.path.dirname(filepath) or "."
    os.makedirs(directory, exist_ok=True)
    lock_path = filepath + ".lock"
    with open(lock_path, "a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        if os.path.exists(filepath):
            with open(filepath, encoding="utf-8") as handle:
                payload = json.load(handle)
            _validate_envelope(payload, metadata)
        else:
            payload = {
                "schema_version": SCHEMA_VERSION,
                **metadata.to_dict(),
                "transports": {},
            }
        payload["transports"][transport] = {
            "services": bandit_to_services(bandit),
        }
        if spec_digests is not None:
            payload["transports"][transport]["spec_digests"] = spec_digests
        fd, tmp_path = tempfile.mkstemp(
            prefix=os.path.basename(filepath) + ".", suffix=".tmp", dir=directory
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, filepath)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
