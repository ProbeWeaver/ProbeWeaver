"""Phase-aware, exactly-three-repetition candidate stability facts.

This module takes **stored**
``multi_probe`` / ``exploratory_multi_probe`` candidates (flat candidate-stream
schema or public nested fingerprint schema), re-probes each packet exactly
three times against the current fleet, and records **network stability facts
only**:

- per-repetition target gate (active target → post-send observed;
  passive target → banner-or-post observed);
- per claimed extra active cluster (``selective_payload_clusters``) an
  independent post-payload hit count over the three repetitions;
- ``network_stable`` = target stable (>= 2/3) AND at least one stable extra.

It deliberately does **not** claim any final ``validated_exploratory``
verdict: held-out / rule confirmation is a later stage.  Artifacts therefore
carry ``claim_scope = network_stability_only`` and never a validated flag.

Candidate identity binds ``(transport, mutation_target, candidate_type,
packet_hex)`` and is stable across calls.  Provenance identities
(objective_version / background artifact / weight config) are merged with
fail-fast semantics: mixing non-empty values is an error, never a silent
selection.

This module is pure with respect to the network: probing is injected through
``probe_fn(record, repetition_index)``.  Only the CLI
(``scripts/reprobe_candidate_stability.py``) instantiates a ServiceTester.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from config import cluster_of
from core.candidate_collector import (
    CANDIDATE_EXPLORATORY_MULTI_PROBE,
    CANDIDATE_MULTI_PROBE,
)
from core.clustering import (
    observed_clusters_from,
    payload_triggered_clusters_from,
)
from core.service_tester import ServiceResponse

# ---------------------------------------------------------------------------
# Schema / version constants
# ---------------------------------------------------------------------------

STABILITY_SCHEMA_VERSION = 1
STABILITY_ARTIFACT_TYPE = "candidate_stability"
#: This stage establishes network stability facts only.  It must never be
#: read as a final ``validated_exploratory`` confirmation.
CLAIM_SCOPE_NETWORK_STABILITY_ONLY = "network_stability_only"

#: Exactly three repetitions, no configuration permitted.
STABILITY_REPETITIONS = 3
#: A fact is stable when it holds in at least 2 of the 3 repetitions.
STABLE_MIN_HITS = 2

SUPPORTED_CANDIDATE_TYPES = (
    CANDIDATE_MULTI_PROBE,
    CANDIDATE_EXPLORATORY_MULTI_PROBE,
)

#: Response phases produced by the phase-aware ServiceTester.
RESPONSE_PHASE_POST_PAYLOAD = "post_payload"
RESPONSE_PHASE_PRE_PAYLOAD_BANNER = "pre_payload_banner"
KNOWN_RESPONSE_PHASES = (
    RESPONSE_PHASE_POST_PAYLOAD,
    RESPONSE_PHASE_PRE_PAYLOAD_BANNER,
)
#: Marker written by the candidate stream for legacy, phase-unknown records.
LEGACY_RESPONSE_PHASE = "legacy_unknown"

SUPPORTED_TRANSPORTS = ("tcp", "udp")

# E0 fresh probes have no stored response by definition: the three new
# repetitions are the first observations.  They are admitted only through an
# explicit parser flag and this qualification marker, with complete parent
# lineage.  Ordinary candidate reprobes retain the original strict behavior.
FRESH_RULE_VALIDATION_QUALIFICATION = "fresh_rule_validation_challenge"

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class CandidateStabilityError(ValueError):
    """Base error for candidate-stability parsing / artifact failures."""

class UnsupportedCandidateTypeError(CandidateStabilityError):
    """Candidate type outside {multi_probe, exploratory_multi_probe}."""

class LegacyPhaseUnknownError(CandidateStabilityError):
    """Record without per-response phase facts in strict phase-aware mode."""

class DuplicateCandidateError(CandidateStabilityError):
    """Two records sharing one candidate identity."""

class MixedProvenanceError(CandidateStabilityError):
    """Mixed non-empty objective/background/weight identities."""

class ArtifactTamperError(CandidateStabilityError):
    """Artifact payload does not match its recorded artifact_hash."""

class ArtifactIdentityMismatchError(CandidateStabilityError):
    """Artifact identity fields differ from expected provenance."""

# ---------------------------------------------------------------------------
# Canonical hashing
# ---------------------------------------------------------------------------

def canonical_sha256(payload: Any) -> str:
    """Deterministic canonical SHA256 hex digest.

    Mappings are serialized with sorted keys and compact separators.  The
    top-level ``artifact_hash`` and ``created_at`` keys are excluded so that
    ``artifact_hash = canonical_sha256(artifact)`` is self-consistent
    (``created_at`` is provenance, not content).
    """
    data: Any = payload
    if isinstance(payload, Mapping):
        data = dict(payload)
        data.pop("artifact_hash", None)
        data.pop("created_at", None)
    blob = json.dumps(data, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

# ---------------------------------------------------------------------------
# Candidate identity
# ---------------------------------------------------------------------------

IDENTITY_FIELDS: Tuple[str, ...] = (
    "transport", "mutation_target", "candidate_type", "packet_hex",
)

def candidate_identity(record: Mapping) -> Tuple[str, str, str, str]:
    """Stable candidate identity: (transport, mutation_target,
    candidate_type, packet_hex).

    ``packet_hex`` is normalized to lowercase so identical packets hashed in
    different cases share one identity.  A missing ``candidate_type`` reads
    as ``multi_probe`` (public-nested legacy convention), matching
    :func:`parse_candidate_record`.  Other missing components are
    construction errors raised by :func:`parse_candidate_record`.
    """
    candidate_type = str(
        record.get("candidate_type", "") or CANDIDATE_MULTI_PROBE)
    return (
        str(record.get("transport", "")).strip().lower(),
        str(record.get("mutation_target", "")),
        candidate_type,
        str(record.get("packet_hex", "")).strip().lower(),
    )

def candidate_identity_digest(record: Mapping) -> str:
    """Canonical SHA256 over the identity tuple."""
    return canonical_sha256(list(candidate_identity(record)))

# ---------------------------------------------------------------------------
# Record parsing (flat candidate-stream schema + public nested schema)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CandidateSpec:
    """Normalized view of one stored candidate record."""

    identity: Tuple[str, str, str, str]
    packet_hex: str
    mutation_target: str
    candidate_type: str
    transport: str
    passive_target: bool
    claimed_extra_clusters: Tuple[str, ...]
    objective_version: str
    weight_config_hash: str
    background_artifact_hash: str
    qualification_status: str
    iteration: int
    parent_seed_id: str
    parent_packet_hash: str
    phase_aware: bool

    @property
    def identity_digest(self) -> str:
        return canonical_sha256(list(self.identity))

def _iter_stored_observations(record: Mapping) -> List[dict]:
    """Yield member observations from either stored schema.

    Flat candidate-stream schema (``core/candidate_stream.py``):
        ``responses = [{service, response_hex, banner_hex, response_phase,
        latency_ms, banner_latency_ms, payload_latency_ms}, ...]``

    Public nested schema (``core/clustering.candidate_to_nested_dict`` /
    ``disk_record_to_nested``):
        ``responses = [{service: <cluster>, responses: [{service: <member>,
        response_hex, ...}, ...]}, ...]``
    """
    responses = record.get("responses", [])
    if not isinstance(responses, list):
        raise CandidateStabilityError(
            f"record 'responses' must be a list, got {type(responses).__name__}")
    observations: List[dict] = []
    for entry in responses:
        if not isinstance(entry, dict):
            raise CandidateStabilityError(
                f"record 'responses' entries must be dicts, got "
                f"{type(entry).__name__}")
        if isinstance(entry.get("responses"), list):
            # Nested schema: outer level is a cluster group.
            for member in entry["responses"]:
                if not isinstance(member, dict):
                    raise CandidateStabilityError(
                        "nested member entries must be dicts")
                item = dict(member)
                item.setdefault("service", "")
                observations.append(item)
        else:
            observations.append(entry)
    return observations

def _stored_phase_is_known(phase: Any) -> bool:
    return phase in KNOWN_RESPONSE_PHASES

def parse_candidate_record(
    record: Mapping,
    *,
    strict_phase_aware: bool = True,
    allow_unobserved_challenge: bool = False,
) -> CandidateSpec:
    """Validate + normalize one stored candidate record.

    Fail-fast errors:
      - ``packet_hex`` missing or not valid hex;
      - ``mutation_target`` missing (target gate cannot be evaluated, and it
        is part of the identity);
      - ``transport`` missing or not tcp/udp (identity + fleet routing);
      - candidate_type outside the supported set
        (:class:`UnsupportedCandidateTypeError`);
      - strict phase-aware mode and any stored response lacks a known
        ``response_phase`` (or carries ``legacy_unknown``)
        → :class:`LegacyPhaseUnknownError`.

    With ``strict_phase_aware=False`` (explicit legacy opt-out) legacy
    records are accepted; their historical responses are never used as
    payload evidence anywhere downstream (fresh probe repetitions drive all
    facts), the flag only controls admission.
    """
    if not isinstance(record, Mapping):
        raise CandidateStabilityError(
            f"candidate record must be a mapping, got {type(record).__name__}")

    packet_hex = str(record.get("packet_hex", "") or "").strip().lower()
    if not packet_hex:
        raise CandidateStabilityError("candidate record missing packet_hex")
    try:
        bytes.fromhex(packet_hex)
    except ValueError as exc:
        raise CandidateStabilityError(
            f"candidate packet_hex is not valid hex: {exc}") from exc

    mutation_target = str(record.get("mutation_target", "") or "")
    if not mutation_target:
        # origin_protocol is NOT a direction ground truth (project memory);
        # records without mutation_target cannot be target-gated at all.
        raise CandidateStabilityError(
            "candidate record missing mutation_target; origin_protocol is "
            "not an acceptable substitute for the stability target gate")

    transport = str(record.get("transport", "") or "").strip().lower()
    if transport not in SUPPORTED_TRANSPORTS:
        raise CandidateStabilityError(
            f"candidate transport must be one of {SUPPORTED_TRANSPORTS}, "
            f"got {transport!r}")

    candidate_type = str(record.get("candidate_type", "") or CANDIDATE_MULTI_PROBE)
    if candidate_type not in SUPPORTED_CANDIDATE_TYPES:
        raise UnsupportedCandidateTypeError(
            f"candidate_type {candidate_type!r} is outside the stability "
            f"scope {SUPPORTED_CANDIDATE_TYPES}")

    observations = _iter_stored_observations(record)
    qualification_status = str(record.get("qualification_status", "") or "")
    parent_seed_id = str(record.get("parent_seed_id", "") or "")
    parent_packet_hash = str(record.get("parent_packet_hash", "") or "")
    unobserved_challenge = (
        allow_unobserved_challenge
        and not observations
        and qualification_status == FRESH_RULE_VALIDATION_QUALIFICATION
        and bool(parent_seed_id)
        and bool(parent_packet_hash)
    )
    phase_aware = unobserved_challenge or (bool(observations) and all(
        _stored_phase_is_known(item.get("response_phase"))
        for item in observations
    ))
    if strict_phase_aware and not phase_aware:
        raise LegacyPhaseUnknownError(
            "strict phase-aware mode rejected a legacy record without "
            "per-response phase facts (missing or legacy_unknown "
            "response_phase); rerun with --allow-legacy to admit it "
            "explicitly")

    extras = sorted({
        str(cluster)
        for cluster in (record.get("selective_payload_clusters") or ())
        if str(cluster)
    })
    return CandidateSpec(
        identity=(transport, mutation_target, candidate_type, packet_hex),
        packet_hex=packet_hex,
        mutation_target=mutation_target,
        candidate_type=candidate_type,
        transport=transport,
        passive_target=bool(record.get("passive_target", False)),
        claimed_extra_clusters=tuple(extras),
        objective_version=str(record.get("objective_version", "") or ""),
        weight_config_hash=str(record.get("weight_config_hash", "") or ""),
        background_artifact_hash=str(
            record.get("background_artifact_hash", "") or ""),
        qualification_status=qualification_status,
        iteration=int(record.get("iteration", 0) or 0),
        parent_seed_id=parent_seed_id,
        parent_packet_hash=parent_packet_hash,
        phase_aware=phase_aware,
    )

# ---------------------------------------------------------------------------
# Repetition normalization
# ---------------------------------------------------------------------------

def normalize_repetition(responses: Sequence[ServiceResponse]) -> dict:
    """Normalize one probe repetition into deterministic member observations.

    Each retained member observation preserves member name, ``cluster_of``
    mapping, response/banner hex, ``response_phase`` and banner/payload
    latencies.  Fully silent members (no response and no banner bytes) carry
    no observation and are omitted, matching how the candidate stream
    persists responses.

    Fresh repetitions must be phase-aware: a retained observation whose
    ``response_phase`` is not one of :data:`KNOWN_RESPONSE_PHASES`
    (``pre_payload_banner`` / ``post_payload``) — including missing/empty or
    the stored-stream ``legacy_unknown`` marker — fails fast with
    :class:`CandidateStabilityError` at normalization time.  Phase facts are
    the evidence this stage records, so an unphaseable observation is never
    silently coerced to a default phase.

    Derived cluster sets:
      - ``observed_clusters``: banner OR post-payload bytes visible;
      - ``payload_triggered_clusters``: post-send response bytes only (the
        field name is historical and does not assert semantic causality).
    """
    members: List[dict] = []
    for response in responses:
        response_bytes = bytes(response.response_bytes or b"")
        banner_bytes = bytes(getattr(response, "banner_bytes", b"") or b"")
        if not response_bytes and not banner_bytes:
            continue  # silent member: no observation
        phase = str(getattr(response, "response_phase", "") or "")
        if phase not in KNOWN_RESPONSE_PHASES:
            raise CandidateStabilityError(
                f"member {response.service_name!r} observation carries "
                f"unknown response_phase {phase!r}; fresh repetitions must be "
                f"phase-aware (one of {KNOWN_RESPONSE_PHASES})")
        members.append({
            "member": response.service_name,
            "cluster": cluster_of(response.service_name),
            "response_hex": response_bytes.hex(),
            "banner_hex": banner_bytes.hex(),
            "response_phase": phase,
            "latency_ms": float(response.latency_ms),
            "banner_latency_ms": float(
                getattr(response, "banner_latency_ms", 0.0) or 0.0),
            "payload_latency_ms": float(
                getattr(response, "payload_latency_ms", 0.0) or 0.0),
        })
    members.sort(key=lambda item: item["member"])
    observed = sorted(observed_clusters_from(list(responses)))
    payload_triggered = sorted(payload_triggered_clusters_from(list(responses)))
    return {
        "members": members,
        "observed_clusters": observed,
        "payload_triggered_clusters": payload_triggered,
    }

# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _repetition_target_hit(spec: CandidateSpec, repetition: Mapping) -> bool:
    if spec.passive_target:
        return spec.mutation_target in set(repetition["observed_clusters"])
    return spec.mutation_target in set(repetition["payload_triggered_clusters"])

def evaluate_candidate_stability(
    record: Mapping,
    repetition_responses: Sequence[Sequence[ServiceResponse]],
    *,
    strict_phase_aware: bool = True,
    allow_unobserved_challenge: bool = False,
    repetitions: int = STABILITY_REPETITIONS,
) -> dict:
    """Evaluate one candidate over exactly three probe repetitions.

    ``repetition_responses`` must supply exactly ``STABILITY_REPETITIONS``
    (3) response sequences; any other requested or supplied count fails.
    Returns the per-candidate stability facts (no validated claim).

    Gate semantics per repetition:
      - active target (``passive_target`` false): target cluster must be in
        the post-send observation set (the historical schema key remains
        ``payload_triggered_clusters``; it does not prove semantic causation);
      - passive target: target cluster may be in the observed set
        (banner OR post).

    Claimed extra active clusters come from the record's
    ``selective_payload_clusters``; each is counted against post-payload hits
    only, independently.  A fact is stable at >= 2/3 repetitions.
    """
    if repetitions != STABILITY_REPETITIONS:
        raise CandidateStabilityError(
            f"candidate stability requires exactly {STABILITY_REPETITIONS} "
            f"repetitions, requested {repetitions}")
    if len(repetition_responses) != repetitions:
        raise CandidateStabilityError(
            f"expected exactly {repetitions} repetition response sequences, "
            f"got {len(repetition_responses)}")

    spec = parse_candidate_record(
        record, strict_phase_aware=strict_phase_aware,
        allow_unobserved_challenge=allow_unobserved_challenge)

    repetitions_out: List[dict] = []
    target_gate_hits: List[bool] = []
    extra_hits: Dict[str, int] = {cluster: 0 for cluster in spec.claimed_extra_clusters}
    for responses in repetition_responses:
        repetition = normalize_repetition(responses)
        repetitions_out.append(repetition)
        hit = _repetition_target_hit(spec, repetition)
        target_gate_hits.append(hit)
        payload_clusters = set(repetition["payload_triggered_clusters"])
        for cluster in spec.claimed_extra_clusters:
            if cluster in payload_clusters:
                extra_hits[cluster] += 1

    target_hits = sum(1 for hit in target_gate_hits if hit)
    target_stable = target_hits >= STABLE_MIN_HITS
    stable_extras = sorted(
        cluster for cluster, hits in extra_hits.items()
        if hits >= STABLE_MIN_HITS
    )
    return {
        "candidate_id": spec.identity_digest,
        "identity": {
            "transport": spec.transport,
            "mutation_target": spec.mutation_target,
            "candidate_type": spec.candidate_type,
            "packet_hex": spec.packet_hex,
        },
        "source": {
            "objective_version": spec.objective_version,
            "weight_config_hash": spec.weight_config_hash,
            "background_artifact_hash": spec.background_artifact_hash,
            "qualification_status": spec.qualification_status,
            "iteration": spec.iteration,
            "parent_seed_id": spec.parent_seed_id,
            "parent_packet_hash": spec.parent_packet_hash,
        },
        "target_cluster": spec.mutation_target,
        "passive_target": spec.passive_target,
        "target_gate_mode": "passive" if spec.passive_target else "active",
        "claimed_extra_active_clusters": list(spec.claimed_extra_clusters),
        "target_gate_hits": target_gate_hits,
        "target_hits": target_hits,
        "target_stable": target_stable,
        "extra_active_hits": {k: extra_hits[k] for k in sorted(extra_hits)},
        "stable_extra_active_clusters": stable_extras,
        # Strict multi_probe qualification is NOT reinterpreted here: the
        # same facts are computed for it, its qualification_status is copied
        # verbatim into "source".
        "network_stable": bool(target_stable and stable_extras),
        "repetition_observations": repetitions_out,
    }

# ---------------------------------------------------------------------------
# Provenance merging (fail-fast)
# ---------------------------------------------------------------------------

_PROVENANCE_FIELDS = (
    "objective_version", "weight_config_hash", "background_artifact_hash",
)

def merge_provenance(
    specs: Sequence[CandidateSpec],
    *,
    objective_version: str = "",
    weight_config_hash: str = "",
    background_artifact_hash: str = "",
) -> Dict[str, str]:
    """Merge provenance identities across records + explicit metadata.

    Mixed non-empty values fail fast instead of silently selecting one.  A
    non-empty explicit argument conflicting with non-empty record values is
    the same error.  Returns the single artifact-level identity per field
    ("" when absent everywhere).
    """
    explicit = {
        "objective_version": objective_version or "",
        "weight_config_hash": weight_config_hash or "",
        "background_artifact_hash": background_artifact_hash or "",
    }
    merged: Dict[str, str] = {}
    for field in _PROVENANCE_FIELDS:
        values = sorted({
            getattr(spec, field)
            for spec in specs
            if getattr(spec, field)
        })
        arg = explicit[field]
        if len(values) > 1:
            raise MixedProvenanceError(
                f"mixed non-empty {field} across candidate records: {values}")
        if arg and values and values != [arg]:
            raise MixedProvenanceError(
                f"explicit {field}={arg!r} conflicts with record value "
                f"{values[0]!r}")
        merged[field] = arg if arg else (values[0] if values else "")
    return merged

# ---------------------------------------------------------------------------
# Artifact construction
# ---------------------------------------------------------------------------

def build_stability_artifact(
    records: Sequence[Mapping],
    probe_fn: Callable[[Mapping, int], Sequence[ServiceResponse]],
    *,
    objective_version: str = "",
    weight_config_hash: str = "",
    background_artifact_hash: str = "",
    service_topology_hash: str = "",
    response_phase_schema_version: int = 2,
    created_at: Optional[str] = None,
    strict_phase_aware: bool = True,
    allow_unobserved_challenge: bool = False,
    repetitions: int = STABILITY_REPETITIONS,
) -> dict:
    """Probe every candidate exactly three times and build the artifact.

    ``probe_fn(record, repetition_index)`` must return the
    ``ServiceResponse`` sequence for repetition ``repetition_index`` ∈ {0,1,2}
    of that record (network access is injected; this function stays pure).

    Ordering / determinism:
      - duplicate candidate identities fail fast;
      - candidate_results are sorted by the identity tuple, so the artifact
        (and ``source_candidates_digest``) is independent of input ordering;
      - ``artifact_hash`` excludes ``created_at`` and ``artifact_hash``.
    """
    if repetitions != STABILITY_REPETITIONS:
        raise CandidateStabilityError(
            f"candidate stability requires exactly {STABILITY_REPETITIONS} "
            f"repetitions, requested {repetitions}")
    if not records:
        raise CandidateStabilityError(
            "build_stability_artifact requires at least one candidate record")

    parsed: List[Tuple[CandidateSpec, Mapping]] = []
    seen: Dict[str, Tuple[str, str, str, str]] = {}
    for record in records:
        spec = parse_candidate_record(
            record, strict_phase_aware=strict_phase_aware,
            allow_unobserved_challenge=allow_unobserved_challenge)
        if spec.identity_digest in seen:
            raise DuplicateCandidateError(
                f"duplicate candidate identity {spec.identity_digest} "
                f"({spec.identity}); stability requires unique candidates")
        seen[spec.identity_digest] = spec.identity
        parsed.append((spec, record))

    provenance = merge_provenance(
        [spec for spec, _ in parsed],
        objective_version=objective_version,
        weight_config_hash=weight_config_hash,
        background_artifact_hash=background_artifact_hash,
    )

    candidate_results: List[dict] = []
    for spec, record in sorted(parsed, key=lambda item: item[0].identity):
        repetition_responses = [
            probe_fn(record, index) for index in range(repetitions)
        ]
        candidate_results.append(evaluate_candidate_stability(
            record,
            repetition_responses,
            strict_phase_aware=strict_phase_aware,
            allow_unobserved_challenge=allow_unobserved_challenge,
            repetitions=repetitions,
        ))

    source_candidates_digest = canonical_sha256({
        "candidate_identity_digests": [
            result["candidate_id"] for result in candidate_results
        ],
    })
    artifact: Dict[str, Any] = {
        "schema_version": STABILITY_SCHEMA_VERSION,
        "artifact_type": STABILITY_ARTIFACT_TYPE,
        # Network stability facts only — never a validated_exploratory claim.
        "claim_scope": CLAIM_SCOPE_NETWORK_STABILITY_ONLY,
        "repetitions": repetitions,
        "strict_phase_aware": bool(strict_phase_aware),
        "unobserved_challenge_admission": bool(allow_unobserved_challenge),
        "source_candidates_digest": source_candidates_digest,
        "service_topology_hash": service_topology_hash or "",
        "objective_version": provenance["objective_version"],
        "background_artifact_hash": provenance["background_artifact_hash"],
        "weight_config_hash": provenance["weight_config_hash"],
        "response_phase_schema_version": int(response_phase_schema_version),
        "candidate_results": candidate_results,
    }
    artifact["artifact_hash"] = canonical_sha256(artifact)
    artifact["created_at"] = created_at or datetime.now(
        timezone.utc).isoformat(timespec="seconds")
    return artifact

# ---------------------------------------------------------------------------
# Loader / validator
# ---------------------------------------------------------------------------

_REQUIRED_ARTIFACT_KEYS = (
    "schema_version", "artifact_type", "claim_scope", "repetitions",
    "source_candidates_digest", "service_topology_hash",
    "objective_version", "background_artifact_hash", "weight_config_hash",
    "response_phase_schema_version", "candidate_results", "artifact_hash",
    "created_at",
)

_REQUIRED_RESULT_KEYS = (
    "candidate_id", "identity", "source", "target_cluster",
    "passive_target", "target_gate_mode", "target_gate_hits",
    "target_hits", "target_stable", "extra_active_hits",
    "stable_extra_active_clusters", "network_stable",
    "repetition_observations",
)

def validate_stability_artifact(
    artifact: Mapping,
    *,
    expected_objective_version: Optional[str] = None,
    expected_weight_config_hash: Optional[str] = None,
    expected_background_artifact_hash: Optional[str] = None,
    expected_service_topology_hash: Optional[str] = None,
    expected_source_candidates_digest: Optional[str] = None,
    expected_response_phase_schema_version: Optional[int] = None,
) -> dict:
    """Strict validation: recompute the artifact hash and identity fields.

    Any tampering (payload edited without re-hashing) fails with
    :class:`ArtifactTamperError`; a mismatch against explicitly expected
    provenance identities fails with :class:`ArtifactIdentityMismatchError`.

    Additionally required (even for otherwise self-consistent hashes):
      - ``claim_scope`` must be exactly ``network_stability_only`` (this stage
        may never be repackaged as a validated-exploratory claim);
      - candidate entries must be unique by ``candidate_id`` and identity;
      - ``source_candidates_digest`` is recomputed from the ordered
        ``candidate_ids`` with the same canonical formula the builder uses
        and must match;
      - ``expected_response_phase_schema_version`` is verified when given.
    """
    if not isinstance(artifact, Mapping):
        raise ArtifactTamperError(
            f"artifact must be a mapping, got {type(artifact).__name__}")
    missing = [
        key for key in _REQUIRED_ARTIFACT_KEYS if key not in artifact
    ]
    if missing:
        raise ArtifactTamperError(f"artifact missing keys: {sorted(missing)}")
    if int(artifact["schema_version"]) != STABILITY_SCHEMA_VERSION:
        raise ArtifactTamperError(
            f"unsupported stability schema_version "
            f"{artifact['schema_version']!r}")
    if artifact["artifact_type"] != STABILITY_ARTIFACT_TYPE:
        raise ArtifactTamperError(
            f"unexpected artifact_type {artifact['artifact_type']!r}")
    if artifact["claim_scope"] != CLAIM_SCOPE_NETWORK_STABILITY_ONLY:
        raise ArtifactTamperError(
            "stability artifact must declare claim_scope="
            f"{CLAIM_SCOPE_NETWORK_STABILITY_ONLY!r}, got "
            f"{artifact['claim_scope']!r}")
    if int(artifact["repetitions"]) != STABILITY_REPETITIONS:
        raise ArtifactTamperError(
            f"stability artifact must declare repetitions="
            f"{STABILITY_REPETITIONS}, got {artifact['repetitions']!r}")

    recomputed = canonical_sha256(artifact)
    if recomputed != artifact["artifact_hash"]:
        raise ArtifactTamperError(
            f"artifact_hash mismatch: recorded "
            f"{artifact['artifact_hash']!r}, recomputed {recomputed!r}")

    results = artifact["candidate_results"]
    if not isinstance(results, list) or not results:
        raise ArtifactTamperError(
            "candidate_results must be a non-empty list")
    previous_identity = None
    seen_candidate_ids: set = set()
    seen_identity_keys: set = set()
    for result in results:
        if not isinstance(result, Mapping):
            raise ArtifactTamperError("candidate_results entries must be dicts")
        missing_result = [
            key for key in _REQUIRED_RESULT_KEYS if key not in result
        ]
        if missing_result:
            raise ArtifactTamperError(
                f"candidate result missing keys: {sorted(missing_result)}")
        identity = result["identity"]
        identity_digest = canonical_sha256([
            identity.get("transport", ""),
            identity.get("mutation_target", ""),
            identity.get("candidate_type", ""),
            str(identity.get("packet_hex", "")).strip().lower(),
        ])
        if identity_digest != result["candidate_id"]:
            raise ArtifactTamperError(
                f"candidate_id {result['candidate_id']!r} does not match its "
                f"stored identity {identity!r}")
        identity_key = (
            identity.get("transport", ""),
            identity.get("mutation_target", ""),
            identity.get("candidate_type", ""),
            str(identity.get("packet_hex", "")).strip().lower(),
        )
        if result["candidate_id"] in seen_candidate_ids:
            raise ArtifactTamperError(
                f"duplicate candidate_id {result['candidate_id']!r} in "
                f"candidate_results; each candidate must appear once")
        if identity_key in seen_identity_keys:
            raise ArtifactTamperError(
                f"duplicate candidate identity {identity_key!r} in "
                f"candidate_results; each candidate must appear once")
        seen_candidate_ids.add(result["candidate_id"])
        seen_identity_keys.add(identity_key)
        if previous_identity is not None and identity_key < previous_identity:
            raise ArtifactTamperError(
                "candidate_results are not in deterministic identity order")
        previous_identity = identity_key
        observations = result["repetition_observations"]
        if not isinstance(observations, list) or len(
                observations) != STABILITY_REPETITIONS:
            raise ArtifactTamperError(
                "each candidate result must carry exactly "
                f"{STABILITY_REPETITIONS} repetition observations")

    recomputed_digest = canonical_sha256({
        "candidate_identity_digests": [
            result["candidate_id"] for result in results
        ],
    })
    if recomputed_digest != artifact["source_candidates_digest"]:
        raise ArtifactTamperError(
            f"source_candidates_digest mismatch: recorded "
            f"{artifact['source_candidates_digest']!r}, recomputed "
            f"{recomputed_digest!r} from the ordered candidate_ids")

    expected = {
        "objective_version": expected_objective_version,
        "weight_config_hash": expected_weight_config_hash,
        "background_artifact_hash": expected_background_artifact_hash,
        "service_topology_hash": expected_service_topology_hash,
        "source_candidates_digest": expected_source_candidates_digest,
        "response_phase_schema_version": expected_response_phase_schema_version,
    }
    for field, value in expected.items():
        if value is not None and artifact.get(field) != value:
            raise ArtifactIdentityMismatchError(
                f"artifact {field}={artifact.get(field)!r} differs from "
                f"expected {value!r}")
    return dict(artifact)

def load_stability_artifact(
    path: str,
    *,
    expected_objective_version: Optional[str] = None,
    expected_weight_config_hash: Optional[str] = None,
    expected_background_artifact_hash: Optional[str] = None,
    expected_service_topology_hash: Optional[str] = None,
    expected_source_candidates_digest: Optional[str] = None,
    expected_response_phase_schema_version: Optional[int] = None,
) -> dict:
    """Load + strictly validate one stability artifact file."""
    with open(path, "r", encoding="utf-8") as handle:
        artifact = json.load(handle)
    return validate_stability_artifact(
        artifact,
        expected_objective_version=expected_objective_version,
        expected_weight_config_hash=expected_weight_config_hash,
        expected_background_artifact_hash=expected_background_artifact_hash,
        expected_service_topology_hash=expected_service_topology_hash,
        expected_source_candidates_digest=expected_source_candidates_digest,
        expected_response_phase_schema_version=(
            expected_response_phase_schema_version),
    )

def write_stability_artifact(artifact: Mapping, path: str) -> str:
    """Write the artifact atomically (``.tmp`` + ``os.replace``)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    try:
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(artifact, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except BaseException:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise
    return str(target)
