"""Atomic, multi-probe-first, phase-aware rule-training corpus.

This module turns **stored**
candidate records (flat candidate-stream schema *or* public nested fingerprint
schema) into an *atomic* rule-training corpus:

- one corpus record ("atom") = one (cluster, member, phase) response of one
  observation of one candidate — never a whole multi-service candidate;
- multi-probe first: ``multi_probe`` / ``exploratory_multi_probe`` candidates
  contribute responses from **all** responding services (not only the mutation
  target) and form the main corpus; ``target_reachability`` candidates are a
  support channel that supplements any ``(cluster, member)`` pair;
- ``diagnostic_only`` and unknown candidate types never enter the corpus and
  are only counted/reported;
- phase-aware by default: connection-first and post-send bytes of one
  observation become separate atoms (the stored post phase is named
  ``post_payload`` for schema compatibility); a banner-only observation whose
  ``response_hex == banner_hex`` emits that byte sequence **once** as a banner
  sample.  Missing/``legacy_unknown`` phases fail fast in strict mode and are
  admitted only through an explicit allow-legacy mode that marks the corpus
  provenance as non-phase-aware;
- quotas per ``(cluster, member)`` are enforced through a stable-hash
  reservoir (deterministic ranking), so candidate **input order never affects
  the selected observations**; duplicate response bytes are kept as frequency
  (only later distinct-shape sampling operates on unique values);
- **unpartitioned (schema version 2)**: rules are constructed against the FULL
  observed response variety — the local fleet's labels are ground truth and
  the evaluation universe is closed, so no response-byte fit/dev/eval split
  exists.  Out-of-sample evidence comes from a later probe round whose packet
  identities are disjoint from the **construction packet universe** recorded
  here (``construction_packet_universe_digest``), not from hidden response
  bytes.  ``response_identity`` remains a global SHA256 of the normalized
  response bytes ONLY — identical bytes always share one identity, so
  distinct-response coverage is measurable without any extra bookkeeping;
- **identification clusters ≠ probe clusters (schema version 2)**: the probe-side
  cluster split (``services_config.cluster_of``) is preserved verbatim in
  ``cluster``; ``id_cluster`` applies ``IDENTIFICATION_CLUSTER_MERGE`` (e.g.
  mqttv311 + mqttv50 → mqtt) because dual-stack implementations make the
  version split unidentifiable from responses.  All rule-path grouping
  (pairs/counts/stats/gates) uses ``id_cluster``.

Every atom preserves the nested response shape consumed by the later Agent
code (``responses=[{"service": cluster, "responses":[{"service": member,
"response_hex": ..., "response_phase": ...}, ...]}]``) plus atom metadata.
Atom metadata (source candidate type, mutation target, cluster/id_cluster,
member, phase, packet identity, response identity, observation identity,
transport, iteration, qualification status, reprobe/stability source flag)
exists for sampling/analysis only — it is never used for runtime matching.

The corpus file is written atomically (``.tmp`` + ``os.replace``) as a JSON
array (streamed record by record), and a provenance sidecar is written
atomically **after** the corpus, binding the corpus file SHA256, the canonical
corpus digest, the source candidates digest, the schema version, the
construction packet universe digest, the identification-cluster merge map,
caps, provenance identities, phase-awareness mode and counts.  A consumer can
detect interrupted or mismatched corpus/provenance pairs through those
digests; strict loader/validator APIs recompute every digest and identity.
Superseded schema-v1 (partitioned) corpora are rejected with an explicit
error — they must be rebuilt, not migrated.
"""

from __future__ import annotations

import hashlib
import json
import os
from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional
from typing import Sequence, Set, Tuple

from config import (
    IDENTIFICATION_CLUSTER_MERGE,
    cluster_of,
    identification_cluster_of,
)
from core.candidate_collector import (
    CANDIDATE_DIAGNOSTIC_ONLY,
    CANDIDATE_EXPLORATORY_MULTI_PROBE,
    CANDIDATE_MULTI_PROBE,
    CANDIDATE_TARGET_REACHABILITY,
)

# ---------------------------------------------------------------------------
# Schema / version constants
# ---------------------------------------------------------------------------

RULE_CORPUS_SCHEMA_VERSION = 2

RULE_CORPUS_ARTIFACT_TYPE = "rule_training_corpus"
RULE_CORPUS_PROVENANCE_TYPE = "rule_training_corpus_provenance"

PRIMARY_CANDIDATE_TYPES = (
    CANDIDATE_MULTI_PROBE,
    CANDIDATE_EXPLORATORY_MULTI_PROBE,
)
SUPPORT_CANDIDATE_TYPES = (CANDIDATE_TARGET_REACHABILITY,)
#: Never enter the corpus; counted and reported only.
EXCLUDED_KNOWN_TYPES = (CANDIDATE_DIAGNOSTIC_ONLY,)

SOURCE_CLASS_PRIMARY = "primary"
SOURCE_CLASS_SUPPORT = "support"

RESPONSE_PHASE_POST_PAYLOAD = "post_payload"
RESPONSE_PHASE_PRE_PAYLOAD_BANNER = "pre_payload_banner"
KNOWN_RESPONSE_PHASES = (
    RESPONSE_PHASE_POST_PAYLOAD,
    RESPONSE_PHASE_PRE_PAYLOAD_BANNER,
)
LEGACY_RESPONSE_PHASE = "legacy_unknown"

SUPPORTED_TRANSPORTS = ("tcp", "udp")

PHASE_AWARENESS_STRICT = "strict"
PHASE_AWARENESS_ALLOW_LEGACY = "allow_legacy"

# Legacy response partition API is retained as a read-only compatibility
# helper for historical evaluation artifacts.  Schema version 2 corpus construction
# never writes or consumes these labels; new held-out evidence is probe-family
# based.  Keeping the pure function avoids breaking old reports while making
# the new artifact schema unambiguous.
SPLIT_SCHEMA_VERSION = 1
PARTITION_FIT = "fit"
PARTITION_DEV = "dev"
PARTITION_EVAL = "eval"
PARTITIONS = (PARTITION_FIT, PARTITION_DEV, PARTITION_EVAL)
DEFAULT_FIT_RATIO = 0.6
DEFAULT_DEV_RATIO = 0.2
DEFAULT_EVAL_RATIO = 0.2
DEFAULT_EVAL_SALT = "rule-corpus/partition/eval/v1"
DEFAULT_DEV_SALT = "rule-corpus/partition/dev/v1"

#: Stable-hash reservoir salt: ranks observations for quota selection.
RESERVOIR_SALT = "rule-corpus/reservoir/v1"
#: Domain-separation tag of the global response-byte identity.
RESPONSE_IDENTITY_TAG = "rule-corpus/response-identity/v1"
#: Domain-separation tag of the per-observation identity.
OBSERVATION_IDENTITY_TAG = "rule-corpus/observation-identity/v1"
#: Domain-separation tag of the packet identity.
PACKET_IDENTITY_TAG = "rule-corpus/packet-identity/v1"
#: Domain-separation tag of the canonical (order-independent) corpus digest.
CORPUS_DIGEST_TAG = "rule-corpus/corpus-digest/v1"
#: Domain-separation tag of the construction packet-universe digest.  The
#: universe is the set of packet identities of every selected atom; a later
#: validation round must prove its probes are disjoint from it.
CONSTRUCTION_UNIVERSE_TAG = "rule-corpus/construction-universe/v1"

#: Banner support atoms added per (cluster, member) pair when the selected
#: primary observations carry no banner sample.  (No existing config constant
#: covers this; the value mirrors the phase-3a specification.)
DEFAULT_BANNER_SUPPORT_CAP = 20

def _default_primary_cap() -> int:
    """Default per-pair primary observation cap (config-driven)."""
    import config

    return int(getattr(config, "RULE_GEN_SAMPLE_PER_CLUSTER", 400))

def _default_min_samples() -> int:
    """Default per-pair minimum observation count (config-driven)."""
    import config

    return int(getattr(config, "RULE_GEN_MIN_SAMPLES", 20))

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class RuleCorpusError(ValueError):
    """Base error for rule-corpus parsing / building / artifact failures."""

class LegacyPhaseUnknownError(RuleCorpusError):
    """Selected record without per-response phase facts in strict mode."""

class ConflictingDuplicateCandidateError(RuleCorpusError):
    """Two records share one candidate identity but differ in content."""

class MixedProvenanceError(RuleCorpusError):
    """Mixed non-empty objective/background/weight identities."""

class EmptyCorpusError(RuleCorpusError):
    """No selectable candidate produced any corpus atom."""

class CorpusTamperError(RuleCorpusError):
    """Corpus payload does not match its recorded digests / identities."""

class CorpusIdentityMismatchError(RuleCorpusError):
    """Corpus or provenance identity differs from an explicitly expected one."""

class RuleCorpusLegacyError(RuleCorpusError):
    """Schema-v1 (partitioned) corpus presented to the schema version 2 code path.

    v1 corpora are not migrated: the response-identity fit/dev/eval partition
    was removed by design;
    rebuild with ``scripts/build_rule_training_corpus.py`` instead.
    """

# ---------------------------------------------------------------------------
# Canonical hashing
# ---------------------------------------------------------------------------

def canonical_json(payload: Any) -> str:
    """Deterministic canonical JSON (sorted keys, compact separators)."""
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

def canonical_sha256(payload: Any) -> str:
    """SHA256 hex digest over the canonical JSON of ``payload``."""
    return hashlib.sha256(
        canonical_json(payload).encode("utf-8")).hexdigest()

def _tagged_sha256(tag: str, parts: Sequence[bytes]) -> str:
    """Length-prefixed SHA256 over tagged parts (no concatenation ambiguity)."""
    h = hashlib.sha256()
    h.update(tag.encode("utf-8"))
    for part in parts:
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.hexdigest()

# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------

IDENTITY_FIELDS: Tuple[str, ...] = (
    "transport", "mutation_target", "candidate_type", "packet_hex",
)

def candidate_identity(record: Mapping) -> Tuple[str, ...]:
    """Candidate identity ``(transport, mutation_target, candidate_type,
    packet_hex)``; ``packet_hex`` is normalized to lowercase."""
    candidate_type = str(
        record.get("candidate_type", "") or CANDIDATE_MULTI_PROBE)
    identity = (
        str(record.get("transport", "")).strip().lower(),
        str(record.get("mutation_target", "") or ""),
        candidate_type,
        str(record.get("packet_hex", "")).strip().lower(),
    )
    occurrence = record.get('candidate_occurrence_id')
    if occurrence is not None:
        if (not isinstance(occurrence, str) or len(occurrence) != 64
                or any(c not in '0123456789abcdef' for c in occurrence)):
            raise RuleCorpusError('candidate_occurrence_id must be a lowercase SHA256')
        return identity + (occurrence,)
    return identity

def candidate_identity_digest(record: Mapping) -> str:
    """Canonical SHA256 over the identity tuple."""
    return canonical_sha256(list(candidate_identity(record)))

def packet_identity(packet_hex: str) -> str:
    """Global SHA256 of the packet bytes only (lowercased hex accepted)."""
    return _tagged_sha256(PACKET_IDENTITY_TAG, [_parse_hex(packet_hex)])

def probe_family_identity(
    *,
    transport: str,
    mutation_target: str,
    parent_seed_id: str = "",
    parent_packet_hash: str = "",
    packet_hex: str = "",
) -> Tuple[str, str]:
    """Return ``(family_identity, basis)`` for probe-family holdout.

    A real family is rooted in the parent seed/packet lineage.  Historical
    records did not always preserve that lineage; they receive a deterministic
    packet fallback so corpora remain readable, but ``basis=packet_fallback``
    prevents such a corpus from claiming probe-family-disjoint validation.
    """
    transport = str(transport or "").strip().lower()
    mutation_target = str(mutation_target or "")
    parent_seed_id = str(parent_seed_id or "")
    parent_packet_hash = str(parent_packet_hash or "")
    if parent_seed_id or parent_packet_hash:
        return canonical_sha256({
            "method": "probe_family_lineage_v1",
            "transport": transport,
            "mutation_target": mutation_target,
            "parent_seed_id": parent_seed_id,
            "parent_packet_hash": parent_packet_hash,
        }), "lineage"
    return canonical_sha256({
        "method": "probe_family_packet_fallback_v1",
        "transport": transport,
        "mutation_target": mutation_target,
        "packet_identity": packet_identity(packet_hex),
    }), "packet_fallback"

def response_identity(response_hex: str) -> str:
    """Global deterministic SHA256 of the **normalized response bytes only**.

    Cluster, member, phase, transport and candidate metadata are deliberately
    excluded: identical response bytes must always share one identity
    everywhere in the corpus (which also makes distinct-response coverage
    measurable directly from response-hex counters).
    """
    return _tagged_sha256(RESPONSE_IDENTITY_TAG, [_parse_hex(response_hex)])

def observation_identity(
    candidate_id: str,
    member: str,
    phase: str,
    response_hex: str,
) -> str:
    """SHA256 over (candidate_id, member, phase, response bytes).

    Two emissions of one observation (banner + post) differ in ``phase``;
    the same byte sequence observed under different candidates differs in
    ``candidate_id`` — frequency is preserved while content stays linkable.
    """
    return _tagged_sha256(OBSERVATION_IDENTITY_TAG, [
        candidate_id.encode("utf-8"),
        member.encode("utf-8"),
        phase.encode("utf-8"),
        _parse_hex(response_hex),
    ])

def _reservoir_rank(observation_identity_hex: str) -> Tuple[bytes, str]:
    """Stable rank key for deterministic quota selection."""
    digest = hashlib.sha256(
        RESERVOIR_SALT.encode("utf-8")
        + observation_identity_hex.encode("utf-8")).digest()
    return digest, observation_identity_hex

def _legacy_hash_fraction(salt: str, identity: str) -> float:
    digest = hashlib.sha256(
        salt.encode("utf-8") + identity.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / float(1 << 64)

def partition_for_response_identity(
    response_identity_hex: str, *, fit_ratio: float = DEFAULT_FIT_RATIO,
    dev_ratio: float = DEFAULT_DEV_RATIO, eval_ratio: float = DEFAULT_EVAL_RATIO,
    eval_salt: str = DEFAULT_EVAL_SALT, dev_salt: str = DEFAULT_DEV_SALT,
) -> str:
    """Deprecated deterministic partition resolver for historical reports."""
    ratios = tuple(float(value) for value in
                   (fit_ratio, dev_ratio, eval_ratio))
    if any(value <= 0.0 for value in ratios) or abs(sum(ratios) - 1.0) > 1e-9:
        raise ValueError("legacy partition ratios must be positive and sum to 1")
    if _legacy_hash_fraction(eval_salt, response_identity_hex) < eval_ratio:
        return PARTITION_EVAL
    conditional_dev = dev_ratio / (1.0 - eval_ratio)
    if _legacy_hash_fraction(dev_salt, response_identity_hex) < conditional_dev:
        return PARTITION_DEV
    return PARTITION_FIT

# ---------------------------------------------------------------------------
# Construction view + packet universe (schema version 2)
# ---------------------------------------------------------------------------

#: Method identity of the construction view recorded in provenance.  A
#: validation round proves out-of-sample status against this universe.
CONSTRUCTION_VIEW_METHOD = "rule_corpus_construction_full_view_v1"
CONSTRUCTION_SCHEMA_VERSION = 1

def _construction_universe_digest(packet_identities: Set[str]) -> str:
    """Canonical digest over the sorted set of construction packet identities."""
    return canonical_sha256({
        "method": CONSTRUCTION_UNIVERSE_TAG,
        "packet_identities": sorted(packet_identities),
    })

def construction_block(packet_identities: Iterable[str],
                       identification_cluster_merge: Mapping[str, str],
                       probe_families: Iterable[Tuple[str, str]] = ()) -> dict:
    """The provenance ``construction`` block binding the full view identity.

    One nested field so downstream consumers (bundle provenance, evaluation
    manifests, validation-round reports) copy the whole construction context
    verbatim instead of enumerating flat fields.
    """
    identities = {str(value) for value in packet_identities}
    families = {(str(identity), str(basis))
                for identity, basis in probe_families}
    family_ids = {identity for identity, _basis in families}
    return {
        "schema_version": CONSTRUCTION_SCHEMA_VERSION,
        "view": "full_corpus",
        "method": CONSTRUCTION_VIEW_METHOD,
        "held_out_axis": "fresh_probe_family_disjoint_round",
        "packet_universe_digest": _construction_universe_digest(identities),
        "packet_universe_size": len(identities),
        "probe_family_universe_digest": canonical_sha256({
            "method": "probe_family_universe_v1",
            "probe_family_identities": sorted(family_ids),
        }),
        "probe_family_universe_size": len(family_ids),
        "probe_family_lineage_complete": bool(families) and all(
            basis == "lineage" for _identity, basis in families),
        "identification_cluster_merge": dict(identification_cluster_merge),
    }

# ---------------------------------------------------------------------------
# Record parsing (flat candidate-stream + public nested schemas)
# ---------------------------------------------------------------------------

def _parse_hex(value: Any, *, field: str = "hex field") -> bytes:
    text = str(value or "").strip().lower()
    if not text:
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise RuleCorpusError(f"{field} is not valid hex: {exc}") from exc

def _iter_member_observations(record: Mapping) -> List[dict]:
    """Flatten either stored schema into member observations.

    Flat candidate-stream schema:
        ``responses = [{service, response_hex, banner_hex, response_phase,
        latency_ms, banner_latency_ms, payload_latency_ms}, ...]``

    Public nested schema:
        ``responses = [{service: <cluster>, responses: [{service: <member>,
        response_hex, ...}, ...]}, ...]``
    """
    responses = record.get("responses", [])
    if not isinstance(responses, list):
        raise RuleCorpusError(
            f"record 'responses' must be a list, got "
            f"{type(responses).__name__}")
    observations: List[dict] = []
    for entry in responses:
        if not isinstance(entry, dict):
            raise RuleCorpusError(
                f"record 'responses' entries must be dicts, got "
                f"{type(entry).__name__}")
        if isinstance(entry.get("responses"), list):
            for member in entry["responses"]:
                if not isinstance(member, dict):
                    raise RuleCorpusError(
                        "nested member entries must be dicts")
                item = dict(member)
                item.setdefault("service", "")
                observations.append(item)
        else:
            observations.append(entry)
    return observations

def candidate_source_class(candidate_type: str) -> Optional[str]:
    """:data:`SOURCE_CLASS_PRIMARY` / :data:`SOURCE_CLASS_SUPPORT`, or ``None``
    when the type never enters the corpus (diagnostic / unknown)."""
    if candidate_type in PRIMARY_CANDIDATE_TYPES:
        return SOURCE_CLASS_PRIMARY
    if candidate_type in SUPPORT_CANDIDATE_TYPES:
        return SOURCE_CLASS_SUPPORT
    return None

@dataclass(frozen=True)
class RuleCandidate:
    """Normalized view of one corpus-eligible stored candidate record."""

    identity: Tuple[str, ...]
    source_class: str
    packet_hex: str
    mutation_target: str
    candidate_type: str
    transport: str
    iteration: int
    qualification_status: str
    objective_version: str
    weight_config_hash: str
    background_artifact_hash: str
    parent_seed_id: str
    parent_packet_hash: str
    probe_family_identity: str
    probe_family_basis: str
    from_reprobe_source: bool
    phase_aware: bool
    content_digest: str
    observations: Tuple[dict, ...]
    candidate_occurrence_id: str = ''

    @property
    def identity_digest(self) -> str:
        return canonical_sha256(list(self.identity))

def _parse_observation(item: Mapping) -> dict:
    member = str(item.get("service", "") or "")
    if not member:
        raise RuleCorpusError(
            "member observation carries an empty 'service'; (cluster, "
            "member) attribution is impossible")
    response_hex = str(item.get("response_hex", "") or "").strip().lower()
    banner_hex = str(item.get("banner_hex", "") or "").strip().lower()
    _parse_hex(response_hex, field=f"response_hex of member {member!r}")
    _parse_hex(banner_hex, field=f"banner_hex of member {member!r}")
    return {
        "member": member,
        "cluster": cluster_of(member),
        "response_hex": response_hex,
        "banner_hex": banner_hex,
        "response_phase": str(item.get("response_phase", "") or ""),
        "latency_ms": float(item.get("latency_ms", 0.0) or 0.0),
        "banner_latency_ms": float(
            item.get("banner_latency_ms", 0.0) or 0.0),
        "payload_latency_ms": float(
            item.get("payload_latency_ms", 0.0) or 0.0),
    }

def parse_rule_candidate(
    record: Mapping,
    *,
    strict_phase_aware: bool = True,
) -> RuleCandidate:
    """Validate + normalize one stored candidate record for corpus building.

    Fail-fast errors (a *selected* record must never be silently dropped):
      - non-mapping record; missing/invalid ``packet_hex``; missing
        ``mutation_target``; ``transport`` outside tcp/udp; malformed
        ``responses`` structure; empty member ``service``; invalid hex;
      - strict phase-aware mode and any observation lacks a known
        ``response_phase`` (missing or ``legacy_unknown``)
        → :class:`LegacyPhaseUnknownError`.

    ``from_reprobe_source`` is derived from optional record metadata
    (``from_reprobe`` / ``source_kind`` in {"reprobe", "stability"} /
    ``stability_source``); when no such metadata exists the flag is simply
    absent downstream.
    """
    if not isinstance(record, Mapping):
        raise RuleCorpusError(
            f"candidate record must be a mapping, got "
            f"{type(record).__name__}")

    packet_hex = str(record.get("packet_hex", "") or "").strip().lower()
    if not packet_hex:
        raise RuleCorpusError("candidate record missing packet_hex")
    _parse_hex(packet_hex, field="packet_hex")

    mutation_target = str(record.get("mutation_target", "") or "")
    if not mutation_target:
        raise RuleCorpusError(
            "candidate record missing mutation_target; corpus atoms are "
            "multi-probe-first and must carry their mutation target")

    transport = str(record.get("transport", "") or "").strip().lower()
    if transport not in SUPPORTED_TRANSPORTS:
        raise RuleCorpusError(
            f"candidate transport must be one of {SUPPORTED_TRANSPORTS}, "
            f"got {transport!r}")

    candidate_type = str(
        record.get("candidate_type", "") or CANDIDATE_MULTI_PROBE)
    source_class = candidate_source_class(candidate_type)
    if source_class is None:
        # Selection must filter unsupported types before parsing; reaching
        # this point means a skipped type leaked into the strict parser.
        raise RuleCorpusError(
            f"candidate_type {candidate_type!r} never enters the rule corpus "
            f"(primary={PRIMARY_CANDIDATE_TYPES}, support="
            f"{SUPPORT_CANDIDATE_TYPES})")

    observations = tuple(
        _parse_observation(item)
        for item in _iter_member_observations(record))
    phase_aware = bool(observations) and all(
        obs["response_phase"] in KNOWN_RESPONSE_PHASES
        for obs in observations)
    if strict_phase_aware and observations and not phase_aware:
        raise LegacyPhaseUnknownError(
            "strict phase-aware mode rejected a selected record without "
            "per-response phase facts (missing or legacy_unknown "
            "response_phase); rerun with allow-legacy to admit it explicitly")

    source_kind = str(record.get("source_kind", "") or "").strip().lower()
    from_reprobe = bool(
        record.get("from_reprobe", False)
        or record.get("stability_source", False)
        or source_kind in ("reprobe", "stability"))

    family_identity, family_basis = probe_family_identity(
        transport=transport,
        mutation_target=mutation_target,
        parent_seed_id=str(record.get("parent_seed_id", "") or ""),
        parent_packet_hash=str(record.get("parent_packet_hash", "") or ""),
        packet_hex=packet_hex,
    )
    return RuleCandidate(
        identity=candidate_identity(record),
        source_class=source_class,
        packet_hex=packet_hex,
        mutation_target=mutation_target,
        candidate_type=candidate_type,
        transport=transport,
        iteration=int(record.get("iteration", 0) or 0),
        qualification_status=str(record.get("qualification_status", "") or ""),
        objective_version=str(record.get("objective_version", "") or ""),
        weight_config_hash=str(record.get("weight_config_hash", "") or ""),
        background_artifact_hash=str(
            record.get("background_artifact_hash", "") or ""),
        parent_seed_id=str(record.get("parent_seed_id", "") or ""),
        parent_packet_hash=str(record.get("parent_packet_hash", "") or ""),
        probe_family_identity=family_identity,
        probe_family_basis=family_basis,
        from_reprobe_source=from_reprobe,
        phase_aware=phase_aware,
        content_digest=canonical_sha256(record),
        observations=observations,
        candidate_occurrence_id=str(record.get('candidate_occurrence_id') or ''),
    )

# ---------------------------------------------------------------------------
# Phase expansion: one observation → atomic samples
# ---------------------------------------------------------------------------

def expand_candidate_atoms(candidate: RuleCandidate) -> List[dict]:
    """Expand one candidate into atomic (cluster, member, phase) samples.

    Emission rules:
      - a nonempty ``banner_hex`` emits one banner sample
        (``pre_payload_banner``);
      - a nonempty ``response_hex`` emits one sample at its stored phase
        (``post_payload`` for phase-aware records, ``legacy_unknown`` under
        allow-legacy);
      - banner-only compatibility observations whose ``response_hex ==
        banner_hex`` emit that byte sequence **once** as a banner sample,
        never twice;
      - duplicate member emissions inside one candidate (same observation
        identity) are emitted once.
    """
    atoms: List[dict] = []
    seen: Set[str] = set()
    for obs in candidate.observations:
        post_hex = obs["response_hex"]
        banner_hex = obs["banner_hex"]
        # ``response_bytes`` mirrors ``banner_bytes`` for a banner-only
        # ServiceResponse because the former is the legacy compatibility
        # field.  Collapse only that explicit pre-payload case.  A genuine
        # Banner+post observation remains two phase-labelled samples even
        # when both reads happen to return identical bytes.
        equal_mirror = (
            obs["response_phase"] == RESPONSE_PHASE_PRE_PAYLOAD_BANNER
            and bool(post_hex)
            and post_hex == banner_hex
        )
        emissions: List[Tuple[str, str, Dict[str, float]]] = []
        if equal_mirror:
            # Compatibility banner-only mirror: one banner sample, once.
            emissions.append((
                banner_hex, RESPONSE_PHASE_PRE_PAYLOAD_BANNER,
                {"banner_latency_ms": obs["banner_latency_ms"],
                 "latency_ms": obs["banner_latency_ms"]},
            ))
        else:
            if banner_hex:
                emissions.append((
                    banner_hex, RESPONSE_PHASE_PRE_PAYLOAD_BANNER,
                    {"banner_latency_ms": obs["banner_latency_ms"],
                     "latency_ms": obs["banner_latency_ms"]},
                ))
            if post_hex:
                phase = obs["response_phase"]
                if phase not in KNOWN_RESPONSE_PHASES:
                    phase = LEGACY_RESPONSE_PHASE
                emissions.append((
                    post_hex, phase,
                    {"payload_latency_ms": obs["payload_latency_ms"],
                     "latency_ms": obs["latency_ms"]},
                ))
        for response_hex, phase, latencies in emissions:
            atom = {
                "candidate_id": candidate.identity_digest,
                "observation_identity": observation_identity(
                    candidate.identity_digest, obs["member"], phase,
                    response_hex),
                "packet_identity": packet_identity(candidate.packet_hex),
                "probe_family_identity": candidate.probe_family_identity,
                "probe_family_basis": candidate.probe_family_basis,
                "parent_seed_id": candidate.parent_seed_id,
                "parent_packet_hash": candidate.parent_packet_hash,
                "response_identity": response_identity(response_hex),
                "source_class": candidate.source_class,
                "source_candidate_type": candidate.candidate_type,
                "mutation_target": candidate.mutation_target,
                "cluster": obs["cluster"],
                "member": obs["member"],
                "phase": phase,
                "transport": candidate.transport,
                "iteration": candidate.iteration,
                "qualification_status": candidate.qualification_status,
                "packet_hex": candidate.packet_hex,
                "response_hex": response_hex,
                "latency_ms": latencies["latency_ms"],
                "banner_latency_ms": latencies.get("banner_latency_ms", 0.0),
                "payload_latency_ms": latencies.get("payload_latency_ms", 0.0),
            }
            if candidate.from_reprobe_source:
                atom["from_reprobe_source"] = True
            if candidate.candidate_occurrence_id:
                atom['candidate_occurrence_id'] = candidate.candidate_occurrence_id
            if atom["observation_identity"] in seen:
                continue  # never emit one observation identity twice
            seen.add(atom["observation_identity"])
            atoms.append(atom)
    return atoms

# ---------------------------------------------------------------------------
# Deterministic quota selection (stable-hash reservoir)
# ---------------------------------------------------------------------------

class _TopK:
    """Bounded reservoir keeping the k smallest rank keys (0 keeps nothing)."""

    def __init__(self, k: int) -> None:
        self.k = int(k)
        self._keys: List[Tuple[bytes, str]] = []
        self._atoms: List[dict] = []

    def add(self, atom: dict) -> None:
        if self.k <= 0:
            return
        key = _reservoir_rank(atom["observation_identity"])
        if len(self._atoms) >= self.k and key >= self._keys[-1]:
            return
        position = bisect_left(self._keys, key)
        self._keys.insert(position, key)
        self._atoms.insert(position, atom)
        if len(self._atoms) > self.k:
            self._keys.pop()
            self._atoms.pop()

    def sorted_atoms(self) -> List[dict]:
        return list(self._atoms)

    def __len__(self) -> int:
        return len(self._atoms)

class _IdentityExemplars:
    """Retain the lowest-ranked deterministic exemplar per response identity."""

    def __init__(self) -> None:
        self._by_identity: Dict[str, Tuple[Tuple[bytes, str], dict]] = {}

    def add(self, atom: dict) -> None:
        identity = str(atom["response_identity"])
        rank = _reservoir_rank(atom["observation_identity"])
        current = self._by_identity.get(identity)
        if current is None or rank < current[0]:
            self._by_identity[identity] = (rank, atom)

    def sorted_atoms(self) -> List[dict]:
        return [item[1] for item in sorted(
            self._by_identity.values(), key=lambda item: item[0])]

    def __len__(self) -> int:
        return len(self._by_identity)

class _PairSelection:
    """Per-(cluster, member) quota state."""

    def __init__(self, primary_cap: int, min_samples: int,
                 banner_support_cap: int) -> None:
        self.primary = _TopK(primary_cap)
        self.primary_identities = _IdentityExemplars()
        self.support_all = _TopK(min_samples)
        self.support_banner = _TopK(banner_support_cap)
        self.primary_available = 0
        self.support_available = 0
        self.support_banner_available = 0

    def add(self, atom: dict) -> None:
        if atom["source_class"] == SOURCE_CLASS_PRIMARY:
            self.primary_available += 1
            self.primary.add(atom)
            self.primary_identities.add(atom)
        else:
            self.support_available += 1
            self.support_all.add(atom)
            if atom["phase"] == RESPONSE_PHASE_PRE_PAYLOAD_BANNER:
                self.support_banner_available += 1
                self.support_banner.add(atom)

    def select(self, *, min_samples: int, banner_support_cap: int) -> List[dict]:
        """Deterministic per-pair selection.

        1. primary observations (at most ``primary_cap``, ranked);
        2. if fewer than ``min_samples`` were selected, supplement from
           target_reachability until ``min_samples`` or exhausted;
        3. if support holds banner samples but the selected primary has no
           banner sample, add up to ``banner_support_cap`` banner support
           observations (excluding already selected ones), even if that
           exceeds ``min_samples``.
        """

        selected = self.primary_identities.sorted_atoms()
        target_count = max(self.primary.k, len(selected))
        selected_observations = {
            atom["observation_identity"] for atom in selected}
        for atom in self.primary.sorted_atoms():
            if len(selected) >= target_count:
                break
            if atom["observation_identity"] in selected_observations:
                continue
            selected.append(atom)
            selected_observations.add(atom["observation_identity"])
        primary_has_banner = any(
            atom["phase"] == RESPONSE_PHASE_PRE_PAYLOAD_BANNER
            for atom in selected)
        if len(selected) < min_samples:
            for atom in self.support_all.sorted_atoms():
                if len(selected) >= min_samples:
                    break
                selected.append(atom)
        if (self.support_banner_available > 0
                and not primary_has_banner and banner_support_cap > 0):
            already = {
                atom["observation_identity"]
                for atom in selected
                if atom["source_class"] == SOURCE_CLASS_SUPPORT
            }
            added = 0
            for atom in self.support_banner.sorted_atoms():
                if added >= banner_support_cap:
                    break
                if atom["observation_identity"] in already:
                    continue
                selected.append(atom)
                added += 1
        return selected

# ---------------------------------------------------------------------------
# Provenance merging (fail-fast)
# ---------------------------------------------------------------------------

_PROVENANCE_FIELDS = (
    "objective_version", "weight_config_hash", "background_artifact_hash",
)

def merge_provenance(
    candidates: Sequence[RuleCandidate],
    *,
    objective_version: str = "",
    weight_config_hash: str = "",
    background_artifact_hash: str = "",
) -> Dict[str, str]:
    """Merge provenance identities; mixed non-empty values fail fast."""
    explicit = {
        "objective_version": objective_version or "",
        "weight_config_hash": weight_config_hash or "",
        "background_artifact_hash": background_artifact_hash or "",
    }
    merged: Dict[str, str] = {}
    for name in _PROVENANCE_FIELDS:
        values = sorted({
            getattr(candidate, name)
            for candidate in candidates
            if getattr(candidate, name)
        })
        argument = explicit[name]
        if len(values) > 1:
            raise MixedProvenanceError(
                f"mixed non-empty {name} across candidate records: {values}")
        if argument and values and values != [argument]:
            raise MixedProvenanceError(
                f"explicit {name}={argument!r} conflicts with record value "
                f"{values[0]!r}")
        merged[name] = argument if argument else (values[0] if values else "")
    return merged

# ---------------------------------------------------------------------------
# Corpus building
# ---------------------------------------------------------------------------

@dataclass
class CorpusBuildReport:
    """Explicit accounting of candidates/atoms kept, skipped, selected."""

    selected_candidates: int = 0
    selected_primary: int = 0
    selected_support: int = 0
    duplicate_identity_deduped: int = 0
    skipped_candidate_types: Dict[str, int] = field(default_factory=dict)
    atoms_total: int = 0
    atoms_by_source: Dict[str, int] = field(default_factory=dict)
    atoms_by_phase: Dict[str, int] = field(default_factory=dict)
    selected_atoms: int = 0

    def summary(self) -> str:
        skipped = " ".join(
            f"{ctype}={count}"
            for ctype, count in sorted(self.skipped_candidate_types.items())
        ) or "none"
        return (
            f"candidates[selected={self.selected_candidates} "
            f"primary={self.selected_primary} "
            f"support={self.selected_support}] "
            f"skipped_candidate_types[{skipped}] "
            f"duplicate_identity_deduped={self.duplicate_identity_deduped} "
            f"atoms[expanded={self.atoms_total} "
            f"selected={self.selected_atoms}]")

@dataclass
class RuleCorpusBuild:
    """In-memory corpus build: sorted atoms + provenance + report."""

    atoms: List[dict]
    provenance: dict
    report: CorpusBuildReport

def _select_candidates(
    records: Iterable[Mapping],
    *,
    strict_phase_aware: bool,
    limit: int,
    report: CorpusBuildReport,
) -> List[RuleCandidate]:
    """Filter candidate types, dedupe identity, parse strictly (fail-fast).

    - ``multi_probe`` / ``exploratory_multi_probe`` → primary;
    - ``target_reachability`` → support;
    - ``diagnostic_only`` and unknown types → skipped + counted;
    - exact duplicate identities (same identity **and** same canonical
      content) are deterministically deduplicated;
    - conflicting duplicates (same identity, different content) fail fast.
    """
    selected: List[RuleCandidate] = []
    seen: Dict[str, str] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise RuleCorpusError(
                f"candidate record must be a mapping, got "
                f"{type(record).__name__}")
        candidate_type = str(
            record.get("candidate_type", "") or CANDIDATE_MULTI_PROBE)
        if candidate_source_class(candidate_type) is None:
            report.skipped_candidate_types[candidate_type] = (
                report.skipped_candidate_types.get(candidate_type, 0) + 1)
            continue
        candidate = parse_rule_candidate(
            record, strict_phase_aware=strict_phase_aware)
        previous = seen.get(candidate.identity_digest)
        if previous is not None:
            if previous != candidate.content_digest:
                raise ConflictingDuplicateCandidateError(
                    f"conflicting duplicate candidate identity "
                    f"{candidate.identity}: same identity carries different "
                    f"content (digests {previous} vs {candidate.content_digest})"
                )
            report.duplicate_identity_deduped += 1
            continue
        seen[candidate.identity_digest] = candidate.content_digest
        selected.append(candidate)
        if limit > 0 and len(selected) >= limit:
            break
    return selected

def build_rule_corpus(
    records: Iterable[Mapping],
    *,
    allow_legacy: bool = False,
    primary_cap: Optional[int] = None,
    min_samples: Optional[int] = None,
    banner_support_cap: int = DEFAULT_BANNER_SUPPORT_CAP,
    objective_version: str = "",
    weight_config_hash: str = "",
    background_artifact_hash: str = "",
    limit: int = 0,
    created_at: Optional[str] = None,
) -> RuleCorpusBuild:
    """Build the atomic rule-training corpus from stored candidate records.

    Quotas are enforced per ``(id_cluster, member)`` through a stable-hash
    reservoir, so the selected observations — and therefore the output atoms,
    the canonical corpus digest and the source candidates digest — are
    independent of candidate input order.  Duplicate response bytes are kept
    as frequency (one atom per observation) and share one global response
    identity.  Atoms carry both ``cluster`` (probe-side, traceability) and
    ``id_cluster`` (identification grouping via ``IDENTIFICATION_CLUSTER_MERGE``).
    """
    cap = _default_primary_cap() if primary_cap is None else int(primary_cap)
    minimum = (
        _default_min_samples() if min_samples is None else int(min_samples))
    banner_cap = int(banner_support_cap)
    if cap < 1:
        raise RuleCorpusError(f"primary_cap must be >= 1, got {cap}")
    if minimum < 0:
        raise RuleCorpusError(f"min_samples must be >= 0, got {minimum}")
    if banner_cap < 0:
        raise RuleCorpusError(
            f"banner_support_cap must be >= 0, got {banner_cap}")
    if limit < 0:
        raise RuleCorpusError(f"limit must be >= 0, got {limit}")

    report = CorpusBuildReport()
    selected = _select_candidates(
        records,
        strict_phase_aware=not allow_legacy,
        limit=limit,
        report=report,
    )
    report.selected_candidates = len(selected)
    report.selected_primary = sum(
        1 for c in selected if c.source_class == SOURCE_CLASS_PRIMARY)
    report.selected_support = sum(
        1 for c in selected if c.source_class == SOURCE_CLASS_SUPPORT)
    if not selected:
        raise EmptyCorpusError(
            "no selectable candidates (multi_probe / "
            "exploratory_multi_probe / target_reachability); nothing to "
            f"build; selection report: {report.summary()}")

    provenance = merge_provenance(
        selected,
        objective_version=objective_version,
        weight_config_hash=weight_config_hash,
        background_artifact_hash=background_artifact_hash,
    )

    pairs: Dict[Tuple[str, str], _PairSelection] = {}
    for candidate in sorted(selected, key=lambda c: c.identity):
        for atom in expand_candidate_atoms(candidate):
            report.atoms_total += 1
            report.atoms_by_source[atom["source_class"]] = (
                report.atoms_by_source.get(atom["source_class"], 0) + 1)
            report.atoms_by_phase[atom["phase"]] = (
                report.atoms_by_phase.get(atom["phase"], 0) + 1)
            atom["id_cluster"] = identification_cluster_of(atom["cluster"])
            pair = pairs.setdefault(
                (atom["id_cluster"], atom["member"]),
                _PairSelection(cap, minimum, banner_cap))
            pair.add(atom)

    atoms: List[dict] = []
    for pair_key in sorted(pairs):
        atoms.extend(
            pairs[pair_key].select(
                min_samples=minimum, banner_support_cap=banner_cap))

    if not atoms:
        raise EmptyCorpusError(
            "selected candidates produced no response observations; nothing "
            f"to build; selection report: {report.summary()}")

    atoms.sort(key=lambda atom: atom["observation_identity"])
    report.selected_atoms = len(atoms)

    source_candidates_digest = canonical_sha256({
        "candidate_identity_digests": [
            candidate.identity_digest
            for candidate in sorted(selected, key=lambda c: c.identity)
        ],
    })
    provenance_doc = {
        "schema_version": RULE_CORPUS_SCHEMA_VERSION,
        "artifact_type": RULE_CORPUS_PROVENANCE_TYPE,
        "corpus_schema_version": RULE_CORPUS_SCHEMA_VERSION,
        "source_candidates_digest": source_candidates_digest,
        # Allow-legacy runs are non-phase-aware as a whole: the mode flag is
        # the authoritative marker (even if no legacy sample happened to be
        # emitted), so consumers never need atom-level inference.
        "phase_aware": not allow_legacy,
        "phase_awareness_mode": (
            PHASE_AWARENESS_ALLOW_LEGACY if allow_legacy
            else PHASE_AWARENESS_STRICT),
        "construction": construction_block(
            (atom["packet_identity"] for atom in atoms),
            IDENTIFICATION_CLUSTER_MERGE,
            ((atom["probe_family_identity"], atom["probe_family_basis"])
             for atom in atoms)),
        "caps": {
            "primary": cap,
            "min_samples": minimum,
            "banner_support": banner_cap,
        },
        "objective_version": provenance["objective_version"],
        "weight_config_hash": provenance["weight_config_hash"],
        "background_artifact_hash": provenance["background_artifact_hash"],
        "counts": _build_counts(report, atoms, pairs),
        "created_at": created_at or datetime.now(
            timezone.utc).isoformat(timespec="seconds"),
    }
    return RuleCorpusBuild(
        atoms=atoms, provenance=provenance_doc, report=report)

def _atom_responses_entry(atom: Mapping) -> dict:
    """Nested response shape retained by every corpus atom."""
    member_response: Dict[str, Any] = {
        "service": atom["member"],
        "response_hex": atom["response_hex"],
        "response_phase": atom["phase"],
        "latency_ms": atom["latency_ms"],
    }
    if atom["phase"] == RESPONSE_PHASE_PRE_PAYLOAD_BANNER:
        member_response["banner_latency_ms"] = atom["banner_latency_ms"]
    else:
        member_response["payload_latency_ms"] = atom["payload_latency_ms"]
    return {"service": atom["cluster"], "responses": [member_response]}

def corpus_atom_record(atom: Mapping) -> dict:
    """Serialize one selected atom into its durable corpus record shape.

    Accepts both a freshly built atom (no ``responses`` yet — the nested
    entry is constructed) and an already durable corpus record (passed
    through, so loaded/tampered records can be rewritten byte-compatibly).
    """
    record: Dict[str, Any] = dict(atom)
    record.setdefault("schema_version", RULE_CORPUS_SCHEMA_VERSION)
    if "responses" not in record:
        record["response_hex"] = atom["response_hex"]
        record["responses"] = [_atom_responses_entry(atom)]
    if record.get("from_reprobe_source"):
        record["from_reprobe_source"] = True
    return record

def _build_counts(
    report: CorpusBuildReport,
    atoms: List[dict],
    pairs: Dict[Tuple[str, str], _PairSelection],
) -> dict:
    pair_counts: Dict[str, dict] = {}
    for pair_key in sorted(pairs):
        id_cluster, member = pair_key
        pair_atoms = [
            atom for atom in atoms
            if atom["id_cluster"] == id_cluster and atom["member"] == member]
        probe_clusters = sorted({atom["cluster"] for atom in pair_atoms})
        pair_counts[f"{id_cluster}/{member}"] = {
            "primary": sum(
                1 for atom in pair_atoms
                if atom["source_class"] == SOURCE_CLASS_PRIMARY),
            "support": sum(
                1 for atom in pair_atoms
                if atom["source_class"] == SOURCE_CLASS_SUPPORT),
            "atoms": len(pair_atoms),
            "probe_clusters": probe_clusters,
            "unique_response_identities": len({
                atom["response_identity"] for atom in pair_atoms}),
        }
    unique_identities = {atom["response_identity"] for atom in atoms}
    return {
        "candidates": {
            "selected": report.selected_candidates,
            "selected_primary": report.selected_primary,
            "selected_support": report.selected_support,
            "duplicate_identity_deduped": report.duplicate_identity_deduped,
            "skipped_candidate_types": dict(
                sorted(report.skipped_candidate_types.items())),
        },
        "atoms": {
            "total": len(atoms),
            "by_source": {
                key: report.atoms_by_source.get(key, 0)
                for key in (SOURCE_CLASS_PRIMARY, SOURCE_CLASS_SUPPORT)
            },
            "by_phase": dict(sorted(report.atoms_by_phase.items())),
            "unique_response_identities": len(unique_identities),
        },
        "pairs": pair_counts,
    }

# ---------------------------------------------------------------------------
# Atomic writers
# ---------------------------------------------------------------------------

def _corpus_digest_update(hasher: Any, blob: str) -> None:
    encoded = blob.encode("utf-8")
    hasher.update(len(encoded).to_bytes(8, "big"))
    hasher.update(encoded)

def write_rule_corpus(atoms: Sequence[Mapping], output_path: str) -> dict:
    """Stream the sorted corpus atoms to ``output_path`` atomically.

    The JSON array is written record by record (``[`` then records), so
    memory does not double during serialization.  Returns the output path,
    the file SHA256 (over the exact bytes written) and the canonical corpus
    digest (order- and whitespace-independent, computed over the atoms).
    """
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    file_hasher = hashlib.sha256()
    corpus_hasher = hashlib.sha256(CORPUS_DIGEST_TAG.encode("utf-8"))
    try:
        with open(temp, "w", encoding="utf-8", newline="\n") as handle:
            def emit(text: str) -> None:
                handle.write(text)
                file_hasher.update(text.encode("utf-8"))

            emit("[\n")
            for index, atom in enumerate(atoms):
                blob = canonical_json(corpus_atom_record(atom))
                _corpus_digest_update(corpus_hasher, blob)
                if index:
                    emit(",\n")
                emit(blob)
            emit("\n]\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except BaseException:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise
    return {
        "output_path": str(target),
        "file_sha256": file_hasher.hexdigest(),
        "corpus_digest": corpus_hasher.hexdigest(),
        "atom_count": len(atoms),
    }

def finalize_corpus_provenance(provenance: dict, corpus_info: Mapping) -> dict:
    """Bind corpus file digests into the provenance sidecar document."""
    finalized = dict(provenance)
    finalized["corpus_path"] = str(corpus_info["output_path"])
    finalized["corpus_file_sha256"] = str(corpus_info["file_sha256"])
    finalized["corpus_digest"] = str(corpus_info["corpus_digest"])
    finalized["corpus_atom_count"] = int(corpus_info["atom_count"])
    return finalized

def write_corpus_provenance(provenance: Mapping, path: str) -> str:
    """Write the provenance sidecar atomically (``.tmp`` + ``os.replace``)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(provenance, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
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

def default_provenance_path(corpus_path: str) -> str:
    """``<output>.provenance.json`` sidecar convention."""
    return f"{corpus_path}.provenance.json"

def derive_lineage_complete_rule_corpus(
    corpus_path: str,
    output_path: str,
    *,
    provenance_path: Optional[str] = None,
    provenance_output: Optional[str] = None,
    created_at: Optional[str] = None,
) -> dict:
    """Derive a strict construction view containing lineage-backed atoms only.

    Historical candidate observations may carry only packet-fallback probe
    families.  They are legitimate construction evidence, but they make a
    formal probe-family-disjoint challenge impossible to prove.  This helper
    does **not** weaken that proof.  It validates the source pair, removes only
    ``probe_family_basis != 'lineage'`` atoms, recomputes every corpus and
    construction identity, and writes a new independently bound corpus pair.

    Existing rules must be revalidated/frozen against the derived corpus
    before it can be used for E0; this function deliberately does not copy or
    bless any rule state.
    """
    atoms, source = load_rule_corpus(corpus_path, provenance_path)
    retained = [atom for atom in atoms
                if atom.get("probe_family_basis") == "lineage"]
    if not retained:
        raise EmptyCorpusError(
            "lineage-complete construction view would be empty")

    candidate_ids = {atom["candidate_id"] for atom in retained}
    candidate_source = {
        atom["candidate_id"]: atom["source_class"] for atom in retained}
    by_source = Counter(atom["source_class"] for atom in retained)
    by_phase = Counter(atom["phase"] for atom in retained)
    pairs: Dict[str, dict] = {}
    pair_keys = sorted({
        (atom["id_cluster"], atom["member"]) for atom in retained
    })
    for id_cluster, member in pair_keys:
        pair_atoms = [
            atom for atom in retained
            if atom["id_cluster"] == id_cluster and atom["member"] == member
        ]
        pairs[f"{id_cluster}/{member}"] = {
            "primary": sum(
                atom["source_class"] == SOURCE_CLASS_PRIMARY
                for atom in pair_atoms),
            "support": sum(
                atom["source_class"] == SOURCE_CLASS_SUPPORT
                for atom in pair_atoms),
            "atoms": len(pair_atoms),
            "probe_clusters": sorted({atom["cluster"] for atom in pair_atoms}),
            "unique_response_identities": len({
                atom["response_identity"] for atom in pair_atoms}),
        }

    provenance_doc = {
        "schema_version": RULE_CORPUS_SCHEMA_VERSION,
        "artifact_type": RULE_CORPUS_PROVENANCE_TYPE,
        "corpus_schema_version": RULE_CORPUS_SCHEMA_VERSION,
        "source_candidates_digest": canonical_sha256({
            "method": "lineage_complete_candidate_view_v1",
            "source_corpus_digest": source["corpus_digest"],
            "candidate_ids": sorted(candidate_ids),
        }),
        "phase_aware": True,
        "phase_awareness_mode": PHASE_AWARENESS_STRICT,
        "construction": construction_block(
            (atom["packet_identity"] for atom in retained),
            source["construction"]["identification_cluster_merge"],
            ((atom["probe_family_identity"], atom["probe_family_basis"])
             for atom in retained),
        ),
        "caps": dict(source["caps"]),
        "objective_version": source["objective_version"],
        "weight_config_hash": source["weight_config_hash"],
        "background_artifact_hash": source["background_artifact_hash"],
        "counts": {
            "candidates": {
                "selected": len(candidate_ids),
                "selected_primary": sum(
                    source_class == SOURCE_CLASS_PRIMARY
                    for source_class in candidate_source.values()),
                "selected_support": sum(
                    source_class == SOURCE_CLASS_SUPPORT
                    for source_class in candidate_source.values()),
                "duplicate_identity_deduped": 0,
                "skipped_candidate_types": {},
            },
            "atoms": {
                "total": len(retained),
                "by_source": {
                    SOURCE_CLASS_PRIMARY: by_source[SOURCE_CLASS_PRIMARY],
                    SOURCE_CLASS_SUPPORT: by_source[SOURCE_CLASS_SUPPORT],
                },
                "by_phase": dict(sorted(by_phase.items())),
                "unique_response_identities": len({
                    atom["response_identity"] for atom in retained}),
            },
            "pairs": pairs,
        },
        "created_at": created_at or datetime.now(
            timezone.utc).isoformat(timespec="seconds"),
        "derived_from": {
            "method": "drop_packet_fallback_probe_families_v1",
            "source_corpus_path": os.path.abspath(corpus_path),
            "source_corpus_digest": source["corpus_digest"],
            "source_corpus_file_sha256": source["corpus_file_sha256"],
            "source_atom_count": len(atoms),
            "retained_atom_count": len(retained),
            "dropped_atom_count": len(atoms) - len(retained),
        },
    }
    corpus_info = write_rule_corpus(retained, output_path)
    finalized = finalize_corpus_provenance(provenance_doc, corpus_info)
    sidecar = write_corpus_provenance(
        finalized,
        provenance_output or default_provenance_path(output_path),
    )
    # Re-read the durable pair; this also proves lineage completeness from the
    # atom identities rather than trusting the derived manifest text.
    checked_atoms, checked_provenance = load_rule_corpus(
        output_path, sidecar,
        expected_corpus_digest=corpus_info["corpus_digest"],
        expected_phase_awareness_mode=PHASE_AWARENESS_STRICT,
    )
    if not checked_provenance["construction"][
            "probe_family_lineage_complete"]:
        raise CorpusTamperError(
            "derived construction view is unexpectedly lineage-incomplete")
    return {
        "corpus": corpus_info,
        "provenance": checked_provenance,
        "provenance_path": sidecar,
        "source_atom_count": len(atoms),
        "retained_atom_count": len(checked_atoms),
        "dropped_atom_count": len(atoms) - len(checked_atoms),
    }

def build_and_write_rule_corpus(
    records: Iterable[Mapping],
    output_path: str,
    *,
    provenance_output: Optional[str] = None,
    **build_kwargs: Any,
) -> dict:
    """Build, then atomically write the corpus **and** its provenance sidecar.

    The corpus is written first; the provenance sidecar (which binds the
    corpus file SHA256 and canonical corpus digest) is written only after the
    corpus is durable, so an interrupted run can never leave a sidecar that
    vouches for a missing or partial corpus.
    """
    build = build_rule_corpus(records, **build_kwargs)
    corpus_info = write_rule_corpus(build.atoms, output_path)
    provenance = finalize_corpus_provenance(build.provenance, corpus_info)
    sidecar = write_corpus_provenance(
        provenance, provenance_output or default_provenance_path(output_path))
    return {
        "build": build,
        "corpus": corpus_info,
        "provenance": provenance,
        "provenance_path": sidecar,
    }

# ---------------------------------------------------------------------------
# Strict loader / validator
# ---------------------------------------------------------------------------

#: JSON corpora above this size stream with ijson when available.
_IJSON_SIZE_THRESHOLD = 8 * 1024 * 1024

try:  # optional streaming dependency
    import ijson  # type: ignore
except ImportError:  # pragma: no cover - environment dependent
    ijson = None

def iter_corpus_atoms(path: str) -> Iterator[dict]:
    """Yield corpus atoms from the JSON array at ``path`` (streaming)."""
    size = os.path.getsize(path)
    if ijson is not None and size > _IJSON_SIZE_THRESHOLD:
        with open(path, "rb") as handle:
            # use_float=True keeps the streaming branch type-compatible with
            # json.load: JSON decimals become plain floats (never Decimal),
            # so canonical_json(dict(atom)) stays serializable downstream.
            for atom in ijson.items(handle, "item", use_float=True):
                yield atom
        return
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise CorpusTamperError(
            f"corpus file {path} is not a JSON array of atoms")
    for atom in data:
        yield atom

def _file_sha256(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

_REQUIRED_ATOM_KEYS = (
    "schema_version", "observation_identity", "candidate_id",
    "response_identity", "packet_identity", "probe_family_identity",
    "probe_family_basis", "parent_seed_id", "parent_packet_hash", "source_class",
    "source_candidate_type", "mutation_target", "cluster", "id_cluster",
    "member", "phase", "transport", "iteration", "qualification_status",
    "packet_hex", "response_hex", "responses",
)

_REQUIRED_PROVENANCE_KEYS = (
    "schema_version", "artifact_type", "corpus_schema_version",
    "corpus_path", "corpus_file_sha256",
    "corpus_digest", "corpus_atom_count", "source_candidates_digest",
    "phase_aware", "phase_awareness_mode", "construction", "caps",
    "objective_version", "weight_config_hash", "background_artifact_hash",
    "counts", "created_at",
)

_REQUIRED_CONSTRUCTION_KEYS = (
    "schema_version", "view", "method", "held_out_axis",
    "packet_universe_digest", "packet_universe_size",
    "probe_family_universe_digest", "probe_family_universe_size",
    "probe_family_lineage_complete",
    "identification_cluster_merge",
)

_LEGACY_MESSAGE = (
    "partitioned schema-v1 rule corpora are superseded by the unpartitioned "
    "schema version 2 construction view — do not migrate; rebuild with "
    "scripts/build_rule_training_corpus.py (schema version 2: no fit/dev/eval "
    "partition, full-corpus construction gates, held-out axis = "
    "construction-packet-disjoint validation round)")

def _validate_provenance_document(provenance: Mapping) -> None:
    if not isinstance(provenance, Mapping):
        raise CorpusTamperError(
            f"provenance must be a mapping, got {type(provenance).__name__}")
    if "partition_salts" in provenance or "partition_ratios" in provenance \
            or "split_schema_version" in provenance \
            or int(provenance.get("schema_version", 0) or 0) == 1:
        raise RuleCorpusLegacyError(_LEGACY_MESSAGE)
    missing = [
        key for key in _REQUIRED_PROVENANCE_KEYS if key not in provenance]
    if missing:
        raise CorpusTamperError(
            f"provenance missing keys: {sorted(missing)}")
    if int(provenance["schema_version"]) != RULE_CORPUS_SCHEMA_VERSION:
        raise CorpusTamperError(
            f"unsupported provenance schema_version "
            f"{provenance['schema_version']!r}")
    if provenance["artifact_type"] != RULE_CORPUS_PROVENANCE_TYPE:
        raise CorpusTamperError(
            f"unexpected provenance artifact_type "
            f"{provenance['artifact_type']!r}")
    if int(provenance["corpus_schema_version"]) != RULE_CORPUS_SCHEMA_VERSION:
        raise CorpusTamperError(
            "provenance corpus_schema_version mismatch: "
            f"{provenance['corpus_schema_version']!r}")
    if provenance["phase_awareness_mode"] not in (
            PHASE_AWARENESS_STRICT, PHASE_AWARENESS_ALLOW_LEGACY):
        raise CorpusTamperError(
            f"invalid phase_awareness_mode "
            f"{provenance['phase_awareness_mode']!r}")
    if provenance["phase_awareness_mode"] == PHASE_AWARENESS_ALLOW_LEGACY \
            and provenance["phase_aware"]:
        raise CorpusTamperError(
            "allow-legacy provenance must be marked non-phase-aware")
    if provenance["phase_awareness_mode"] == PHASE_AWARENESS_STRICT \
            and not provenance["phase_aware"]:
        raise CorpusTamperError(
            "strict phase-aware provenance must be marked phase-aware")
    construction = provenance["construction"]
    if not isinstance(construction, Mapping):
        raise CorpusTamperError(
            f"construction block must be a mapping, got {construction!r}")
    cmissing = [
        key for key in _REQUIRED_CONSTRUCTION_KEYS
        if key not in construction]
    if cmissing:
        raise CorpusTamperError(
            f"construction block missing keys: {sorted(cmissing)}")
    if int(construction["schema_version"]) != CONSTRUCTION_SCHEMA_VERSION:
        raise CorpusTamperError(
            "construction schema_version mismatch: "
            f"{construction['schema_version']!r}")
    if construction["view"] != "full_corpus" \
            or construction["method"] != CONSTRUCTION_VIEW_METHOD:
        raise CorpusTamperError(
            "construction view/method mismatch: "
            f"{construction.get('view')!r}/{construction.get('method')!r}")
    digest = construction["packet_universe_digest"]
    if not isinstance(digest, str) or len(digest) != 64 \
            or any(c not in "0123456789abcdef" for c in digest):
        raise CorpusTamperError(
            f"packet_universe_digest must be 64 lowercase hex, got {digest!r}")
    if not isinstance(construction["packet_universe_size"], int) \
            or isinstance(construction["packet_universe_size"], bool) \
            or construction["packet_universe_size"] < 0:
        raise CorpusTamperError(
            "packet_universe_size must be a non-negative int, got "
            f"{construction['packet_universe_size']!r}")
    family_digest = construction["probe_family_universe_digest"]
    if not isinstance(family_digest, str) or len(family_digest) != 64 \
            or any(c not in "0123456789abcdef" for c in family_digest):
        raise CorpusTamperError(
            "probe_family_universe_digest must be 64 lowercase hex")
    if not isinstance(construction["probe_family_universe_size"], int) \
            or isinstance(construction["probe_family_universe_size"], bool) \
            or construction["probe_family_universe_size"] < 0:
        raise CorpusTamperError(
            "probe_family_universe_size must be a non-negative int")
    if not isinstance(construction["probe_family_lineage_complete"], bool):
        raise CorpusTamperError(
            "probe_family_lineage_complete must be bool")
    merge_map = construction["identification_cluster_merge"]
    if not isinstance(merge_map, Mapping) or not all(
            isinstance(k, str) and isinstance(v, str) and v and v != k
            for k, v in merge_map.items()):
        raise CorpusTamperError(
            "identification_cluster_merge must be a str→str mapping with "
            f"non-empty renamed values, got {merge_map!r}")

def validate_rule_corpus(
    atoms: Iterable[Mapping],
    provenance: Mapping,
    *,
    expected_corpus_digest: Optional[str] = None,
    expected_objective_version: Optional[str] = None,
    expected_weight_config_hash: Optional[str] = None,
    expected_background_artifact_hash: Optional[str] = None,
    expected_source_candidates_digest: Optional[str] = None,
    expected_phase_awareness_mode: Optional[str] = None,
    expected_construction_digest: Optional[str] = None,
) -> List[dict]:
    """Strictly validate corpus atoms against their provenance document.

    Recomputed and enforced:
      - required atom keys and schema version;
      - ``candidate_id`` / ``packet_identity`` / ``response_identity`` /
        ``observation_identity`` (full identity chain from atom fields);
      - the nested response shape (one cluster group, one member entry whose
        bytes/phase match the atom);
      - ``id_cluster`` recomputed from ``cluster`` through the provenance
        merge map;
      - the construction packet universe digest over the atoms' packet
        identities (a validation round proves probe disjointness against it);
      - deterministic ordering + uniqueness by ``observation_identity``;
      - the canonical corpus digest over the atom sequence;
      - honest count accounting (``corpus_atom_count`` and
        ``counts.atoms.total``).

    Any digest mismatch fails with :class:`CorpusTamperError`; explicit
    expected identities that differ fail with
    :class:`CorpusIdentityMismatchError`.
    """
    _validate_provenance_document(provenance)

    corpus_hasher = hashlib.sha256(CORPUS_DIGEST_TAG.encode("utf-8"))
    validated: List[dict] = []
    previous: Optional[str] = None
    packet_identities: Set[str] = set()
    probe_families: Set[Tuple[str, str]] = set()
    for atom in atoms:
        if not isinstance(atom, Mapping):
            raise CorpusTamperError(
                f"corpus atoms must be dicts, got {type(atom).__name__}")
        missing = [key for key in _REQUIRED_ATOM_KEYS if key not in atom]
        if missing:
            raise CorpusTamperError(
                f"corpus atom missing keys: {sorted(missing)}")
        if int(atom["schema_version"]) != RULE_CORPUS_SCHEMA_VERSION:
            raise CorpusTamperError(
                f"unsupported corpus atom schema_version "
                f"{atom['schema_version']!r}")
        if atom.get("partition") is not None:
            raise CorpusTamperError(
                f"corpus atom {atom.get('observation_identity')!r} carries a "
                f"'partition' field; partitioned schema-v1 atoms are "
                f"superseded — rebuild the corpus")
        expected_id_cluster = identification_cluster_of(atom["cluster"])
        if expected_id_cluster != atom["id_cluster"]:
            raise CorpusTamperError(
                f"id_cluster mismatch for atom "
                f"{atom['observation_identity']!r}: recorded "
                f"{atom['id_cluster']!r}, recomputed {expected_id_cluster!r}")

        # Nested response shape.
        responses = atom["responses"]
        if (not isinstance(responses, list) or len(responses) != 1
                or not isinstance(responses[0], dict)
                or responses[0].get("service") != atom["cluster"]
                or not isinstance(responses[0].get("responses"), list)
                or len(responses[0]["responses"]) != 1):
            raise CorpusTamperError(
                f"corpus atom {atom['observation_identity']!r} must carry "
                f"exactly one nested (cluster → member) response entry")
        member_entry = responses[0]["responses"][0]
        if (not isinstance(member_entry, dict)
                or member_entry.get("service") != atom["member"]
                or member_entry.get("response_phase") != atom["phase"]):
            raise CorpusTamperError(
                f"corpus atom {atom['observation_identity']!r} nested member "
                f"entry does not match its (member, phase) metadata")
        member_hex = str(member_entry.get("response_hex", "") or "")
        if not member_hex:
            raise CorpusTamperError(
                f"corpus atom {atom['observation_identity']!r} carries an "
                f"empty nested response_hex; atoms always carry bytes")
        _parse_hex(member_hex, field="nested response_hex")
        if atom.get("response_hex") != member_hex:
            raise CorpusTamperError(
                f"corpus atom {atom['observation_identity']!r} top-level "
                f"response_hex does not match its nested entry")

        # Identity chain.
        expected_candidate_id = candidate_identity_digest({
            **atom, 'candidate_type': atom['source_candidate_type']})
        if expected_candidate_id != atom["candidate_id"]:
            raise CorpusTamperError(
                f"candidate_id mismatch for atom "
                f"{atom['observation_identity']!r}")
        if packet_identity(atom["packet_hex"]) != atom["packet_identity"]:
            raise CorpusTamperError(
                f"packet_identity mismatch for atom "
                f"{atom['observation_identity']!r}")
        expected_family, expected_basis = probe_family_identity(
            transport=atom["transport"],
            mutation_target=atom["mutation_target"],
            parent_seed_id=atom["parent_seed_id"],
            parent_packet_hash=atom["parent_packet_hash"],
            packet_hex=atom["packet_hex"],
        )
        if atom["probe_family_identity"] != expected_family \
                or atom["probe_family_basis"] != expected_basis:
            raise CorpusTamperError(
                f"probe family identity mismatch for atom "
                f"{atom['observation_identity']!r}")
        if response_identity(member_hex) != atom["response_identity"]:
            raise CorpusTamperError(
                f"response_identity mismatch for atom "
                f"{atom['observation_identity']!r} (nested response_hex does "
                f"not hash to the recorded identity)")
        expected_observation = observation_identity(
            atom["candidate_id"], atom["member"], atom["phase"], member_hex)
        if expected_observation != atom["observation_identity"]:
            raise CorpusTamperError(
                f"observation_identity mismatch for atom "
                f"{atom['observation_identity']!r}")

        # Deterministic order + uniqueness.
        if previous is not None and atom["observation_identity"] <= previous:
            raise CorpusTamperError(
                "corpus atoms are not sorted by unique observation_identity")
        previous = atom["observation_identity"]

        packet_identities.add(atom["packet_identity"])
        probe_families.add((atom["probe_family_identity"],
                            atom["probe_family_basis"]))
        _corpus_digest_update(corpus_hasher, canonical_json(dict(atom)))
        validated.append(dict(atom))

    recomputed_digest = corpus_hasher.hexdigest()
    if recomputed_digest != provenance["corpus_digest"]:
        raise CorpusTamperError(
            f"corpus digest mismatch: recorded "
            f"{provenance['corpus_digest']!r}, recomputed "
            f"{recomputed_digest!r}")
    construction = provenance["construction"]
    recomputed_universe = _construction_universe_digest(packet_identities)
    if recomputed_universe != construction["packet_universe_digest"]:
        raise CorpusTamperError(
            "construction packet universe digest mismatch: recorded "
            f"{construction['packet_universe_digest']!r}, "
            f"recomputed {recomputed_universe!r}")
    if int(construction["packet_universe_size"]) != len(packet_identities):
        raise CorpusTamperError(
            "construction packet_universe_size "
            f"{construction['packet_universe_size']!r} != "
            f"{len(packet_identities)} unique packet identities in the corpus")
    family_ids = {identity for identity, _basis in probe_families}
    recomputed_family_digest = canonical_sha256({
        "method": "probe_family_universe_v1",
        "probe_family_identities": sorted(family_ids),
    })
    if recomputed_family_digest != construction["probe_family_universe_digest"]:
        raise CorpusTamperError("construction probe-family universe digest mismatch")
    if int(construction["probe_family_universe_size"]) != len(family_ids):
        raise CorpusTamperError("construction probe-family universe size mismatch")
    lineage_complete = bool(probe_families) and all(
        basis == "lineage" for _identity, basis in probe_families)
    if construction["probe_family_lineage_complete"] != lineage_complete:
        raise CorpusTamperError("construction probe-family lineage flag mismatch")
    if expected_corpus_digest is not None \
            and expected_corpus_digest != provenance["corpus_digest"]:
        raise CorpusIdentityMismatchError(
            f"corpus_digest {provenance['corpus_digest']!r} differs from "
            f"expected {expected_corpus_digest!r}")
    if int(provenance["corpus_atom_count"]) != len(validated):
        raise CorpusTamperError(
            f"provenance corpus_atom_count "
            f"{provenance['corpus_atom_count']!r} != {len(validated)} atoms")
    counts = provenance.get("counts", {}).get("atoms", {})
    if counts and int(counts.get("total", len(validated))) != len(validated):
        raise CorpusTamperError(
            "provenance counts.atoms.total does not match the atom count")

    expected = {
        "objective_version": expected_objective_version,
        "weight_config_hash": expected_weight_config_hash,
        "background_artifact_hash": expected_background_artifact_hash,
        "source_candidates_digest": expected_source_candidates_digest,
        "phase_awareness_mode": expected_phase_awareness_mode,
    }
    for name, value in expected.items():
        if value is not None and provenance.get(name) != value:
            raise CorpusIdentityMismatchError(
                f"provenance {name}={provenance.get(name)!r} differs from "
                f"expected {value!r}")
    if expected_construction_digest is not None \
            and provenance["construction"]["packet_universe_digest"] \
            != expected_construction_digest:
        raise CorpusIdentityMismatchError(
            "provenance construction packet_universe_digest "
            f"{provenance['construction']['packet_universe_digest']!r} "
            f"differs from expected {expected_construction_digest!r}")
    return validated

def load_rule_corpus(
    corpus_path: str,
    provenance_path: Optional[str] = None,
    *,
    expected_corpus_digest: Optional[str] = None,
    expected_file_sha256: Optional[str] = None,
    expected_objective_version: Optional[str] = None,
    expected_weight_config_hash: Optional[str] = None,
    expected_background_artifact_hash: Optional[str] = None,
    expected_source_candidates_digest: Optional[str] = None,
    expected_phase_awareness_mode: Optional[str] = None,
    expected_construction_digest: Optional[str] = None,
) -> Tuple[List[dict], dict]:
    """Load + strictly validate one (corpus, provenance) file pair.

    The corpus file SHA256 is verified against the sidecar first (interrupted
    or edited corpora fail before any atom is trusted), then every atom is
    validated and every digest recomputed by
    :func:`validate_rule_corpus`.
    """
    sidecar = provenance_path or default_provenance_path(corpus_path)
    if not os.path.exists(sidecar):
        raise CorpusTamperError(
            f"provenance sidecar {sidecar} is missing; the corpus/provenance "
            f"pair is incomplete (interrupted run?)")
    with open(sidecar, "r", encoding="utf-8") as handle:
        provenance = json.load(handle)
    _validate_provenance_document(provenance)

    file_digest = _file_sha256(corpus_path)
    if file_digest != provenance["corpus_file_sha256"]:
        raise CorpusTamperError(
            f"corpus file sha256 mismatch for {corpus_path}: recorded "
            f"{provenance['corpus_file_sha256']!r}, actual {file_digest!r}")
    if expected_file_sha256 is not None \
            and expected_file_sha256 != file_digest:
        raise CorpusIdentityMismatchError(
            f"corpus file sha256 {file_digest!r} differs from expected "
            f"{expected_file_sha256!r}")

    atoms = validate_rule_corpus(
        iter_corpus_atoms(corpus_path),
        provenance,
        expected_corpus_digest=expected_corpus_digest,
        expected_objective_version=expected_objective_version,
        expected_weight_config_hash=expected_weight_config_hash,
        expected_background_artifact_hash=expected_background_artifact_hash,
        expected_source_candidates_digest=expected_source_candidates_digest,
        expected_phase_awareness_mode=expected_phase_awareness_mode,
        expected_construction_digest=expected_construction_digest,
    )
    return atoms, dict(provenance)
