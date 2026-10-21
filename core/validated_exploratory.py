"""Final, offline promotion of background-adjusted search exploratory multi-probe candidates.

Promotion is deliberately stricter than online candidate collection.  A
candidate is promoted only when its target and an extra active service are
stable over three reprobes and the extra service is correctly identified by
the rule cascade on a fresh probe-family-disjoint validation round.  The
evaluation artifact must be cryptographically bound to those observations.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from core.candidate_collector import CANDIDATE_EXPLORATORY_MULTI_PROBE
from core.candidate_stability import canonical_sha256, validate_stability_artifact
from core.distinguishability import (
    LEAKAGE_VERIFIED,
    load_distinguishability_artifact,
    manifest_core_hash,
    packet_hash_from_hex,
)
from core.rule_bundle_provenance import (
    ARTIFACT_TYPE as RULE_BUNDLE_ARTIFACT_TYPE,
    SCHEMA_VERSION as RULE_BUNDLE_SCHEMA_VERSION,
)
from core.rule_corpus import canonical_sha256 as bundle_canonical_sha256

SCHEMA_VERSION = 1
ARTIFACT_TYPE = "probeweaver_validated_exploratory"
CLAIM_SCOPE = "probe_family_held_out_rule_confirmed_network_stability"
CANDIDATE_TYPE_AFTER_PROMOTION = "validated_exploratory"
SOURCE_BINDING_MODE = "candidate_stability_reprobes"
STRICT_RULE_BUNDLE_MODE = "strict_rule_bundle"
VALIDATION_MODE = "probe_family_disjoint"

REASON_TARGET_UNSTABLE = "target_unstable"
REASON_NO_STABLE_EXTRA = "no_stable_extra_active_cluster"
REASON_PACKET_NOT_IN_INDEX = "evaluation_entry_missing"
REASON_NO_CONFIRMED_EXTRA = "no_stable_extra_rule_confirmed_on_eval"
REASON_EXTRAS_ONLY_OBSERVED_OR_BANNER = (
    "stable_extra_clusters_only_observed_or_banner_identifiable")

class ValidatedExploratoryError(ValueError):
    pass

class SourceBindingError(ValidatedExploratoryError):
    pass

class RuleBundleBindingError(ValidatedExploratoryError):
    pass

class ArtifactTamperError(ValidatedExploratoryError):
    pass

class ArtifactIdentityMismatchError(ValidatedExploratoryError):
    pass

def _require(condition: bool, message: str, error=ValidatedExploratoryError):
    if not condition:
        raise error(message)

def _bundle_core(bundle: Mapping) -> dict:
    return {key: value for key, value in bundle.items()
            if key not in ("artifact_hash", "created_at")}

def validate_rule_bundle_manifest(bundle: Mapping) -> dict:
    """Validate the bundle document itself (not its bound files)."""
    _require(isinstance(bundle, Mapping), "rule bundle must be an object",
             RuleBundleBindingError)
    _require(bundle.get("schema_version") == RULE_BUNDLE_SCHEMA_VERSION,
             "rule bundle schema_version mismatch", RuleBundleBindingError)
    _require(bundle.get("artifact_type") == RULE_BUNDLE_ARTIFACT_TYPE,
             "rule bundle artifact_type mismatch", RuleBundleBindingError)
    for key in ("corpus", "rules", "runtime", "training_contract",
                "artifact_hash", "created_at"):
        _require(key in bundle, f"rule bundle missing {key!r}",
                 RuleBundleBindingError)
    expected = bundle_canonical_sha256(_bundle_core(bundle))
    _require(bundle.get("artifact_hash") == expected,
             "rule bundle artifact_hash mismatch", RuleBundleBindingError)
    for section, key in (("rules", "digest"), ("runtime", "digest"),
                         ("corpus", "corpus_digest")):
        _require(bool((bundle.get(section) or {}).get(key)),
                 f"rule bundle {section}.{key} missing",
                 RuleBundleBindingError)
    return dict(bundle)

def load_rule_bundle_manifest(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return validate_rule_bundle_manifest(json.load(handle))

def _source_binding(manifest: Mapping) -> dict:
    provenance = manifest.get("provenance")
    _require(isinstance(provenance, Mapping),
             "evaluation manifest lacks provenance", SourceBindingError)
    binding = provenance.get("source_binding")
    _require(isinstance(binding, Mapping) and binding,
             "evaluation provenance lacks stability source_binding",
             SourceBindingError)
    return dict(binding)

def validate_evaluation_manifest(
    manifest: Mapping, *, stability: Mapping, rule_bundle: Mapping,
) -> dict:
    """Cross-bind strict evaluation, stability facts, and rule bundle."""
    _require(isinstance(manifest, Mapping), "evaluation manifest must be object",
             RuleBundleBindingError)
    _require(manifest.get("manifest_core_hash") == manifest_core_hash(dict(manifest)),
             "evaluation manifest_core_hash mismatch", RuleBundleBindingError)
    _require(manifest.get("leakage_status") == LEAKAGE_VERIFIED,
             "evaluation leakage_status must be verified", RuleBundleBindingError)
    _require(manifest.get("strict_rule_bundle") is True,
             "evaluation is not strict_rule_bundle", RuleBundleBindingError)
    split = manifest.get("split") or {}
    _require(split.get("mode") == STRICT_RULE_BUNDLE_MODE,
             "evaluation is not strict full-source mode", RuleBundleBindingError)
    validation = split.get("validation") or {}
    _require(validation.get("status") == "verified"
             and validation.get("mode") == VALIDATION_MODE,
             "evaluation lacks verified probe-family validation",
             RuleBundleBindingError)
    provenance = manifest.get("provenance") or {}
    _require(provenance.get("mode") == STRICT_RULE_BUNDLE_MODE,
             "evaluation provenance is not strict_rule_bundle",
             RuleBundleBindingError)
    _require(provenance.get("artifact_hash") == rule_bundle.get("artifact_hash"),
             "evaluation and rule bundle artifact hashes differ",
             RuleBundleBindingError)
    validation_provenance = provenance.get("validation_round") or {}
    _require(validation_provenance.get("artifact_hash") ==
             validation.get("artifact_hash"),
             "evaluation validation artifact binding mismatch",
             RuleBundleBindingError)
    _require(validation_provenance.get("validation_mode") == VALIDATION_MODE,
             "evaluation validation mode mismatch", RuleBundleBindingError)
    _require((validation_provenance.get("disjointness") or {}).get(
        "packet_overlap_count") == 0,
        "evaluation validation packets overlap construction",
        RuleBundleBindingError)
    _require((validation_provenance.get("disjointness") or {}).get(
        "probe_family_overlap_count") == 0,
        "evaluation validation families overlap construction",
        RuleBundleBindingError)

    corpus = rule_bundle.get("corpus") or {}
    checks = (
        (manifest.get("rules", {}).get("digest"),
         rule_bundle.get("rules", {}).get("digest"), "rules.digest"),
        (provenance.get("rules_digest"),
         rule_bundle.get("rules", {}).get("digest"), "provenance rules"),
        (manifest.get("engine", {}).get("runtime_registry_digest"),
         rule_bundle.get("runtime", {}).get("digest"), "runtime digest"),
        (provenance.get("runtime_registry_digest"),
         rule_bundle.get("runtime", {}).get("digest"), "provenance runtime"),
        (provenance.get("corpus", {}).get("digest"),
         corpus.get("corpus_digest"), "corpus digest"),
        (provenance.get("corpus", {}).get("file_sha256"),
         corpus.get("corpus_file_sha256"), "corpus file hash"),
        (provenance.get("corpus", {}).get("source_candidates_digest"),
         corpus.get("source_candidates_digest"), "corpus source digest"),
        (split.get("construction"), corpus.get("construction"),
         "construction identity"),
        (manifest.get("objective_version"), stability.get("objective_version"),
         "objective_version"),
        (corpus.get("objective_version"), stability.get("objective_version"),
         "bundle objective_version"),
        (corpus.get("weight_config_hash"), stability.get("weight_config_hash"),
         "weight_config_hash"),
        (corpus.get("background_artifact_hash"),
         stability.get("background_artifact_hash"), "background_artifact_hash"),
    )
    for actual, expected, label in checks:
        _require(actual == expected, f"{label} mismatch: {actual!r} != {expected!r}",
                 RuleBundleBindingError)

    binding = _source_binding(manifest)
    binding_checks = (
        (binding.get("mode"), SOURCE_BINDING_MODE, "mode"),
        (binding.get("stability_artifact_hash"), stability.get("artifact_hash"),
         "stability_artifact_hash"),
        (binding.get("stability_source_candidates_digest"),
         stability.get("source_candidates_digest"),
         "stability_source_candidates_digest"),
        (binding.get("response_phase_schema_version"),
         stability.get("response_phase_schema_version"),
         "response_phase_schema_version"),
    )
    for actual, expected, label in binding_checks:
        _require(actual == expected, f"source_binding.{label} mismatch",
                 SourceBindingError)
    challenge = validation_provenance.get("challenge") or {}
    _require(challenge.get("stability_artifact_hash") ==
             stability.get("artifact_hash"),
             "validation challenge stability artifact mismatch",
             SourceBindingError)
    _require(challenge.get("source_candidates_digest") ==
             stability.get("source_candidates_digest"),
             "validation challenge source digest mismatch",
             SourceBindingError)
    transport = str(binding.get("transport") or "")
    _require(transport in ("tcp", "udp"),
             "source_binding.transport must be tcp or udp", SourceBindingError)
    available = {str((item.get("identity") or {}).get("transport") or "")
                 for item in stability.get("candidate_results", [])}
    _require(transport in available,
             "source_binding transport absent from stability candidates",
             SourceBindingError)
    return dict(manifest)

def _identity_key(identity: Mapping) -> Tuple[str, str, str, str]:
    return (str(identity.get("transport") or ""),
            str(identity.get("mutation_target") or ""),
            str(identity.get("candidate_type") or ""),
            str(identity.get("packet_hex") or "").strip().lower())

def evaluate_promotion(stability: Mapping, index, *, transport: str):
    results: List[dict] = []
    reasons_count: Dict[str, int] = {}
    skipped_types: Dict[str, int] = {}
    skipped_transports: Dict[str, int] = {}
    for source in stability.get("candidate_results", []):
        identity = source.get("identity") or {}
        source_transport = str(identity.get("transport") or "")
        if source_transport != transport:
            skipped_transports[source_transport] = (
                skipped_transports.get(source_transport, 0) + 1)
            continue
        candidate_type = str(identity.get("candidate_type") or "")
        if candidate_type != CANDIDATE_EXPLORATORY_MULTI_PROBE:
            skipped_types[candidate_type] = skipped_types.get(candidate_type, 0) + 1
            continue

        packet_hex = str(identity.get("packet_hex") or "").strip().lower()
        packet_hash = packet_hash_from_hex(packet_hex)
        stable_extras = sorted(set(
            source.get("stable_extra_active_clusters") or []))
        reasons: List[str] = []
        if not source.get("target_stable"):
            reasons.append(REASON_TARGET_UNSTABLE)
        if not stable_extras:
            reasons.append(REASON_NO_STABLE_EXTRA)

        active_pairs: List[List[str]] = []
        active_clusters: List[str] = []
        confirmed: List[str] = []
        if not index.entry_loaded(packet_hash):
            reasons.append(REASON_PACKET_NOT_IN_INDEX)
        else:
            active_pairs = [list(pair) for pair in sorted(
                index.active_identifiable_pairs(packet_hash))]
            active_clusters = sorted({pair[0] for pair in active_pairs})
            confirmed = sorted(set(stable_extras) & set(active_clusters))
            if stable_extras and not confirmed:
                reasons.append(REASON_NO_CONFIRMED_EXTRA)
                observed = {cluster for cluster, _member in
                            index.observed_identifiable_pairs(packet_hash)}
                if set(stable_extras) & observed:
                    reasons.append(REASON_EXTRAS_ONLY_OBSERVED_OR_BANNER)

        validated = not reasons
        if not validated:
            for reason in reasons:
                reasons_count[reason] = reasons_count.get(reason, 0) + 1
        results.append({
            "candidate_id": source.get("candidate_id", ""),
            "identity": dict(identity),
            "packet_hash": packet_hash,
            "active_identifiable_pairs": active_pairs,
            "active_identifiable_clusters": active_clusters,
            "stable_extra_active_clusters": stable_extras,
            "confirmed_stable_extra_clusters": confirmed,
            "target_stable": bool(source.get("target_stable")),
            "promotion_status": (
                CANDIDATE_TYPE_AFTER_PROMOTION if validated else "rejected"),
            "candidate_type_after_promotion": (
                CANDIDATE_TYPE_AFTER_PROMOTION if validated
                else CANDIDATE_EXPLORATORY_MULTI_PROBE),
            "validated_exploratory": validated,
            "reasons": reasons,
        })
    results.sort(key=lambda item: _identity_key(item["identity"]))
    summary = {
        "n_exploratory": len(results),
        "n_validated": sum(1 for item in results
                           if item["validated_exploratory"]),
        "n_rejected": sum(1 for item in results
                          if not item["validated_exploratory"]),
        "n_skipped": sum(skipped_types.values()) + sum(skipped_transports.values()),
        "failure_reason_counts": dict(sorted(reasons_count.items())),
        "skipped_candidate_types": dict(sorted(skipped_types.items())),
        "skipped_candidate_transports": dict(sorted(skipped_transports.items())),
    }
    return results, summary

def build_validated_exploratory_artifact(
    stability: Mapping,
    manifest: Mapping,
    rule_bundle: Mapping,
    index,
    *,
    created_at: Optional[str] = None,
) -> dict:
    stability = validate_stability_artifact(stability)
    rule_bundle = validate_rule_bundle_manifest(rule_bundle)
    manifest = validate_evaluation_manifest(
        manifest, stability=stability, rule_bundle=rule_bundle)
    binding = _source_binding(manifest)
    results, summary = evaluate_promotion(
        stability, index, transport=binding["transport"])
    _require(results, "no exploratory candidates for bound transport")
    artifact: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "claim_scope": CLAIM_SCOPE,
        "stability_artifact_hash": stability["artifact_hash"],
        "distinguishability_manifest_core_hash": manifest["manifest_core_hash"],
        "rule_bundle_artifact_hash": rule_bundle["artifact_hash"],
        "objective_version": stability.get("objective_version", ""),
        "background_artifact_hash": stability.get(
            "background_artifact_hash", ""),
        "weight_config_hash": stability.get("weight_config_hash", ""),
        "service_topology_hash": stability.get("service_topology_hash", ""),
        "response_phase_schema_version": stability.get(
            "response_phase_schema_version"),
        "source_binding": binding,
        "candidate_results": results,
        "summary": summary,
    }
    artifact["artifact_hash"] = canonical_sha256(artifact)
    artifact["created_at"] = created_at or datetime.now(
        timezone.utc).isoformat(timespec="seconds")
    return artifact

_RESULT_KEYS = (
    "candidate_id", "identity", "packet_hash", "active_identifiable_pairs",
    "active_identifiable_clusters", "stable_extra_active_clusters",
    "confirmed_stable_extra_clusters", "target_stable", "promotion_status",
    "candidate_type_after_promotion", "validated_exploratory", "reasons",
)

def validate_validated_exploratory_artifact(
    artifact: Mapping,
    *,
    expected_stability_artifact_hash: Optional[str] = None,
    expected_distinguishability_manifest_core_hash: Optional[str] = None,
    expected_rule_bundle_artifact_hash: Optional[str] = None,
    expected_objective_version: Optional[str] = None,
    expected_background_artifact_hash: Optional[str] = None,
    expected_weight_config_hash: Optional[str] = None,
    expected_service_topology_hash: Optional[str] = None,
    expected_response_phase_schema_version: Optional[int] = None,
) -> dict:
    _require(isinstance(artifact, Mapping), "promotion artifact must be object",
             ArtifactTamperError)
    _require(artifact.get("schema_version") == SCHEMA_VERSION,
             "promotion schema_version mismatch", ArtifactTamperError)
    _require(artifact.get("artifact_type") == ARTIFACT_TYPE,
             "promotion artifact_type mismatch", ArtifactTamperError)
    _require(artifact.get("claim_scope") == CLAIM_SCOPE,
             "promotion claim_scope mismatch", ArtifactTamperError)
    _require(artifact.get("artifact_hash") == canonical_sha256(artifact),
             "artifact_hash mismatch", ArtifactTamperError)
    results = artifact.get("candidate_results")
    _require(isinstance(results, list) and results,
             "candidate_results must be non-empty", ArtifactTamperError)

    previous = None
    seen = set()
    failure_counts: Dict[str, int] = {}
    n_validated = 0
    for result in results:
        _require(isinstance(result, Mapping), "candidate result must be object",
                 ArtifactTamperError)
        for key in _RESULT_KEYS:
            _require(key in result, f"candidate result missing {key}",
                     ArtifactTamperError)
        identity = result["identity"]
        identity_key = _identity_key(identity)
        _require(identity_key[2] == CANDIDATE_EXPLORATORY_MULTI_PROBE,
                 "promotion results may contain exploratory candidates only",
                 ArtifactTamperError)
        _require(result["candidate_id"] == canonical_sha256(list(identity_key)),
                 "candidate_id does not match identity", ArtifactTamperError)
        _require(result["candidate_id"] not in seen,
                 "duplicate candidate_id", ArtifactTamperError)
        seen.add(result["candidate_id"])
        _require(previous is None or previous <= identity_key,
                 "candidate_results are not sorted", ArtifactTamperError)
        previous = identity_key
        _require(result["packet_hash"] == packet_hash_from_hex(identity_key[3]),
                 "packet_hash does not match packet_hex", ArtifactTamperError)
        active_pairs = [list(pair) for pair in sorted(
            tuple(pair) for pair in result["active_identifiable_pairs"])]
        _require(result["active_identifiable_pairs"] == active_pairs,
                 "active_identifiable_pairs not canonical", ArtifactTamperError)
        active_clusters = sorted({pair[0] for pair in active_pairs})
        _require(result["active_identifiable_clusters"] == active_clusters,
                 "active clusters do not match active pairs", ArtifactTamperError)
        stable_extras = sorted(set(result["stable_extra_active_clusters"]))
        _require(result["stable_extra_active_clusters"] == stable_extras,
                 "stable extras not canonical", ArtifactTamperError)
        confirmed = sorted(set(stable_extras) & set(active_clusters))
        _require(result["confirmed_stable_extra_clusters"] == confirmed,
                 "confirmed intersection mismatch", ArtifactTamperError)
        validated = bool(result["target_stable"] and stable_extras and confirmed)
        _require(bool(result["validated_exploratory"]) == validated,
                 "validated flag inconsistent with facts", ArtifactTamperError)
        if validated:
            n_validated += 1
            _require(not result["reasons"],
                     "validated candidate has rejection reasons",
                     ArtifactTamperError)
            _require(result["promotion_status"] == CANDIDATE_TYPE_AFTER_PROMOTION,
                     "validated promotion_status mismatch", ArtifactTamperError)
            _require(result["candidate_type_after_promotion"] ==
                     CANDIDATE_TYPE_AFTER_PROMOTION,
                     "validated candidate type mismatch", ArtifactTamperError)
        else:
            _require(bool(result["reasons"]),
                     "rejected candidate lacks reasons", ArtifactTamperError)
            _require(result["promotion_status"] == "rejected",
                     "rejected promotion_status mismatch", ArtifactTamperError)
            _require(result["candidate_type_after_promotion"] ==
                     CANDIDATE_EXPLORATORY_MULTI_PROBE,
                     "rejected candidate type not preserved", ArtifactTamperError)
            for reason in result["reasons"]:
                failure_counts[reason] = failure_counts.get(reason, 0) + 1

    summary = artifact.get("summary")
    _require(isinstance(summary, Mapping), "summary must be object",
             ArtifactTamperError)
    skipped_types = summary.get("skipped_candidate_types")
    skipped_transports = summary.get("skipped_candidate_transports")
    for value, label in ((skipped_types, "types"),
                         (skipped_transports, "transports")):
        _require(isinstance(value, Mapping) and all(
            isinstance(key, str) and isinstance(count, int) and count >= 0
            for key, count in value.items()), f"invalid skipped {label}",
            ArtifactTamperError)
    expected_summary = {
        "n_exploratory": len(results),
        "n_validated": n_validated,
        "n_rejected": len(results) - n_validated,
        "n_skipped": sum(skipped_types.values()) +
                     sum(skipped_transports.values()),
        "failure_reason_counts": dict(sorted(failure_counts.items())),
        "skipped_candidate_types": dict(sorted(skipped_types.items())),
        "skipped_candidate_transports": dict(sorted(skipped_transports.items())),
    }
    _require(dict(summary) == expected_summary, "summary mismatch",
             ArtifactTamperError)

    expected = {
        "stability_artifact_hash": expected_stability_artifact_hash,
        "distinguishability_manifest_core_hash":
            expected_distinguishability_manifest_core_hash,
        "rule_bundle_artifact_hash": expected_rule_bundle_artifact_hash,
        "objective_version": expected_objective_version,
        "background_artifact_hash": expected_background_artifact_hash,
        "weight_config_hash": expected_weight_config_hash,
        "service_topology_hash": expected_service_topology_hash,
        "response_phase_schema_version": expected_response_phase_schema_version,
    }
    for field, value in expected.items():
        if value is not None and artifact.get(field) != value:
            raise ArtifactIdentityMismatchError(
                f"{field} mismatch: {artifact.get(field)!r} != {value!r}")
    return dict(artifact)

def load_validated_exploratory_artifact(path: str, **expected) -> dict:
    with open(path, encoding="utf-8") as handle:
        return validate_validated_exploratory_artifact(
            json.load(handle), **expected)

def write_validated_exploratory_artifact(
        artifact: Mapping, path: str) -> str:
    validate_validated_exploratory_artifact(artifact)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(artifact, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return str(target)

def load_promotion_inputs(stability_path: str, evaluation_path: str,
                          bundle_path: str):
    from core.candidate_stability import load_stability_artifact

    stability = load_stability_artifact(stability_path)
    bundle = load_rule_bundle_manifest(bundle_path)
    index = load_distinguishability_artifact(
        evaluation_path,
        strict=True,
        expected_objective_version=stability.get("objective_version") or None,
        expected_rule_digest=bundle["rules"]["digest"],
        require_leakage_verified=True,
        expected_runtime_digest=bundle["runtime"]["digest"],
    )
    _require(index is not None, "strict evaluation artifact unavailable")
    validate_evaluation_manifest(
        index.manifest, stability=stability, rule_bundle=bundle)
    return stability, index, bundle
