"""Tamper-evident binding for a fresh probe-family rule validation round.

Rule construction deliberately consumes every selected response identity.
Consequently, construction metrics are in-sample.  A rule may claim formal
held-out identification only when its evaluation responses come from a
stability/reprobe artifact whose packets *and parent probe families* are
disjoint from the construction corpus.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from core.candidate_stability import validate_stability_artifact
from core.rule_bundle_provenance import (
    ARTIFACT_TYPE as RULE_BUNDLE_ARTIFACT_TYPE,
    SCHEMA_VERSION as RULE_BUNDLE_SCHEMA_VERSION,
)
from core.rule_corpus import (
    canonical_sha256,
    packet_identity,
    probe_family_identity,
)

SCHEMA_VERSION = 1
ARTIFACT_TYPE = "probeweaver_probe_family_validation_round"
VALIDATION_MODE = "probe_family_disjoint"
HELD_OUT_AXIS = "fresh_probe_family_disjoint_round"

class RuleValidationError(ValueError):
    pass

class RuleValidationTamperError(RuleValidationError):
    pass

class RuleValidationIdentityMismatch(RuleValidationError):
    pass

def _require(condition: bool, message: str,
             error=RuleValidationError) -> None:
    if not condition:
        raise error(message)

def _artifact_core(artifact: Mapping) -> dict:
    return {key: value for key, value in artifact.items()
            if key not in ("artifact_hash", "created_at")}

def _universe_digest(method: str, identities: Sequence[str]) -> str:
    return canonical_sha256({
        "method": method,
        "identities": sorted(set(identities)),
    })

def _validate_bundle_document(bundle: Mapping) -> None:
    _require(bundle.get("schema_version") == RULE_BUNDLE_SCHEMA_VERSION,
             "rule bundle schema mismatch")
    _require(bundle.get("artifact_type") == RULE_BUNDLE_ARTIFACT_TYPE,
             "rule bundle artifact type mismatch")
    _require(bundle.get("artifact_hash") == canonical_sha256(
        _artifact_core(bundle)), "rule bundle artifact hash mismatch")

def _construction_sets(atoms: Sequence[Mapping]) -> tuple[set[str], set[str], bool]:
    packets = {str(atom.get("packet_identity") or "") for atom in atoms}
    families = {str(atom.get("probe_family_identity") or "") for atom in atoms}
    complete = bool(atoms) and all(
        atom.get("probe_family_basis") == "lineage" for atom in atoms)
    _require("" not in packets and "" not in families,
             "construction corpus lacks packet/probe-family identities")
    return packets, families, complete

def _challenge_sets(stability: Mapping, transport: str) -> tuple[set[str], set[str], bool, int]:
    packets: set[str] = set()
    families: set[str] = set()
    complete = True
    count = 0
    for result in stability.get("candidate_results", []):
        identity = result.get("identity") or {}
        if str(identity.get("transport") or "") != transport:
            continue
        source = result.get("source") or {}
        packet_hex = str(identity.get("packet_hex") or "")
        family, basis = probe_family_identity(
            transport=transport,
            mutation_target=str(identity.get("mutation_target") or ""),
            parent_seed_id=str(source.get("parent_seed_id") or ""),
            parent_packet_hash=str(source.get("parent_packet_hash") or ""),
            packet_hex=packet_hex,
        )
        packets.add(packet_identity(packet_hex))
        families.add(family)
        complete = complete and basis == "lineage"
        count += 1
    _require(count > 0, f"validation source has no {transport} candidates")
    return packets, families, complete, count

def build_rule_validation_round(
    *,
    rule_bundle: Mapping,
    corpus_atoms: Sequence[Mapping],
    corpus_provenance: Mapping,
    stability_artifact: Mapping,
    transport: str,
    created_at: Optional[str] = None,
) -> dict:
    """Build a validation binding; fail if either disjointness proof is absent."""
    _validate_bundle_document(rule_bundle)
    stability = validate_stability_artifact(stability_artifact)
    transport = str(transport or "").lower()
    _require(transport in ("tcp", "udp"), "transport must be tcp or udp")

    construction_packets, construction_families, construction_complete = (
        _construction_sets(corpus_atoms))
    challenge_packets, challenge_families, challenge_complete, challenge_count = (
        _challenge_sets(stability, transport))
    construction = corpus_provenance.get("construction") or {}
    _require(construction.get("packet_universe_digest") ==
             rule_bundle.get("corpus", {}).get("construction", {}).get(
                 "packet_universe_digest"),
             "corpus and rule bundle construction identities differ")
    _require(construction_complete,
             "construction corpus has packet-fallback families; rebuild from "
             "candidate records carrying parent_seed_id/parent_packet_hash")
    _require(challenge_complete,
             "validation source has packet-fallback families; fresh challenge "
             "records must carry parent_seed_id/parent_packet_hash")

    packet_overlap = sorted(construction_packets & challenge_packets)
    family_overlap = sorted(construction_families & challenge_families)
    _require(not packet_overlap,
             f"validation packets overlap construction ({len(packet_overlap)})")
    _require(not family_overlap,
             f"validation probe families overlap construction ({len(family_overlap)})")

    artifact: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "validation_mode": VALIDATION_MODE,
        "held_out_axis": HELD_OUT_AXIS,
        "transport": transport,
        "rule_bundle_artifact_hash": rule_bundle["artifact_hash"],
        "rules_digest": rule_bundle["rules"]["digest"],
        "runtime_registry_digest": rule_bundle["runtime"]["digest"],
        "corpus_digest": rule_bundle["corpus"]["corpus_digest"],
        "construction": {
            "packet_universe_digest": construction["packet_universe_digest"],
            "packet_universe_size": len(construction_packets),
            "probe_family_universe_digest": construction[
                "probe_family_universe_digest"],
            "probe_family_universe_size": len(construction_families),
            "lineage_complete": construction_complete,
        },
        "challenge": {
            "stability_artifact_hash": stability["artifact_hash"],
            "source_candidates_digest": stability[
                "source_candidates_digest"],
            "candidate_count": challenge_count,
            "packet_universe_digest": _universe_digest(
                "challenge_packet_universe_v1", list(challenge_packets)),
            "packet_universe_size": len(challenge_packets),
            "probe_family_universe_digest": _universe_digest(
                "challenge_probe_family_universe_v1",
                list(challenge_families)),
            "probe_family_universe_size": len(challenge_families),
            "lineage_complete": challenge_complete,
        },
        "disjointness": {
            "packet_overlap_count": 0,
            "probe_family_overlap_count": 0,
        },
    }
    artifact["artifact_hash"] = canonical_sha256(_artifact_core(artifact))
    artifact["created_at"] = created_at or datetime.now(
        timezone.utc).isoformat(timespec="seconds")
    return artifact

def validate_rule_validation_round(
    artifact: Mapping,
    *,
    rule_bundle: Mapping,
    corpus_atoms: Sequence[Mapping],
    corpus_provenance: Mapping,
    stability_artifact: Mapping,
    transport: str,
) -> dict:
    _require(isinstance(artifact, Mapping), "validation artifact must be object",
             RuleValidationTamperError)
    _require(artifact.get("schema_version") == SCHEMA_VERSION,
             "validation schema mismatch", RuleValidationTamperError)
    _require(artifact.get("artifact_type") == ARTIFACT_TYPE,
             "validation artifact type mismatch", RuleValidationTamperError)
    _require(artifact.get("validation_mode") == VALIDATION_MODE,
             "validation mode mismatch", RuleValidationTamperError)
    _require(artifact.get("artifact_hash") == canonical_sha256(
        _artifact_core(artifact)), "validation artifact hash mismatch",
        RuleValidationTamperError)
    current = build_rule_validation_round(
        rule_bundle=rule_bundle,
        corpus_atoms=corpus_atoms,
        corpus_provenance=corpus_provenance,
        stability_artifact=stability_artifact,
        transport=transport,
        created_at=str(artifact.get("created_at") or ""),
    )
    _require(_artifact_core(current) == _artifact_core(artifact),
             "validation artifact no longer matches bound inputs",
             RuleValidationIdentityMismatch)
    return dict(artifact)

def write_rule_validation_round(artifact: Mapping, path: str) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    try:
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(artifact, handle, indent=2, ensure_ascii=False)
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

def load_rule_validation_round(path: str, **inputs: Any) -> dict:
    with open(path, encoding="utf-8") as handle:
        artifact = json.load(handle)
    return validate_rule_validation_round(artifact, **inputs)
