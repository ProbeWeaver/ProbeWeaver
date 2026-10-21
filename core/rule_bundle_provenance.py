"""Strict provenance for a frozen background-adjusted search identification rule bundle.

The manifest binds four independently mutable inputs: the phase-aware rule
corpus, the Agent states that consumed its fit/dev partitions, the final JSON
rule files, and the compiled Go cascade/runtime registry.  It deliberately
does not use the legacy size+mtime source identity.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from core.distinguishability import rules_digest, runtime_registry_digest
from core.rule_corpus import (
    PHASE_AWARENESS_STRICT,
    canonical_sha256,
    load_rule_corpus,
)

SCHEMA_VERSION = 2
ARTIFACT_TYPE = "probeweaver_rule_bundle_provenance"

class RuleBundleProvenanceError(ValueError):
    """Base error for a malformed or inconsistent rule bundle."""

class RuleBundleTamperError(RuleBundleProvenanceError):
    """A stored artifact or one of its bound files changed."""

class RuleBundleIdentityMismatch(RuleBundleProvenanceError):
    """A valid bundle differs from an explicitly expected identity."""

def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _load_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuleBundleProvenanceError(
            f"cannot load JSON file {path}: {exc}") from exc

def _load_rules(path: Optional[str], label: str) -> tuple[list, Optional[dict]]:
    if not path:
        return [], None
    absolute = os.path.abspath(path)
    rules = _load_json(absolute)
    if not isinstance(rules, list):
        raise RuleBundleProvenanceError(
            f"{label} rule file must contain a JSON array: {absolute}")
    if any(not isinstance(rule, dict) for rule in rules):
        raise RuleBundleProvenanceError(
            f"{label} rule file contains a non-object rule: {absolute}")
    return rules, {
        "path": absolute,
        "file_sha256": _file_sha256(absolute),
        "count": len(rules),
    }

_CORPUS_IDENTITY_FIELDS = (
    "corpus_digest",
    "corpus_file_sha256",
    "source_candidates_digest",
    "corpus_schema_version",
    "phase_awareness_mode",
    "objective_version",
    "weight_config_hash",
    "background_artifact_hash",
    "construction",
)

def _corpus_identity(provenance: Mapping) -> dict:
    return {field: provenance[field] for field in _CORPUS_IDENTITY_FIELDS}

def _state_mode(path: str, identity: Mapping) -> str:
    explicit = str(identity.get("mode", "") or "")
    if explicit in ("cluster", "member"):
        return explicit
    return "member" if "__" in Path(path).stem else "cluster"

def _state_records(paths: Sequence[str], corpus_identity: Mapping) -> list[dict]:
    if not paths:
        raise RuleBundleProvenanceError(
            "at least one explicit Agent state file is required")
    absolute_paths = [os.path.abspath(path) for path in paths]
    if len(set(absolute_paths)) != len(absolute_paths):
        raise RuleBundleProvenanceError("duplicate Agent state path")

    records: list[dict] = []
    identities_by_mode: dict[str, dict] = {}
    for path in sorted(absolute_paths):
        state = _load_json(path)
        if not isinstance(state, dict):
            raise RuleBundleProvenanceError(
                f"Agent state must be a JSON object: {path}")
        if state.get("attempted") is not True:
            raise RuleBundleProvenanceError(
                f"Agent state is not finalized (attempted=true required): {path}")
        identity = state.get("agent_input_identity")
        if not isinstance(identity, dict):
            raise RuleBundleProvenanceError(
                f"Agent state lacks agent_input_identity: {path}")
        for field, expected in corpus_identity.items():
            if identity.get(field) != expected:
                raise RuleBundleIdentityMismatch(
                    f"Agent state {path} has {field}={identity.get(field)!r}, "
                    f"expected {expected!r} from the strict corpus")
        if identity.get("phase_awareness_mode") != PHASE_AWARENESS_STRICT:
            raise RuleBundleIdentityMismatch(
                f"Agent state {path} is not strict phase-aware")
        if not identity.get("sampling_config_hash"):
            raise RuleBundleProvenanceError(
                f"Agent state {path} lacks sampling_config_hash")
        mode = _state_mode(path, identity)
        previous = identities_by_mode.setdefault(mode, dict(identity))
        if previous != identity:
            raise RuleBundleIdentityMismatch(
                f"mixed Agent input identities within {mode!r} mode")
        records.append({
            "path": path,
            "state_name": Path(path).stem,
            "mode": mode,
            "file_sha256": _file_sha256(path),
            "agent_input_identity": dict(identity),
        })
    return records

def _artifact_core(manifest: Mapping) -> dict:
    return {
        key: manifest[key]
        for key in manifest
        if key not in ("artifact_hash", "created_at")
    }

def build_rule_bundle_provenance(
    *,
    cluster_rules_path: Optional[str],
    member_rules_path: Optional[str],
    corpus_path: str,
    corpus_provenance_path: Optional[str],
    agent_state_paths: Sequence[str],
    zgrab_dir: str,
    created_at: Optional[str] = None,
) -> dict:
    """Build a deterministic, tamper-evident rule-bundle manifest."""
    cluster_rules, cluster_file = _load_rules(
        cluster_rules_path, "cluster")
    member_rules, member_file = _load_rules(member_rules_path, "member")
    if cluster_file is None and member_file is None:
        raise RuleBundleProvenanceError(
            "at least one of cluster_rules_path/member_rules_path is required")

    _atoms, corpus_provenance = load_rule_corpus(
        corpus_path,
        corpus_provenance_path,
        expected_phase_awareness_mode=PHASE_AWARENESS_STRICT,
    )
    corpus_identity = _corpus_identity(corpus_provenance)
    states = _state_records(agent_state_paths, corpus_identity)
    try:
        runtime_digest, runtime_files = runtime_registry_digest(zgrab_dir)
    except (OSError, ValueError) as exc:
        raise RuleBundleProvenanceError(
            f"cannot bind Go runtime registry: {exc}") from exc

    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "corpus": {
            "path": os.path.abspath(corpus_path),
            "provenance_path": os.path.abspath(
                corpus_provenance_path or f"{corpus_path}.provenance.json"),
            **corpus_identity,
        },
        "rules": {
            "digest": rules_digest(cluster_rules, member_rules),
            "cluster": cluster_file,
            "member": member_file,
        },
        "runtime": {
            "zgrab_dir": os.path.abspath(zgrab_dir),
            "digest": runtime_digest,
            "files": runtime_files,
        },
        "agent_states": states,
        "training_contract": {
            "construction_view": "all_selected_response_identities",
            "construction_metrics": "in_sample",
            "held_out_axis": "fresh_probe_family_disjoint_round",
            "fresh_validation_status": "not_bound_by_rule_bundle",
            "response_identity_is_global": True,
            "phase_metadata_runtime_condition": False,
        },
    }
    manifest["artifact_hash"] = canonical_sha256(_artifact_core(manifest))
    manifest["created_at"] = created_at or datetime.now(
        timezone.utc).isoformat(timespec="seconds")
    return manifest

_REQUIRED_KEYS = (
    "schema_version", "artifact_type", "corpus", "rules", "runtime",
    "agent_states", "training_contract", "artifact_hash", "created_at",
)

def validate_rule_bundle_provenance(
    manifest: Mapping,
    *,
    cluster_rules_path: Optional[str],
    member_rules_path: Optional[str],
    corpus_path: str,
    corpus_provenance_path: Optional[str],
    agent_state_paths: Sequence[str],
    zgrab_dir: str,
    expected_manifest_hash: Optional[str] = None,
    expected_corpus_digest: Optional[str] = None,
    expected_runtime_digest: Optional[str] = None,
    expected_rules_digest: Optional[str] = None,
) -> dict:
    """Recompute every bound identity from disk and require an exact match."""
    if not isinstance(manifest, Mapping):
        raise RuleBundleTamperError("rule-bundle manifest must be an object")
    missing = [key for key in _REQUIRED_KEYS if key not in manifest]
    if missing:
        raise RuleBundleTamperError(
            f"rule-bundle manifest missing keys: {sorted(missing)}")
    if int(manifest["schema_version"]) != SCHEMA_VERSION:
        raise RuleBundleTamperError("unsupported rule-bundle schema_version")
    if manifest["artifact_type"] != ARTIFACT_TYPE:
        raise RuleBundleTamperError("unexpected rule-bundle artifact_type")
    recomputed_hash = canonical_sha256(_artifact_core(manifest))
    if recomputed_hash != manifest["artifact_hash"]:
        raise RuleBundleTamperError(
            "rule-bundle artifact_hash mismatch")

    try:
        current = build_rule_bundle_provenance(
            cluster_rules_path=cluster_rules_path,
            member_rules_path=member_rules_path,
            corpus_path=corpus_path,
            corpus_provenance_path=corpus_provenance_path,
            agent_state_paths=agent_state_paths,
            zgrab_dir=zgrab_dir,
            created_at=str(manifest["created_at"]),
        )
    except RuleBundleProvenanceError:
        raise
    except Exception as exc:
        raise RuleBundleTamperError(str(exc)) from exc
    if _artifact_core(current) != _artifact_core(manifest):
        raise RuleBundleTamperError(
            "rule-bundle inputs no longer match the stored manifest")

    expected = {
        "artifact_hash": expected_manifest_hash,
        "corpus.corpus_digest": expected_corpus_digest,
        "runtime.digest": expected_runtime_digest,
        "rules.digest": expected_rules_digest,
    }
    actual = {
        "artifact_hash": manifest["artifact_hash"],
        "corpus.corpus_digest": manifest["corpus"]["corpus_digest"],
        "runtime.digest": manifest["runtime"]["digest"],
        "rules.digest": manifest["rules"]["digest"],
    }
    for field, value in expected.items():
        if value is not None and actual[field] != value:
            raise RuleBundleIdentityMismatch(
                f"{field}={actual[field]!r} differs from expected {value!r}")
    return dict(manifest)

def write_rule_bundle_provenance(manifest: Mapping, path: str) -> str:
    """Atomically write a manifest."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    try:
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, ensure_ascii=False)
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

def load_rule_bundle_provenance(path: str, **validation_inputs: Any) -> dict:
    """Load and strictly validate a manifest against all bound files."""
    manifest = _load_json(path)
    return validate_rule_bundle_provenance(manifest, **validation_inputs)
