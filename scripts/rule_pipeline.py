#!/usr/bin/env python3
"""rule_pipeline.py — deterministic full-corpus rule-generation exchange.

One CLI with three subcommands mediating a direct Claude-Code rule-generation
session (driven by the rule-gen skill) over a **strict phase-aware** rule corpus:

- ``prepare``  — load the strict full construction corpus and write an atomic
  briefing + session manifest.  Preview bytes are representative only; all
  known response identities remain in the deterministic validator.
- ``validate`` — reload independently and gate each 1–2-rule bundle against
  all construction positives, all cross-cluster negatives, unique identities,
  and the probe-echo guard.
- ``freeze``   — bind session + draft + validation report and atomically emit
  stamped rules, one state JSON per target, and a freeze manifest.  Its metrics
  are explicitly in-sample; out-of-sample evidence comes from a separately
  frozen probe-family-disjoint validation round.

The construction report is never called held-out.  The later challenge round
must prove both exact packet and normalized probe-family disjointness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config  # noqa: E402
from core.rule_corpus import (  # noqa: E402
    RuleCorpusError,
    canonical_sha256,
    default_provenance_path,
)
from fingerprint.agent import shapes, tools  # noqa: E402
from fingerprint.agent import code_validator, echo_guard  # noqa: E402
from fingerprint.agent.literal_evidence import analyze_literal  # noqa: E402
from fingerprint.agent.protocol_literal_evidence import (  # noqa: E402
    analyze_protocol_literal, bind_literal_justifications)
from services_config import identification_cluster_of  # noqa: E402

# ---------------------------------------------------------------------------
# Schema / identity constants
# ---------------------------------------------------------------------------

PIPELINE_SCHEMA_VERSION = 2

BRIEFING_ARTIFACT_TYPE = "claude_code_rule_briefing"
SESSION_ARTIFACT_TYPE = "claude_code_rule_session"
DRAFT_ARTIFACT_TYPE = "claude_code_rule_draft"
REPORT_ARTIFACT_TYPE = "claude_code_rule_validation_report"
FREEZE_ARTIFACT_TYPE = "claude_code_rule_freeze_manifest"

GENERATOR_NAME = "claude_code_rule_gen_skill"

POLICY_STRING = (
    "full construction corpus; previews are samples, not ground truth; every "
    "rule constant must be evidence-grounded; 1-2 rules are accepted only if "
    "their OR union passes full atom/identity recall and all-negative precision; "
    "construction metrics are in-sample and fresh probe-family-disjoint results "
    "are the out-of-sample claim")

GO_FORBIDDEN_TOKENS = ("import", "package", "func")

_DRAFT_TOP_KEYS = {
    "schema_version", "artifact_type", "mode", "session_id", "generator",
    "decisions",
}

class PipelineError(ValueError):
    """Actionable pipeline failure (bad input, mismatch, tamper)."""

# ---------------------------------------------------------------------------
# Deterministic IO helpers
# ---------------------------------------------------------------------------

def _file_sha256(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def _atomic_write_json(path: str, payload: Mapping) -> Tuple[str, str]:
    """Write JSON deterministically via a ``.tmp`` sibling + ``os.replace``.

    Returns ``(absolute_path, file_sha256)``.  Bytes are deterministic for a
    given payload (sorted keys, fixed indent), so identical inputs yield
    identical files and digests.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    blob = json.dumps(payload, indent=2, sort_keys=True,
                      ensure_ascii=False) + "\n"
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except BaseException:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise
    return str(target), _file_sha256(str(target))

def _load_json(path: str, label: str) -> Any:
    if not os.path.exists(path):
        raise PipelineError(f"{label} not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"cannot parse {label} {path}: {exc}") from exc

def _require_mapping(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise PipelineError(f"{label} must be a JSON object, got "
                            f"{type(value).__name__}")
    return value

def _require_keys(obj: Mapping, allowed: set, label: str) -> None:
    """Reject missing and unknown keys (unsafe ambiguity fails fast)."""
    missing = sorted(allowed - set(obj))
    if missing:
        raise PipelineError(f"{label} missing keys: {missing}")
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise PipelineError(f"{label} has unknown keys: {unknown} "
                            f"(allowed: {sorted(allowed)})")

def _require_str(obj: Mapping, key: str, label: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PipelineError(f"{label}.{key} must be a non-empty string, got "
                            f"{value!r}")
    return value

# ---------------------------------------------------------------------------
# Skill / corpus loading
# ---------------------------------------------------------------------------

def _resolve_skill_path(explicit: Optional[str]) -> str:
    """Resolve the rule-gen SKILL.md path (explicit → config → repo default)."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    else:
        configured = str(getattr(config, "RULE_GEN_SKILL_PATH", "") or "")
        if configured:
            candidates.append(configured)
        candidates.append(str(_ROOT / ".agents" / "skills" / "rule-gen"
                              / "SKILL.md"))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    raise PipelineError(
        "rule-gen skill file not found (tried: "
        + ", ".join(candidates)
        + "); pass --skill-path with the SKILL.md used by the generator")

def _load_strict_view(corpus_path: str, provenance_path: Optional[str],
                      targets: Sequence[str], mode: str,
                      sampling: Mapping) -> dict:
    """Strict phase-aware corpus view via the existing stats path (fail-fast).

    Never ``json.load``s the corpus (the loader streams large files) and never
    materializes eval bytes.
    """
    return shapes.collect_full_shape_stats(
        corpus_path, list(targets), provenance_path,
        cap_per_member=int(sampling["cap_per_member"]),
        distinct_sample_count=int(sampling["distinct_sample_count"]),
        sample_seed=int(sampling["sample_seed"]),
        mode=mode,
        expected_phase_awareness_mode="strict",
    )

def _sampling_from_args(args: argparse.Namespace) -> dict:
    return {
        "cap_per_member": args.cap_per_member,
        "neg_cap": args.neg_cap,
        "distinct_sample_count": args.pos_distinct,
        "sample_seed": int(getattr(config, "RULE_GEN_SAMPLE_SEED", 12345)),
    }

def _preview_config_from_args(args: argparse.Namespace) -> dict:
    return {
        "top_k": args.top_k,
        "hex_cap": int(getattr(config, "RULE_GEN_HEX_PREVIEW_BYTES", 64)),
        "text_cap": int(getattr(config, "RULE_GEN_TEXT_PREVIEW_BYTES", 256)),
        "printable_ratio": float(
            getattr(config, "RULE_GEN_PRINTABLE_RATIO", 0.6)),
        "theta": float(getattr(config, "RULE_GEN_THETA", 0.9)),
        "min_samples": int(getattr(config, "RULE_GEN_MIN_SAMPLES", 20)),
    }

def _gates() -> dict:
    return {
        "tau_own": float(getattr(config, "RULE_GEN_TAU_OWN", 0.7)),
        "tau_other": float(getattr(config, "RULE_GEN_TAU_OTHER", 0.02)),
        "identity_coverage_min": float(getattr(
            config, "RULE_GEN_IDENTITY_COVERAGE_MIN", 0.90)),
        "echo_min_constant_bytes": int(getattr(
            config, "RULE_GEN_ECHO_GUARD_MIN_CONSTANT_BYTES", 4)),
        "substring_min_len": int(
            getattr(config, "RULE_GEN_SUBSTRING_MIN_LEN", 8)),
        "substring_max_len": int(
            getattr(config, "RULE_GEN_SUBSTRING_MAX_LEN", 64)),
        "substring_top_n": int(getattr(config, "RULE_GEN_SUBSTRING_TOPN", 4)),
    }

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def member_target(cluster: str, member: str) -> str:
    """Deterministic member-mode target key ``<cluster>__<member>``."""
    return f"{cluster}__{member}"

def split_member_target(target: str) -> Tuple[str, str]:
    if "__" not in target:
        raise PipelineError(
            f"member target {target!r} must be '<cluster>__<member>'")
    cluster, member = target.split("__", 1)
    if not cluster or not member:
        raise PipelineError(
            f"member target {target!r} has an empty cluster or member")
    return cluster, member

def _session_targets(mode: str, requested: Sequence[str], stats: Mapping
                     ) -> Tuple[List[str], List[str]]:
    """(targets, requested_clusters) in deterministic order.

    Cluster mode keeps every requested cluster as a target (matching the
    Member mode expands requested clusters into the ``(cluster, member)``
    pairs that have **fit evidence**.
    """
    clusters = sorted({identification_cluster_of(str(c).strip())
                       for c in requested if str(c).strip()})
    if not clusters:
        raise PipelineError("targets must be a comma-separated list of "
                            "cluster names, got nothing usable")
    if mode == "cluster":
        return clusters, clusters
    targets: List[str] = []
    for cluster in clusters:
        for member in sorted(stats.get(cluster, {})):
            targets.append(member_target(cluster, member))
    return targets, clusters

def _truncate_hex(hex_str: str, byte_cap: int) -> str:
    """Truncate a hex string to ``byte_cap`` bytes (2 hex chars per byte)."""
    text = str(hex_str or "")
    return text[: byte_cap * 2]

def _briefing_findings(fit_counter, neg: Mapping[str, List[bytes]],
                       previews: Mapping) -> dict:
    """Deterministic analyzer findings from FULL fit positives vs fit negatives."""
    pos = shapes.all_responses(fit_counter)
    findings = tools.tool_analyze(
        pos,
        neg={k: list(v) for k, v in neg.items()} if neg else None,
        theta=float(previews["theta"]),
        min_samples=int(previews["min_samples"]),
        mode="all",
        tau_other=float(getattr(config, "RULE_GEN_TAU_OTHER", 0.02)),
        min_len=int(getattr(config, "RULE_GEN_SUBSTRING_MIN_LEN", 8)),
        max_len=int(getattr(config, "RULE_GEN_SUBSTRING_MAX_LEN", 64)),
        top_n=int(getattr(config, "RULE_GEN_SUBSTRING_TOPN", 4)),
    )
    byte_cap = int(previews["hex_cap"])
    capped = []
    for finding in findings.get("findings", []):
        capped.append({
            "kind": finding.get("kind"),
            "offset": finding.get("offset"),
            "value_hex": _truncate_hex(finding.get("value_hex", ""), byte_cap),
            "mask_hex": _truncate_hex(finding.get("mask_hex", ""), byte_cap),
        })
    for index, finding in enumerate(capped):
        finding["evidence_id"] = f"deterministic:{index}"
    return {"findings": capped, "rationale": findings.get("rationale", "")}

def _shape_previews(fit_counter, previews: Mapping) -> List[dict]:
    """Top-K previews: truncated hex + decoded text preview + counts only."""
    shapes_list = shapes.top_k(
        fit_counter, int(previews["top_k"]),
        hex_cap=int(previews["hex_cap"]),
        text_cap=int(previews["text_cap"]),
        printable_ratio=float(previews["printable_ratio"]))
    return [{
        "preview_hex": shape.preview_hex,
        "count": shape.count,
        "full_len": shape.full_len,
        "text_preview": shape.text_preview,
    } for shape in shapes_list]

# ---------------------------------------------------------------------------
# prepare
# ---------------------------------------------------------------------------

def _build_briefing(mode: str, targets: Sequence[str], clusters: Sequence[str],
                    ss: Mapping, skill_path: str, skill_sha: str,
                    sampling: Mapping, previews: Mapping, gates: Mapping
                    ) -> dict:
    fit_stats = ss["stats"]
    per_target: List[dict] = []
    for target in targets:
        if mode == "cluster":
            cluster = target
            fit_counter = shapes.cluster_counter(fit_stats, cluster)
            neg = shapes.cluster_negatives(
                fit_stats, cluster, cap=int(sampling["neg_cap"]))
            siblings: List[dict] = []
            note = ("cluster tier: drop version-specific literals; the rule "
                    "must match this cluster and reject every other cluster")
        else:
            cluster, member = split_member_target(target)
            fit_counter = shapes.member_counter(fit_stats, cluster, member)
            neg = shapes.member_negatives(
                fit_stats, cluster, member, cap=int(sampling["neg_cap"]))
            siblings = [{
                "member": sibling,
                "fit_atoms": shapes.member_counter(
                    fit_stats, cluster, sibling).total(),
            } for sibling in sorted(fit_stats.get(cluster, {}))
                if sibling != member]
            note = ("member tier: version/product literals are allowed and "
                    "usually best; discriminate from sibling members only "
                    "(the cluster gate is already confirmed at runtime)")
        entry = {
            "target": target,
            "service": cluster,
            "mode": mode,
            "construction_atoms": int(fit_counter.total()),
            "unique_response_identities": int(len(fit_counter)),
            "negative_kind": "other_clusters" if mode == "cluster"
                             else "sibling_members",
            "negative_groups": [{"name": name, "count": len(bytes_list)}
                                for name, bytes_list in sorted(neg.items())],
            "top_shapes": _shape_previews(fit_counter, previews),
            "findings": _briefing_findings(fit_counter, neg, previews),
            "note": note,
        }
        if mode == "member":
            entry["member"] = split_member_target(target)[1]
            entry["siblings"] = siblings
        if fit_counter.total() == 0:
            entry["note"] += ("; no construction evidence for this target — an honest "
                              "no_invariant decision is expected")
        per_target.append(entry)

    return {
        "schema_version": PIPELINE_SCHEMA_VERSION,
        "artifact_type": BRIEFING_ARTIFACT_TYPE,
        "policy": POLICY_STRING,
        "mode": mode,
        "skill": {"path": os.path.abspath(skill_path), "sha256": skill_sha},
        "agent_input_identity": dict(ss["identity"]),
        "corpus_atom_counts": json.loads(json.dumps(ss["atom_counts"])),
        "requested_clusters": list(clusters),
        "targets": list(targets),
        "gates": dict(gates),
        "per_target": per_target,
        "draft_contract": {
            "schema_version": PIPELINE_SCHEMA_VERSION,
            "artifact_type": DRAFT_ARTIFACT_TYPE,
            "top_level_keys": sorted(_DRAFT_TOP_KEYS),
            "rule_decision_keys_cluster": [
                "rules", "service", "status"],
            "rule_decision_keys_member": [
                "member", "rules", "service", "status"],
            "no_invariant_decision_keys": ["reason", "service", "status"],
            "rule_types": {"cluster": "code", "member": "member_code"},
            "forbidden_go_tokens": list(GO_FORBIDDEN_TOKENS),
            "rule_bundle": {
                "count": "1 or 2",
                "roles": ["primary", "fallback"],
                "rule_keys": ["role", "code", "rationale",
                              "echo_justification"],
            },
            "note": "exactly one decision per session target; each decision "
                    "contains 1-2 pure Go function bodies; primary is required",
        },
    }

def _session_id(mode: str, targets: Sequence[str], identity: Mapping,
                skill_sha: str) -> str:
    """Deterministic session identity (order-independent in targets)."""
    return canonical_sha256({
        "pipeline_schema_version": PIPELINE_SCHEMA_VERSION,
        "artifact_type": SESSION_ARTIFACT_TYPE,
        "mode": mode,
        "targets": sorted(targets),
        "agent_input_identity": dict(identity),
        "skill_sha256": skill_sha,
    })

def _write_session(session_dir: str, briefing: Mapping, mode: str,
                   targets: Sequence[str], clusters: Sequence[str],
                   ss: Mapping, skill_path: str, skill_sha: str,
                   corpus_path: str, provenance_path: str,
                   sampling: Mapping, previews: Mapping, gates: Mapping
                   ) -> Tuple[dict, str]:
    briefing_path, briefing_sha = _atomic_write_json(
        os.path.join(session_dir, "briefing.json"), briefing)
    session_core = {
        "schema_version": PIPELINE_SCHEMA_VERSION,
        "artifact_type": SESSION_ARTIFACT_TYPE,
        "session_id": _session_id(mode, targets, ss["identity"], skill_sha),
        "mode": mode,
        "requested_clusters": list(clusters),
        "targets": list(targets),
        "policy": POLICY_STRING,
        "skill": {"path": os.path.abspath(skill_path), "sha256": skill_sha},
        "corpus": {"path": os.path.abspath(corpus_path),
                   "provenance_path": os.path.abspath(provenance_path)},
        "agent_input_identity": dict(ss["identity"]),
        "corpus_atom_counts": json.loads(json.dumps(ss["atom_counts"])),
        "sampling": dict(sampling),
        "previews": dict(previews),
        "gates": dict(gates),
        "briefing": {"path": briefing_path, "file_sha256": briefing_sha,
                     "digest": canonical_sha256(dict(briefing))},
        "generator": GENERATOR_NAME,
    }
    session = dict(session_core)
    session["session_digest"] = _session_digest(session_core)
    session_path, _ = _atomic_write_json(
        os.path.join(session_dir, "session.json"), session)
    return session, session_path

def _session_digest(session_core: Mapping) -> str:
    """Hash semantic session content without its relocatable output path."""
    normalized = dict(session_core)
    briefing = dict(normalized.get("briefing") or {})
    briefing.pop("path", None)
    normalized["briefing"] = briefing
    return canonical_sha256(normalized)

def _load_session(session_dir: str) -> Tuple[dict, str]:
    session_path = os.path.join(session_dir, "session.json")
    session = _require_mapping(
        _load_json(session_path, "session manifest"), "session manifest")
    if session.get("artifact_type") != SESSION_ARTIFACT_TYPE:
        raise PipelineError(
            f"session manifest has unexpected artifact_type "
            f"{session.get('artifact_type')!r}")
    core = {k: v for k, v in session.items() if k != "session_digest"}
    recorded = session.get("session_digest")
    recomputed = _session_digest(core)
    if recorded != recomputed:
        raise PipelineError(
            "session manifest digest mismatch (recorded "
            f"{recorded!r}, recomputed {recomputed!r}); the manifest was "
            "edited or corrupted — rerun prepare")
    mode = session.get("mode")
    if mode not in ("cluster", "member"):
        raise PipelineError(f"session manifest has invalid mode {mode!r}")
    targets = session.get("targets")
    if (not isinstance(targets, list) or not targets
            or any(not isinstance(t, str) for t in targets)):
        raise PipelineError("session manifest targets must be a non-empty "
                            "list of strings")
    return session, session_path

# ---------------------------------------------------------------------------
# Draft schema (strict)
# ---------------------------------------------------------------------------

def _check_go_body(code: str, label: str) -> None:
    if not isinstance(code, str) or not code.strip():
        raise PipelineError(f"{label}.code must be a non-empty Go body string")
    for token in GO_FORBIDDEN_TOKENS:
        if re.search(rf"\b{token}\b", code):
            raise PipelineError(
                f"{label}.code contains forbidden token {token!r}; code must "
                "be a pure function BODY (the harness wraps it and pre-imports"
                " bytes/binary)")

def _validate_draft(draft: Any, session: Mapping) -> List[dict]:
    """Strict draft validation; returns decisions in deterministic order.

    Rejects: unknown/missing keys, wrong artifact/mode, session mismatch,
    duplicate decisions, target scope mismatch, missing member (member mode),
    forbidden Go tokens.
    """
    label = "draft"
    draft = _require_mapping(draft, label)
    _require_keys(draft, _DRAFT_TOP_KEYS, label)
    if (isinstance(draft["schema_version"], bool)
            or not isinstance(draft["schema_version"], int)
            or draft["schema_version"] != PIPELINE_SCHEMA_VERSION):
        raise PipelineError(
            f"unsupported draft schema_version {draft['schema_version']!r}")
    if draft["artifact_type"] != DRAFT_ARTIFACT_TYPE:
        raise PipelineError(
            f"unexpected draft artifact_type {draft['artifact_type']!r}")
    mode = session["mode"]
    if draft["mode"] != mode:
        raise PipelineError(
            f"draft mode {draft['mode']!r} does not match session mode "
            f"{mode!r}")
    if draft["session_id"] != session["session_id"]:
        raise PipelineError(
            "draft session_id does not match the session manifest (draft "
            f"{draft['session_id']!r} vs session "
            f"{session['session_id']!r}); regenerate the draft from this "
            "session briefing")
    generator = draft.get("generator")
    if not isinstance(generator, dict) or not generator:
        raise PipelineError("draft.generator must be a non-empty object with "
                            "generator metadata (e.g. name/model)")
    decisions = draft.get("decisions")
    if not isinstance(decisions, list) or not decisions:
        raise PipelineError("draft.decisions must be a non-empty list")

    scope = set(session["targets"])
    seen: Dict[str, dict] = {}
    for index, decision in enumerate(decisions):
        dlabel = f"draft.decisions[{index}]"
        decision = _require_mapping(decision, dlabel)
        status = decision.get("status")
        if status == "rule":
            if mode == "member":
                allowed = {"service", "member", "status", "rules"}
            else:
                allowed = {"service", "status", "rules"}
        elif status == "no_invariant":
            if mode == "member":
                allowed = {"service", "member", "status", "reason"}
            else:
                allowed = {"service", "status", "reason"}
        else:
            raise PipelineError(
                f"{dlabel}.status must be 'rule' or 'no_invariant', got "
                f"{status!r}")
        _require_keys(decision, allowed, dlabel)
        service = _require_str(decision, "service", dlabel)
        if mode == "member":
            member = _require_str(decision, "member", dlabel)
            target = member_target(service, member)
        else:
            target = service
        if target not in scope:
            raise PipelineError(
                f"{dlabel} targets {target!r} which is outside this "
                f"session's targets {sorted(scope)}")
        if target in seen:
            raise PipelineError(
                f"duplicate decision for target {target!r}; exactly one "
                "decision per target is allowed")
        if status == "rule":
            bundle = decision.get("rules")
            if not isinstance(bundle, list) or not 1 <= len(bundle) <= 2:
                raise PipelineError(
                    f"{dlabel}.rules must contain 1 or 2 rule objects")
            roles = []
            for rule_index, raw_rule in enumerate(bundle):
                rlabel = f"{dlabel}.rules[{rule_index}]"
                rule = _require_mapping(raw_rule, rlabel)
                _require_keys(rule, {
                    "role", "code", "rationale", "echo_justification"}, rlabel)
                role = _require_str(rule, "role", rlabel)
                if role not in ("primary", "fallback"):
                    raise PipelineError(
                        f"{rlabel}.role must be 'primary' or 'fallback'")
                roles.append(role)
                _check_go_body(rule.get("code"), rlabel)
                _require_str(rule, "rationale", rlabel)
                justifications = rule.get("echo_justification")
                if not isinstance(justifications, list):
                    raise PipelineError(
                        f"{rlabel}.echo_justification must be a list")
            if roles.count("primary") != 1 or len(set(roles)) != len(roles):
                raise PipelineError(
                    f"{dlabel}.rules must contain exactly one primary and at "
                    "most one fallback")
        else:
            _require_str(decision, "reason", dlabel)
        seen[target] = dict(decision)
    return [seen[target] for target in sorted(seen)]

# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def _construction_views(mode: str, target: str, ss: Mapping
                        ) -> Tuple[List[bytes], List[bytes],
                                   Dict[str, List[bytes]], List[bytes], List[dict]]:
    """Reconstruct full construction positives/negatives and echo evidence."""
    stats = ss["stats"]
    if mode == "cluster":
        counter = shapes.cluster_counter(stats, target)
        neg = shapes.cluster_negatives(stats, target, cap=None)
        observations = list(ss.get("observations", {}).get(target, []))
    else:
        cluster, member = split_member_target(target)
        counter = shapes.member_counter(stats, cluster, member)
        neg = shapes.member_negatives(stats, cluster, member, cap=None)
        observations = [row for row in
                        ss.get("observations", {}).get(cluster, [])
                        if row.get("member") == member]
        target = cluster
    held = shapes.all_responses(counter)
    distinct = [bytes.fromhex(value) for value in sorted(counter)]
    packets = echo_guard.packet_hexes_to_bytes(
        ss.get("packets", {}).get(target, []))
    return held, distinct, neg, packets, observations

def _decision_digest(decision: Mapping) -> str:
    return canonical_sha256(dict(decision))

def cmd_validate(args: argparse.Namespace) -> int:
    session, _session_path = _load_session(args.session_dir)
    draft_path = args.draft or os.path.join(args.session_dir, "draft.json")
    draft_digest = _file_sha256(draft_path)
    draft = _load_json(draft_path, "draft")
    decisions = _validate_draft(draft, session)

    # Independent strict reload; any corpus/session drift fails fast.  The
    # reload uses the requested CLUSTER names (the sampling-identity inputs of
    # prepare), not the expanded member targets.
    ss = _load_strict_view(
        session["corpus"]["path"], session["corpus"]["provenance_path"],
        session["requested_clusters"], session["mode"], session["sampling"])
    if ss["identity"] != session["agent_input_identity"]:
        raise PipelineError(
            "corpus identity changed since prepare (agent_input_identity "
            "mismatch); rerun prepare and regenerate the draft")

    mode = session["mode"]
    tau_own = float(session["gates"]["tau_own"])
    tau_other = float(session["gates"]["tau_other"])
    identity_min = float(session["gates"]["identity_coverage_min"])
    briefing = _load_json(session["briefing"]["path"], "briefing")
    if _file_sha256(session["briefing"]["path"]) != session["briefing"]["file_sha256"]:
        raise PipelineError("briefing changed after prepare")
    briefing_targets = {row["target"]: row for row in briefing["per_target"]}

    entries: List[dict] = []
    aggregate = {"targets_total": len(session["targets"]),
                 "rule_decisions": 0, "rules_accepted": 0,
                 "rules_rejected": 0, "no_invariant": 0}
    for target in session["targets"]:
        decision = next((d for d in decisions
                         if (member_target(d["service"], d["member"])
                             if mode == "member" else d["service"]) == target),
                        None)
        entry = {"target": target, "service": split_member_target(target)[0]
                 if mode == "member" else target}
        if mode == "member":
            entry["member"] = split_member_target(target)[1]
        if decision is None:
            entry.update({"decision_status": "missing", "accepted": None,
                          "reason": "no decision for this target in the draft",
                          "recall": None})
            entries.append(entry)
            continue
        entry["decision_status"] = decision["status"]
        entry["decision_digest"] = _decision_digest(decision)
        if decision["status"] == "no_invariant":
            entry.update({"accepted": None, "reason": decision["reason"],
                          "recall": None})
            aggregate["no_invariant"] += 1
            entries.append(entry)
            continue
        aggregate["rule_decisions"] += 1
        held, held_distinct, neg, packets, observations = _construction_views(
            mode, target, ss)
        entry["n_held"] = len(held)
        entry["n_distinct"] = len(held_distinct)
        entry["n_negative_groups"] = len(neg)
        if mode == "member" and not neg:
            entry.update({"accepted": False, "recall": 0.0,
                          "reason": "no sibling-member negatives in construction corpus; a "
                          "member rule without precision evidence cannot be "
                          "accepted — declare no_invariant"})
        elif not held:
            entry.update({"accepted": False, "recall": 0.0,
                          "reason": "no construction positives — declare no_invariant"})
        else:
            target_briefing = briefing_targets.get(target, {})
            allowed_evidence = {
                str(finding.get("evidence_id"))
                for finding in (target_briefing.get("findings", {})
                                .get("findings", []))
                if finding.get("evidence_id")}
            echo_reports = []
            echo_ok = True
            for rule in decision["rules"]:
                # Supplement top-N briefing findings only through reproducible
                # response-side measurements, never through free-form IDs.
                literal_findings = []
                protocol_findings = []
                verified_by_literal = {}
                protocol_ids = {e for j in rule["echo_justification"]
                                for e in j.get("evidence_ids", [])
                                if isinstance(e, str) and e.startswith("protocol-literal-v1:")}
                for constant in echo_guard.extract_go_constants(rule["code"]):
                    if not protocol_ids:
                        break
                    finding = analyze_protocol_literal(bytes.fromhex(constant.constant_hex),
                        target=target, corpus_identity=ss["identity"])
                    if finding is not None:
                        protocol_findings.append(finding)
                        if finding["evidence_id"] in protocol_ids and any(
                                j.get("constant_hex") == constant.constant_hex
                                and finding["evidence_id"] in j.get("evidence_ids", [])
                                for j in rule["echo_justification"]):
                            allowed_evidence.add(finding["evidence_id"])
                            verified_by_literal.setdefault(constant.constant_hex, set()).add(finding["evidence_id"])
                claimed_ids = {e for j in rule["echo_justification"]
                               for e in j.get("evidence_ids", [])
                               if isinstance(e, str) and e.startswith("response-literal-v1:")}
                for constant in echo_guard.extract_go_constants(rule["code"]):
                    if not claimed_ids:
                        break
                    finding = analyze_literal(bytes.fromhex(constant.constant_hex),
                        observations, neg, target=target, corpus_identity=ss["identity"])
                    literal_findings.append(finding)
                    if finding["eligible"] and finding["evidence_id"] in claimed_ids:
                        # Bind this evidence to this exact literal as well.
                        if any(j.get("constant_hex") == constant.constant_hex
                               and finding["evidence_id"] in j.get("evidence_ids", [])
                               for j in rule["echo_justification"]):
                            allowed_evidence.add(finding["evidence_id"])
                            verified_by_literal.setdefault(constant.constant_hex, set()).add(finding["evidence_id"])
                echo_report = echo_guard.check_echo_guard(
                    rule["code"], packets, bind_literal_justifications(
                        rule["echo_justification"], verified_by_literal),
                    min_bytes=int(session["gates"]["echo_min_constant_bytes"]),
                    observations=observations,
                    allowed_evidence_ids=allowed_evidence)
                echo_reports.append({"role": rule["role"], **echo_report,
                                     "response_literal_findings": literal_findings,
                                     "protocol_literal_findings": protocol_findings})
                echo_ok = echo_ok and echo_report["status"] == "pass"
            if not echo_ok:
                entry.update({
                    "accepted": False, "recall": 0.0,
                    "identity_coverage": 0.0,
                    "reason": "probe-echo guard rejected one or more rules",
                    "echo_guard": echo_reports,
                })
            else:
                ok, reason, recall, coverage, details = (
                    code_validator.validate_code_bundle(
                        [rule["code"] for rule in decision["rules"]],
                        held, neg, tau_own, tau_other,
                        held_distinct=held_distinct,
                        min_identity_coverage=identity_min))
                entry.update({"accepted": bool(ok), "reason": reason,
                              "recall": recall,
                              "identity_coverage": coverage,
                              "per_rule": details,
                              "echo_guard": echo_reports})
        if entry["accepted"]:
            aggregate["rules_accepted"] += 1
        else:
            aggregate["rules_rejected"] += 1
        entries.append(entry)

    missing = sorted(e["target"] for e in entries
                     if e["decision_status"] == "missing")
    core = {
        "schema_version": PIPELINE_SCHEMA_VERSION,
        "artifact_type": REPORT_ARTIFACT_TYPE,
        "session_id": session["session_id"],
        "mode": mode,
        "generator": GENERATOR_NAME,
        "draft_path": os.path.abspath(draft_path),
        "draft_digest": draft_digest,
        "corpus_identity": dict(session["agent_input_identity"]),
        "gates": dict(session["gates"]),
        "construction_in_sample": True,
        "held_out_axis": "fresh_probe_family_disjoint_round",
        "meaning": "accepted == full-construction accepted; these are "
                   "in-sample construction metrics, NOT fresh-round results",
        "targets": entries,
        "missing_decision_targets": missing,
        "aggregate": aggregate,
    }
    report = dict(core)
    report["report_digest"] = canonical_sha256(core)

    report_path, _ = _atomic_write_json(args.report, report)
    print(f"[validate] session={session['session_id'][:12]}… "
          f"rules accepted={aggregate['rules_accepted']}/"
          f"{aggregate['rule_decisions']} "
          f"no_invariant={aggregate['no_invariant']} "
          f"missing={len(missing)} (construction in-sample; fresh round pending)")
    print(f"[validate] report → {report_path}")
    return 0

def _load_report(report_path: str, session: Mapping,
                 draft_digest: str) -> dict:
    report = _require_mapping(
        _load_json(report_path, "validation report"), "validation report")
    if report.get("artifact_type") != REPORT_ARTIFACT_TYPE:
        raise PipelineError(
            "validation report has unexpected artifact_type "
            f"{report.get('artifact_type')!r}")
    core = {k: v for k, v in report.items() if k != "report_digest"}
    recorded = report.get("report_digest")
    recomputed = canonical_sha256(core)
    if recorded != recomputed:
        raise PipelineError(
            "validation report digest mismatch (recorded "
            f"{recorded!r}, recomputed {recomputed!r}); the report was "
            "tampered with or truncated — rerun validate")
    if report.get("session_id") != session["session_id"]:
        raise PipelineError(
            "validation report session_id does not match this session "
            f"({report.get('session_id')!r} vs "
            f"{session['session_id']!r})")
    if report.get("draft_digest") != draft_digest:
        raise PipelineError(
            "draft changed after validation (draft digest "
            f"{draft_digest!r} != report {report.get('draft_digest')!r}); "
            "rerun validate on the current draft")
    return report

# ---------------------------------------------------------------------------
# freeze
# ---------------------------------------------------------------------------

def _stamped_rules(mode: str, decision: Mapping) -> List[dict]:
    """Server-stamped 1–2 rule records; service/type cannot be forged."""
    rule_type = "member_code" if mode == "member" else "code"
    stamped: List[dict] = []
    for item in decision["rules"]:
        rule = {
            "service": decision["service"],
            "source": rule_type,
            "type": rule_type,
            "role": item["role"],
            "code": item["code"],
            "rationale": item["rationale"],
            "echo_justification": list(item["echo_justification"]),
        }
        if mode == "member":
            rule["member"] = decision["member"]
        stamped.append(rule)
    return stamped

def cmd_freeze(args: argparse.Namespace) -> int:
    session, _session_path = _load_session(args.session_dir)
    draft_path = args.draft or os.path.join(args.session_dir, "draft.json")
    draft_digest = _file_sha256(draft_path)
    draft = _load_json(draft_path, "draft")
    decisions = _validate_draft(draft, session)
    report = _load_report(args.report, session, draft_digest)

    mode = session["mode"]
    by_target = {
        (member_target(d["service"], d["member"]) if mode == "member"
         else d["service"]): d
        for d in decisions}
    report_by_target = {e["target"]: e for e in report.get("targets", [])}
    session_targets = list(session["targets"])

    missing = [t for t in session_targets if t not in by_target]
    if missing:
        raise PipelineError(
            f"freeze requires exactly one decision per session target; "
            f"missing decisions for {sorted(missing)} "
            f"(session targets: {session_targets})")
    extra = [t for t in sorted(by_target) if t not in set(session_targets)]
    if extra:
        raise PipelineError(f"decisions outside the session targets: {extra}")

    rules: List[dict] = []
    states: List[dict] = []
    skill_sha = session["skill"]["sha256"]
    validation_digest = report["report_digest"]
    for target in sorted(session_targets):
        decision = by_target[target]
        entry = report_by_target.get(target)
        if entry is None:
            raise PipelineError(
                f"validation report has no entry for target {target!r}; "
                "rerun validate")
        if entry.get("decision_digest") != _decision_digest(decision):
            raise PipelineError(
                f"decision for target {target!r} differs from the validated "
                "one (decision_digest mismatch); rerun validate")
        target_rules: List[dict] = []
        if decision["status"] == "rule":
            if entry.get("accepted") is not True:
                raise PipelineError(
                    f"rule bundle for target {target!r} is not construction-accepted "
                    f"(reason: {entry.get('reason')!r}); only dev-accepted "
                    "rules may be frozen — fix the bundle or declare "
                    "no_invariant and rerun validate")
            target_rules = _stamped_rules(mode, decision)
            rules.extend(target_rules)
        service = split_member_target(target)[0] if mode == "member" else target
        state = {
            "attempted": True,
            "mode": mode,
            "target": target,
            "service": service,
            "status": decision["status"],
            "rules": target_rules,
            "generator": GENERATOR_NAME,
            "skill_sha256": skill_sha,
            "agent_input_identity": dict(session["agent_input_identity"]),
            "session_id": session["session_id"],
            "draft_digest": draft_digest,
            "validation_digest": validation_digest,
            "fresh_validation_status": "not_evaluated",
            "construction_validation": {
                "accepted": entry.get("accepted"),
                "reason": entry.get("reason", ""),
                "recall": entry.get("recall"),
                "identity_coverage": entry.get("identity_coverage"),
                "meaning": "full-construction in-sample; fresh probe-family "
                           "validation has not run",
            },
        }
        if decision["status"] == "rule":
            state["rule_roles"] = [rule["role"] for rule in target_rules]
        else:
            state["reason"] = decision["reason"]
        if mode == "member":
            state["member"] = decision["member"]
        states.append(state)

    rules_path, rules_sha = _atomic_write_json(args.rules_out, rules)
    state_dir = args.state_dir
    state_records: List[dict] = []
    for state in states:
        state_path, state_sha = _atomic_write_json(
            os.path.join(state_dir, f"{state['target']}.json"), state)
        state_records.append({"target": state["target"], "path": state_path,
                              "file_sha256": state_sha})

    core = {
        "schema_version": PIPELINE_SCHEMA_VERSION,
        "artifact_type": FREEZE_ARTIFACT_TYPE,
        "session_id": session["session_id"],
        "mode": mode,
        "targets": list(session_targets),
        "generator": GENERATOR_NAME,
        "skill_sha256": skill_sha,
        "agent_input_identity": dict(session["agent_input_identity"]),
        "corpus": dict(session["corpus"]),
        "draft_digest": draft_digest,
        "validation_digest": validation_digest,
        "fresh_validation_status": "not_evaluated",
        "construction_in_sample": True,
        "rules": {"path": rules_path, "file_sha256": rules_sha,
                  "count": len(rules)},
        "states": state_records,
    }
    manifest = dict(core)
    manifest["manifest_digest"] = canonical_sha256(core)
    manifest_path, _ = _atomic_write_json(args.manifest, manifest)

    accepted = sum(1 for s in states if s["status"] == "rule")
    print(f"[freeze] session={session['session_id'][:12]}… targets="
          f"{len(states)} rules={len(rules)} no_invariant="
          f"{len(states) - accepted} fresh_validation_status=not_evaluated")
    print(f"[freeze] rules → {rules_path}")
    print(f"[freeze] states → {state_dir}")
    print(f"[freeze] manifest → {manifest_path}")
    return 0

# ---------------------------------------------------------------------------
# prepare command + CLI
# ---------------------------------------------------------------------------

def cmd_prepare(args: argparse.Namespace) -> int:
    skill_path = _resolve_skill_path(args.skill_path)
    skill_sha = _file_sha256(skill_path)

    requested = sorted({t.strip() for t in args.targets.split(",")
                        if t.strip()})
    if not requested:
        raise PipelineError("--targets must name at least one cluster")
    for name in ("top_k", "pos_distinct", "cap_per_member", "neg_cap"):
        value = getattr(args, name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise PipelineError(
                f"--{name.replace('_', '-')} must be a positive integer, "
                f"got {value!r}")
    sampling = _sampling_from_args(args)
    previews = _preview_config_from_args(args)
    gates = _gates()

    ss = _load_strict_view(args.corpus, args.corpus_provenance, requested,
                           args.mode, sampling)
    targets, clusters = _session_targets(args.mode, requested, ss["stats"])
    if not targets:
        raise PipelineError(
            "member mode found no (cluster, member) with construction evidence for "
            f"clusters {requested}; nothing to generate — check --targets")

    briefing = _build_briefing(args.mode, targets, clusters, ss, skill_path,
                               skill_sha, sampling, previews, gates)
    provenance = args.corpus_provenance or default_provenance_path(args.corpus)
    session, session_path = _write_session(
        args.session_dir, briefing, args.mode, targets, clusters, ss,
        skill_path, skill_sha, args.corpus, provenance, sampling, previews,
        gates)

    print(f"[prepare] session={session['session_id'][:12]}… mode="
          f"{args.mode} targets={len(targets)} "
          f"construction_atoms={ss['atom_counts']['atoms']} "
          f"unique-response-aware=true")
    print(f"[prepare] briefing → {session['briefing']['path']}")
    print(f"[prepare] session → {session_path}")
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rule_pipeline",
        description=("Deterministic prepare/validate/freeze exchange for "
                     "rule generation (rule-gen skill) over a strict full "
                     "construction corpus. Accepted metrics are in-sample; "
                     "fresh probe-family validation is a separate stage."))
    sub = parser.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--session-dir", required=True,
                        help="directory holding briefing.json/session.json "
                             "(and default draft/report paths)")

    p_prepare = sub.add_parser(
        "prepare", parents=[common],
        help="load the strict corpus and write the full-construction briefing "
             "+ session manifest")
    p_prepare.add_argument("--corpus", required=True,
                           help="strict phase-aware rule_corpus.json")
    p_prepare.add_argument("--corpus-provenance", default=None,
                           help="provenance sidecar (default: "
                                "<corpus>.provenance.json)")
    p_prepare.add_argument("--targets", required=True,
                           help="comma-separated cluster names (member mode "
                                 "expands them to (cluster,member) targets "
                                 "with fit evidence)")
    p_prepare.add_argument("--mode", choices=["cluster", "member"],
                           default="cluster",
                           help="cluster=one Go rule per cluster; "
                                "member=one Go rule per member")
    p_prepare.add_argument("--skill-path", default=None,
                           help="rule-gen SKILL.md (default: "
                                "config.RULE_GEN_SKILL_PATH)")
    p_prepare.add_argument("--top-k", type=int,
                           default=int(getattr(config, "RULE_GEN_TOP_K_SHAPES",
                                               20)),
                           help="top-K shape previews per target")
    p_prepare.add_argument("--pos-distinct", type=int,
                           default=int(getattr(config, "RULE_GEN_POS_DISTINCT",
                                               64)),
                           help="distinct construction shapes sampled for analysis")
    p_prepare.add_argument("--cap-per-member", type=int,
                           default=int(getattr(
                               config, "RULE_GEN_SAMPLE_PER_CLUSTER", 400)),
                           help="corpus construction repetition budget identity")
    p_prepare.add_argument("--neg-cap", type=int,
                           default=int(getattr(
                               config, "RULE_GEN_NEGATIVES_PER_CLUSTER", 60)),
                           help="per-group negative cap")
    p_prepare.set_defaults(func=cmd_prepare)

    p_validate = sub.add_parser(
        "validate", parents=[common],
        help="strictly validate 1-2 rules against full construction responses, "
             "all negatives and the echo guard")
    p_validate.add_argument("--draft", default=None,
                            help="draft JSON (default: "
                                 "<session-dir>/draft.json)")
    p_validate.add_argument("--report", default=None,
                            help="output report (default: "
                                 "<session-dir>/validation_report.json)")
    p_validate.set_defaults(
        report=None, func=cmd_validate)

    p_freeze = sub.add_parser(
        "freeze", parents=[common],
        help="freeze construction-accepted rules into stamped rules + state "
             "+ manifest (fresh validation remains pending)")
    p_freeze.add_argument("--draft", default=None,
                          help="draft JSON (default: <session-dir>/draft.json)")
    p_freeze.add_argument("--report", default=None,
                          help="validation report (default: "
                               "<session-dir>/validation_report.json)")
    p_freeze.add_argument("--rules-out", required=True,
                          help="output JSON array of stamped rules")
    p_freeze.add_argument("--state-dir", required=True,
                          help="output directory for per-target state JSON")
    p_freeze.add_argument("--manifest", default=None,
                          help="freeze manifest (default: "
                               "<session-dir>/freeze_manifest.json)")
    p_freeze.set_defaults(func=cmd_freeze)
    return parser

def _apply_output_defaults(args: argparse.Namespace) -> None:
    if args.cmd == "validate" and args.report is None:
        args.report = os.path.join(args.session_dir, "validation_report.json")
    if args.cmd == "freeze":
        if args.report is None:
            args.report = os.path.join(args.session_dir,
                                       "validation_report.json")
        if args.manifest is None:
            args.manifest = os.path.join(args.session_dir,
                                         "freeze_manifest.json")

def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _apply_output_defaults(args)
    try:
        return args.func(args)
    except (PipelineError, RuleCorpusError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[error] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
