"""Deterministic tools exposed to the rule-gen skill through JSON stdin/stdout. Analyze byte patterns, retrieve original evidence, run bounded analysis, validate Go functions, reject probe echoes and admit rules. The coding agent orchestrates these tools directly."""

import argparse
import asyncio
import json
import sys
from typing import Dict, List, Optional, Tuple

import config
from . import analyzer, code_validator, validator
from .schema import dict_to_findings, findings_to_dict

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def _hexs_to_bytes(lst: List[str]) -> List[bytes]:
    out = []
    for h in lst or []:
        try:
            out.append(bytes.fromhex(h))
        except (ValueError, TypeError):
            continue
    return out

def _bytes_to_hexs(lst: List[bytes]) -> List[str]:
    return [b.hex() for b in lst]

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def _check_code_rule(rule: dict, held: List[bytes], neg: Dict[str, List[bytes]],
                     min_recall: Optional[float], tau_own: float,
                     tau_other: float, held_distinct: List[bytes] = None,
                     min_identity_coverage: Optional[float] = None
                     ) -> Tuple[bool, str, float, float]:
    """Validate a Go body against precision, atom recall and unique-identity coverage gates."""
    if not getattr(config, "RULE_GEN_CODE_ENABLE", True):
        return (False, "code rules are disabled (config.RULE_GEN_CODE_ENABLE=False)",
                0.0, 0.0)
    body = rule.get("code", "") or ""
    if min_recall is not None:
        mr = max(min_recall, getattr(config, "RULE_GEN_CODE_MIN_RECALL", 0.3))
    else:
        mr = tau_own
    if min_identity_coverage is None:
        min_identity_coverage = getattr(
            config, "RULE_GEN_IDENTITY_COVERAGE_MIN", 0.90)
    return code_validator.validate_code(
        body, held, neg, mr, tau_other,
        timeout=getattr(config, "RULE_GEN_CODE_TIMEOUT", 10.0),
        go_bin=getattr(config, "RULE_GEN_CODE_GO_BIN", "go"),
        held_distinct=held_distinct,
        min_identity_coverage=min_identity_coverage)

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def tool_analyze(pos: List[bytes], neg: Dict[str, List[bytes]] = None,
                 subset: Optional[List[bytes]] = None,
                 theta: float = 0.9, min_samples: int = 20,
                 mode: str = "all", tau_other: float = 0.02,
                 min_len: int = 8, max_len: int = 64, top_n: int = 4) -> dict:
    """Extract deterministic invariants and substrings frequent in positives but absent from negatives."""
    rs = list(subset) if subset is not None else list(pos)
    findings_list, rationale_parts = [], []
    if mode in ("all", "deterministic"):
        fs_det = analyzer.deterministic_analyzer(rs, theta=theta, min_samples=min_samples)
        findings_list.extend(fs_det.findings)
        if fs_det.rationale:
            rationale_parts.append(fs_det.rationale)
    if mode in ("all", "substrings") and neg:
        subs = analyzer.discriminating_substrings(
            rs, neg, theta=theta, tau_other=tau_other,
            min_len=min_len, max_len=max_len, top_n=top_n)
        findings_list.extend(subs)
        if subs:
            rationale_parts.append(
                "substrings: " + "; ".join(bytes.fromhex(f.value_hex).hex()[:32] for f in subs))
    fs = analyzer.Findings(findings_list, rationale="; ".join(rationale_parts) or "no invariant")
    return findings_to_dict(fs)

def tool_rag(rag_client, cluster: str, task: str) -> dict:
    """Retrieve source-bound response-format evidence for the coding agent."""
    from scripts.spec_agent import retrieve
    from services_config import identification_candidates
    profiles = identification_candidates(cluster)
    if len(profiles) == 1:
        return retrieve(profiles[0], task, backend="lexical")
    return {"identification_service": cluster,
            "profiles": [retrieve(name, task, backend="lexical") for name in profiles]}

def tool_run_code(code: str, pos: List[bytes], neg: Dict[str, List[bytes]]) -> dict:
    """Run bounded analysis over positive responses and flattened cross-service negatives."""
    neg_list = [b for hs in neg.values() for b in hs] if isinstance(neg, dict) else list(neg or [])
    result, err = analyzer.run_code(code, pos, neg_list)
    if err:
        return {"error": err}
    return {"result": result}

def tool_validate(rule: dict, held: List[bytes],
                  neg: Dict[str, List[bytes]], tau_own: float, tau_other: float,
                  allow_version_locked: bool = False,
                  min_recall: float = None,
                  held_distinct: List[bytes] = None,
                  min_identity_coverage: float = None) -> dict:
    """Validate one generated Go function or supported four-form rule."""
    if rule.get("type") in ("code", "member_code"):
        ok, reason, recall, coverage = _check_code_rule(
            rule, held, neg, min_recall, tau_own, tau_other,
            held_distinct=held_distinct,
            min_identity_coverage=min_identity_coverage)
        return {"ok": ok, "reason": reason, "recall": recall,
                "identity_coverage": coverage}
    ok, reason = validator.validate(rule, held, neg, tau_own, tau_other,
                                    allow_version_locked=allow_version_locked,
                                    min_recall=min_recall)
    return {"ok": ok, "reason": reason}

def tool_select_cover(findings: dict, service: str, held: List[bytes],
                      neg: Dict[str, List[bytes]], tau_own: float,
                      tau_other: float, member: str = None,
                      allow_version_locked: bool = False,
                      full_coverage: bool = False) -> dict:
    """Select a precision-clean rule set covering the supplied findings."""
    fs = dict_to_findings(findings)
    rules, reason = validator.select_covered_rules(
        fs, service, "llm", held, neg, tau_own, tau_other,
        member=member, allow_version_locked=allow_version_locked,
        full_coverage=full_coverage)
    return {"rules": rules, "reason": reason}

def tool_submit_rules(rules: List[dict], service: str, held: List[bytes],
                      neg: Dict[str, List[bytes]], tau_own: float,
                      tau_other: float, member: str = None,
                      allow_version_locked: bool = False,
                      min_recall: float = None,
                      held_distinct: List[bytes] = None,
                      min_identity_coverage: float = None) -> dict:
    """Revalidate each proposed rule before returning an admitted submission."""
    accepted, rejected = [], []
    for rule in rules or []:
        r = dict(rule)
        r["service"] = service                
        is_code = r.get("type") in ("code", "member_code")
        if is_code:
            r["source"] = "member_code" if member is not None else "code"
        else:
            r["source"] = "member_llm" if member is not None else "llm"
        if member is not None:
            r["member"] = member
        if is_code:
            ok, reason, _recall, _cov = _check_code_rule(
                r, held, neg, min_recall, tau_own, tau_other,
                held_distinct=held_distinct,
                min_identity_coverage=min_identity_coverage)
        else:
            ok, reason = validator.validate(r, held, neg, tau_own, tau_other,
                                            allow_version_locked=allow_version_locked,
                                            min_recall=min_recall)
        if ok:
            accepted.append(r)
        else:
            rejected.append({"rule": r, "reason": reason})
    return {"accepted": accepted, "rejected": rejected}

def tool_echo_check(code: str, packets: List[bytes],
                    justification: List[dict] = None,
                    observations: List[dict] = None,
                    allowed_evidence_ids: List[str] = None) -> dict:
    """Check request-echo provenance; the deterministic pipeline enforces the same guard."""
    from . import echo_guard

    return echo_guard.check_echo_guard(
        code, packets, justification or (),
        min_bytes=getattr(config, "RULE_GEN_ECHO_GUARD_MIN_CONSTANT_BYTES", 4),
        observations=observations or (),
        allowed_evidence_ids=allowed_evidence_ids)

def tool_declare_no_invariant(reason: str = "") -> dict:
    """Record an explicit inability to establish a discriminating invariant."""
    return {"declared": True, "reason": reason}

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def _read_json():
    return json.load(sys.stdin)

def _emit(obj):
    json.dump(obj, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")

def _cli():
    ap = argparse.ArgumentParser(description="Rule-generation tools (JSON stdin to stdout).")
    ap.add_argument("cmd", choices=["analyze", "rag", "run_code", "validate",
                                    "echo_check", "select_cover", "submit_rules",
                                    "declare_no_invariant"])
    args = ap.parse_args()
    data = _read_json()

    if args.cmd == "analyze":
        subset = _hexs_to_bytes(data.get("subset"))
        neg = {k: _hexs_to_bytes(v) for k, v in (data.get("neg") or {}).items()}
        res = tool_analyze(_hexs_to_bytes(data["pos"]), neg=neg or None, subset=subset or None,
                           theta=data.get("theta", 0.9), min_samples=data.get("min_samples", 20),
                           mode=data.get("mode", "all"), tau_other=data.get("tau_other", 0.02),
                           min_len=data.get("min_len", 8), max_len=data.get("max_len", 64),
                           top_n=data.get("top_n", 4))
    elif args.cmd == "rag":
        res = tool_rag(None, data["cluster"], data["task"])
    elif args.cmd == "run_code":
        neg = {k: _hexs_to_bytes(v) for k, v in (data.get("neg") or {}).items()}
        res = tool_run_code(data["code"], _hexs_to_bytes(data["pos"]), neg)
    elif args.cmd == "validate":
        neg = {k: _hexs_to_bytes(v) for k, v in (data.get("neg") or {}).items()}
        res = tool_validate(data["rule"], _hexs_to_bytes(data["held"]), neg,
                            data.get("tau_own", 0.95), data.get("tau_other", 0.02),
                            allow_version_locked=data.get("allow_version_locked", False),
                            min_recall=data.get("min_recall"),
                            held_distinct=_hexs_to_bytes(data.get("held_distinct")),
                            min_identity_coverage=data.get("min_identity_coverage"))
    elif args.cmd == "echo_check":
        res = tool_echo_check(data.get("code", ""),
                              _hexs_to_bytes(data.get("packets")),
                              data.get("justification"),
                              data.get("observations"),
                              data.get("allowed_evidence_ids"))
    elif args.cmd == "select_cover":
        neg = {k: _hexs_to_bytes(v) for k, v in (data.get("neg") or {}).items()}
        res = tool_select_cover(data["findings"], data["service"],
                                _hexs_to_bytes(data["held"]), neg,
                                data.get("tau_own", 0.7), data.get("tau_other", 0.02),
                                member=data.get("member"),
                                allow_version_locked=data.get("allow_version_locked", False))
    elif args.cmd == "submit_rules":
        neg = {k: _hexs_to_bytes(v) for k, v in (data.get("neg") or {}).items()}
        res = tool_submit_rules(data["rules"], data["service"],
                                _hexs_to_bytes(data["held"]), neg,
                                data.get("tau_own", 0.7), data.get("tau_other", 0.02),
                                member=data.get("member"),
                                allow_version_locked=data.get("allow_version_locked", False),
                                min_recall=data.get("min_recall"))
    else:  # declare_no_invariant
        res = tool_declare_no_invariant(data.get("reason", ""))

    _emit(res)

if __name__ == "__main__":
    _cli()
