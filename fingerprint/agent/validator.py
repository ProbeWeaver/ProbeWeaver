"""Rule validation gates: syntax, invariance, recall and cross-service false-match rate. Python mirrors the four-form matcher; generated Go function bodies use the separate Go harness. A version-specific literal is not a general service invariant."""

import re
from typing import Dict, List, Tuple

from ..nmap_import import looks_version_locked, _UNSUPPORTED_PATTERNS

_RE_CACHE: Dict[str, "re.Pattern[bytes]"] = {}

def _compile_pat(pat: str) -> "re.Pattern[bytes]":
    """Compile byte-oriented regex patterns for response matching."""
    cre = _RE_CACHE.get(pat)
    if cre is None:
        cre = re.compile(pat.encode("latin-1"))
        _RE_CACHE[pat] = cre
    return cre

def apply_rule(rule: dict, resp: bytes) -> bool:
    """Mirror the Go four-form pattern, offset-magic and mask matching semantics."""
    if not resp:
        return False

    pat = rule.get("pattern")
    if pat:
        try:
            if _compile_pat(pat).search(resp):
                return True
        except re.error:
            pass

    mh = rule.get("mask_hex")
    if mh:
        off = rule.get("offset", 0) or 0
        try:
            mask = bytes.fromhex(mh)
            val = bytes.fromhex(rule["mask_value_hex"])
        except (ValueError, KeyError):
            mask = b""
        if mask and off >= 0 and off + len(mask) <= len(resp):
            if all((resp[off + i] & mask[i]) == val[i] for i in range(len(mask))):
                return True

    mx = rule.get("magic_hex")
    if mx:
        off = rule.get("offset", 0) or 0
        try:
            magic = bytes.fromhex(mx)
        except ValueError:
            magic = b""
        if magic and off >= 0 and off + len(magic) <= len(resp) \
                and resp[off:off + len(magic)] == magic:
            return True

    return False

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def compile_check(rule: dict) -> Tuple[bool, str]:
    """Check regex support, hex validity, offsets and mask widths."""
    pat = rule.get("pattern")
    if pat:
        for rx, name in _UNSUPPORTED_PATTERNS:
            if re.search(rx, pat):
                return False, f"unsupported RE2 construct {name}"
        try:
            _compile_pat(pat)
        except re.error as e:
            return False, f"pattern compilation failed: {e}"

    mx = rule.get("magic_hex")
    if mx:
        try:
            bytes.fromhex(mx)
        except ValueError:
            return False, f"invalid magic_hex: {mx}"

    off = rule.get("offset", 0) or 0
    if not isinstance(off, int) or off < 0:
        return False, f"invalid offset: {off}"

    mh = rule.get("mask_hex")
    if mh:
        if not rule.get("mask_value_hex"):
            return False, "mask_hex requires mask_value_hex"
        try:
            m = bytes.fromhex(mh)
            v = bytes.fromhex(rule["mask_value_hex"])
        except ValueError:
            return False, "invalid mask hex"
        if len(m) != len(v):
            return False, f"mask length mismatch: {len(m)} vs {len(v)}"

    if not (pat or mx or mh):
        return False, "no pattern, magic or mask matcher"
    return True, "ok"

def invariance_check(rule: dict, allow_version_locked: bool = False) -> Tuple[bool, str]:
    """Reject version literals at the service tier."""
    if allow_version_locked:
        return True, "ok"
    pat = rule.get("pattern")
    if pat and looks_version_locked(pat):
        return False, "contains a version-dependent literal"
    return True, "ok"

def recall_check(rule: dict, held_out: List[bytes], tau_own: float) -> Tuple[bool, str, float]:
    """Require the supplied positive-set hit rate to reach its threshold."""
    if not held_out:
        return False, "no validation samples", 0.0
    hits = sum(1 for r in held_out if apply_rule(rule, r))
    recall = hits / len(held_out)
    if recall < tau_own:
        return False, f"recall {recall:.2f} < τ_own {tau_own}", recall
    return True, "ok", recall

def precision_check(rule: dict, negatives: Dict[str, List[bytes]],
                    tau_other: float) -> Tuple[bool, str]:
    """Reject a rule exceeding the false-match cap in any negative service."""
    for c, resps in negatives.items():
        if not resps:
            continue
        fp = sum(1 for r in resps if apply_rule(rule, r))
        rate = fp / len(resps)
        if rate > tau_other:
            return False, f"false matches in service '{c}' rate {rate:.2f} > τ_other {tau_other}"
    return True, "ok"

def validate(rule: dict, held_out: List[bytes], negatives: Dict[str, List[bytes]],
             tau_own: float, tau_other: float,
             allow_version_locked: bool = False,
             min_recall: float = None) -> Tuple[bool, str]:
    """Run syntax, invariance, recall and precision gates in order."""
    ok, reason = compile_check(rule)
    if not ok:
        return False, reason
    ok, reason = invariance_check(rule, allow_version_locked=allow_version_locked)
    if not ok:
        return False, reason
    recall_thresh = tau_own if min_recall is None else min_recall
    ok, reason, _ = recall_check(rule, held_out, recall_thresh)
    if not ok:
        return False, reason
    ok, reason = precision_check(rule, negatives, tau_other)
    if not ok:
        return False, reason
    return True, "ok"

def select_covered_rules(findings, service: str, source: str, held_out: List[bytes],
                         negatives: Dict[str, List[bytes]], tau_own: float,
                         tau_other: float, member: str = None,
                         allow_version_locked: bool = False,
                         full_coverage: bool = False) -> Tuple[List[dict], str]:
    """Select rules passing individual precision gates and union coverage requirements."""
    from .analyzer import build_rule  

    candidates = []          
    first_reject = ""
    for fnd in findings.findings:
        rule = build_rule(fnd, service, source, member=member,
                          allow_version_locked=allow_version_locked)
        if not rule:
            continue
        ok, reason = compile_check(rule)
        if not ok:
            first_reject = first_reject or reason
            continue
        ok, reason = invariance_check(rule, allow_version_locked=allow_version_locked)
        if not ok:
            first_reject = first_reject or reason
            continue
        ok, reason = precision_check(rule, negatives, tau_other)
        if not ok:
            first_reject = first_reject or reason
            continue
        cov = frozenset(i for i, r in enumerate(held_out) if apply_rule(rule, r))
        if cov:
            candidates.append((rule, cov))

    if not candidates:
        return [], (first_reject or "no precision-clean candidates")
    if not held_out:
        
        return [r for r, _ in candidates], ""

    target = len(held_out) if full_coverage else tau_own * len(held_out)
    covered: set = set()
    selected: List[dict] = []
    pool = list(candidates)
    while pool and len(covered) < target:
        best_idx, best_gain = -1, 0
        for idx, (_rule, cov) in enumerate(pool):
            gain = len(cov - covered)
            if gain > best_gain:
                best_gain, best_idx = gain, idx
        if best_idx < 0 or best_gain == 0:
            break
        selected.append(pool[best_idx][0])
        covered |= pool[best_idx][1]
        pool.pop(best_idx)

    union = len(covered) / len(held_out)
    if full_coverage:
        
        if selected:
            return selected, ""
        return [], (first_reject or "no precision-clean candidates")
    if union >= tau_own:
        return selected, ""
    return [], (f"union recall {union:.2f} < τ_own {tau_own}"
                + (f"（{first_reject}）" if first_reject else ""))
