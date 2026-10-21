"""Deterministic byte-invariant and discriminating-substring analysis, restricted analysis subprocesses and rule construction. Candidate constants must be measured against positive and negative data rather than transcribed from a preview."""

import ast
import json
import re
import struct
import traceback
from typing import List, Optional, Tuple

from .schema import Finding, Findings, findings_to_dict
from ..nmap_import import has_high_byte_literal, looks_version_locked, _rule_type

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def _const_byte_at(rs: List[bytes], i: int, theta: float) -> Optional[int]:
    """Return a byte value when its observed frequency reaches theta."""
    counts = {}
    for r in rs:
        if i < len(r):
            counts[r[i]] = counts.get(r[i], 0) + 1
    if not counts:
        return None
    b, c = max(counts.items(), key=lambda kv: kv[1])
    return b if c / len(rs) >= theta else None

def _longest_const_run(rs: List[bytes], start: int, theta: float,
                       max_len: int = 8) -> List[int]:
    """Find the bounded constant byte run beginning at an offset."""
    n = min(len(r) for r in rs)
    run: List[int] = []
    for i in range(start, min(start + max_len, n)):
        b = _const_byte_at(rs, i, theta)
        if b is None:
            break
        run.append(b)
    return run

def _bitmask_at(rs: List[bytes], off: int, theta: float, min_stable: int = 3) -> Optional[Finding]:
    """Find bits whose set frequency is at least theta or at most 1-theta."""
    mask = 0
    value = 0
    stable = 0
    for bit in range(8):
        setcount = sum(1 for r in rs if off < len(r) and (r[off] >> bit) & 1)
        frac = setcount / len(rs)
        if frac >= theta:                 
            mask |= (1 << bit)
            value |= (1 << bit)
            stable += 1
        elif frac <= 1 - theta:           
            mask |= (1 << bit)
            stable += 1
    if stable < min_stable:
        return None
    ok = sum(1 for r in rs if off < len(r) and (r[off] & mask) == value) / len(rs)
    if ok < theta:
        return None
    return Finding("mask", off, bytes([value]).hex(), bytes([mask]).hex())

def deterministic_analyzer(responses: List[bytes], theta: float = 0.9,
                           min_samples: int = 20) -> Findings:
    """Extract stable prefixes, offset magic and bit masks from responses."""
    rs = [r for r in responses if r]
    if len(rs) < min_samples:
        return Findings([], rationale=f"only {len(rs)} samples (< {min_samples}）")
    n = min(len(r) for r in rs)
    if n == 0:
        return Findings([], rationale="all responses are empty")

    found: List[Finding] = []

    prefix = _longest_const_run(rs, 0, theta, max_len=16)
    if len(prefix) >= 1:
        found.append(Finding("prefix", 0, bytes(prefix).hex()))

    for start in range(1, min(8, n)):
        run = _longest_const_run(rs, start, theta, max_len=8)
        if len(run) >= 2:
            found.append(Finding("offset", start, bytes(run).hex()))

    for off in range(min(4, n)):
        f = _bitmask_at(rs, off, theta)
        if f is not None:
            found.append(f)

    _KIND_PRIO = {"prefix": 0, "offset": 1, "mask": 2, "substring": 3}
    found.sort(key=lambda f: (-len(bytes.fromhex(f.value_hex)), _KIND_PRIO.get(f.kind, 9)))

    rationale = "; ".join(
        f"{f.kind}@{f.offset}={f.value_hex}" + (f"/mask={f.mask_hex}" if f.mask_hex else "")
        for f in found[:4]
    ) or "no constant invariant"
    return Findings(found, rationale=rationale)

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

_REGEX_META_BYTES = set(b".^$*+?()[]{}|\\")

def _literal_byte_count(seed: bytes) -> int:
    """Count literal bytes after excluding regex metacharacters."""
    return sum(1 for b in seed if b not in _REGEX_META_BYTES)

def discriminating_substrings(pos, neg, theta: float = 0.9, tau_other: float = 0.02,
                              min_len: int = 8, max_len: int = 64, top_n: int = 4,
                              min_literal: int = 4) -> List[Finding]:
    """Find substrings frequent in positives and absent from cross-service negatives."""
    if not pos:
        return []
    pos_dedup: Dict[bytes, int] = {}
    for r in pos:
        if r:
            pos_dedup[r] = pos_dedup.get(r, 0) + 1
    n_pos = sum(pos_dedup.values())
    if n_pos == 0:
        return []

    neg_seed_sets: Dict[str, set] = {}
    for cluster, resps in (neg or {}).items():
        s = set()
        for r in resps:
            if not r:
                continue
            for i in range(max(0, len(r) - min_len + 1)):
                s.add(r[i:i + min_len])
        neg_seed_sets[cluster] = s

    seed_weights: Dict[bytes, int] = {}
    for shape, w in pos_dedup.items():
        seen = set()
        for i in range(max(0, len(shape) - min_len + 1)):
            seed = shape[i:i + min_len]
            if seed in seen or _literal_byte_count(seed) < min_literal:
                continue
            if all(seed not in ns for ns in neg_seed_sets.values()):
                seen.add(seed)
                seed_weights[seed] = seed_weights.get(seed, 0) + w
    if not seed_weights:
        return []

    candidates = [(s, w) for s, w in seed_weights.items() if w / n_pos >= theta]
    if not candidates:
        return []

    pos_shapes = sorted(pos_dedup.keys(), key=lambda s: pos_dedup[s], reverse=True)
    results = []  # (lcp, len, weight, rep_offset)
    for seed, weight in candidates:
        extensions = []
        rep_offset = -1
        for shape in pos_shapes:
            idx = shape.find(seed)
            if idx < 0:
                continue
            if rep_offset < 0:
                rep_offset = idx
            local_max = min(max_len, len(shape) - idx)
            extensions.append(shape[idx:idx + local_max])
        if not extensions or rep_offset < 0:
            continue
        lcp = extensions[0]
        for ext in extensions[1:]:
            k = 0
            while k < len(lcp) and k < len(ext) and lcp[k] == ext[k]:
                k += 1
            lcp = lcp[:k]
            if len(lcp) <= min_len:
                break
        if len(lcp) >= min_len:
            results.append((lcp, len(lcp), weight / n_pos, rep_offset))

    results.sort(key=lambda x: (-x[1], -x[2]))
    picked, picked_ranges = [], []
    for lcp, length, weight, offset in results:
        lo, hi = offset, offset + length
        if any(not (hi <= r_lo or lo >= r_hi) for r_lo, r_hi in picked_ranges):
            continue  
        picked.append(lcp)
        picked_ranges.append((lo, hi))
        if len(picked) >= top_n:
            break
    return [Finding(kind="substring", offset=0, value_hex=b.hex()) for b in picked]

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

_REGEX_META = set(".^$*+?()[]{}|\\")

def _escape_bytes(val: bytes) -> str:
    """Escape bytes into safe Go regexp literals."""
    out = []
    for b in val:
        if 0x20 <= b < 0x7f and chr(b) not in _REGEX_META:
            out.append(chr(b))
        else:
            out.append("\\x%02x" % b)
    return "".join(out)

def build_rule(findings, service: str, source: str,
               member: Optional[str] = None, allow_version_locked: bool = False) -> Optional[dict]:
    """Construct a rule from the strongest finding, or return None."""
    if isinstance(findings, Finding):
        findings = Findings([findings])
    if not findings or not findings.findings:
        return None
    f = findings.findings[0]
    desc = (findings.rationale or f"{f.kind}@{f.offset}")[:200]

    rule: Optional[dict] = None
    if f.kind == "prefix":
        val = bytes.fromhex(f.value_hex)
        if any(b >= 0x80 for b in val):
            rule = {"service": service, "magic_hex": f.value_hex, "type": "magic",
                    "source": source, "desc": desc}
        else:
            pat = "^" + _escape_bytes(val)
            if not allow_version_locked and looks_version_locked(pat):
                return None
            rule = {"service": service, "pattern": pat, "type": _rule_type(pat),
                    "source": source, "desc": desc}
    elif f.kind == "offset":
        rule = {"service": service, "magic_hex": f.value_hex, "offset": f.offset,
                "type": "offset", "source": source, "desc": desc}
    elif f.kind == "mask":
        rule = {"service": service, "mask_hex": f.mask_hex, "mask_value_hex": f.value_hex,
                "offset": f.offset, "type": "mask", "source": source, "desc": desc}
    elif f.kind == "substring":
        val = bytes.fromhex(f.value_hex)

        pat = _escape_bytes(val)
        if not allow_version_locked and looks_version_locked(pat):
            return None
        rule = {"service": service, "pattern": pat, "type": "substring",
                "source": source, "desc": desc}

    if rule is not None and member is not None:
        rule["member"] = member
    return rule

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

_ALLOWED_NAMES = {
    "Finding", "Findings", "struct", "re",
    "len", "min", "max", "range", "enumerate", "zip", "sorted", "reversed",
    "iter", "next", "isinstance",
    "set", "frozenset", "bytes", "bytearray", "int", "float", "hex", "oct", "bin",
    "list", "tuple", "dict", "str", "abs", "sum", "any", "all", "bool", "ord", "chr",
    "divmod", "pow", "round", "map", "filter", "True", "False", "None",
}

_SAFE_BUILTINS = {
    "len": len, "min": min, "max": max, "range": range, "enumerate": enumerate,
    "zip": zip, "sorted": sorted, "reversed": reversed, "iter": iter, "next": next,
    "isinstance": isinstance,
    "set": set, "frozenset": frozenset, "bytes": bytes, "bytearray": bytearray,
    "int": int, "float": float, "hex": hex, "oct": oct, "bin": bin,
    "list": list, "tuple": tuple, "dict": dict, "str": str, "abs": abs, "sum": sum,
    "any": any, "all": all, "bool": bool, "ord": ord, "chr": chr,
    "divmod": divmod, "pow": pow, "round": round, "map": map, "filter": filter,
    "True": True, "False": False, "None": None,
}

_SANDBOX_GLOBALS = {
    "Finding": Finding,
    "Findings": Findings,
    "struct": struct,
    "re": re,
    "__builtins__": _SAFE_BUILTINS,
    "__name__": "__sandbox__",
}

def _ast_check(src: str) -> None:
    """Reject imports, unsafe attributes/calls and unsupported analysis syntax."""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise ValueError("imports are forbidden")

        if isinstance(node, ast.AsyncFunctionDef):
            raise ValueError(f"forbidden construct: {type(node).__name__}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise ValueError(f"forbidden attribute: .{node.attr}")
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                if f.id not in _ALLOWED_NAMES:
                    raise ValueError(f"forbidden call: {f.id}")
            elif not isinstance(f, ast.Attribute):
                raise ValueError(f"forbidden call syntax: {type(f).__name__}")
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) \
                and node.id.startswith("__"):
            raise ValueError(f"forbidden dunder name: {node.id}")

def _normalize_result(result) -> object:
    """Validate and convert analysis results to JSON-compatible objects."""
    if isinstance(result, Findings):
        return findings_to_dict(result)
    if result is None or isinstance(result, (bool, int, float, str)):
        return result
    if isinstance(result, (list, dict)):
        json.dumps(result)  
        return result
    raise TypeError(f"run() returned a non-serializable type {type(result).__name__}")

def _sandbox_worker(code: str, pos: List[bytes], neg: List[bytes], queue) -> None:
    """Execute admitted analysis in a subprocess and return a normalized result."""
    try:
        ns = dict(_SANDBOX_GLOBALS)
        exec(code, ns)                       
        fn = ns.get("run")
        if not callable(fn):
            queue.put((None, "run(pos, neg) is not defined"))
            return
        result = fn(list(pos), list(neg))
        result = _normalize_result(result)
        queue.put((result, ""))
    except Exception:
        queue.put((None, "exception: " + traceback.format_exc()[-1200:]))

def run_code(code: str, pos: List[bytes], neg: List[bytes],
             timeout: float = 10.0) -> Tuple[Optional[object], str]:
    """Run restricted analysis in a bounded subprocess; return result and error separately."""
    try:
        _ast_check(code)
    except ValueError as e:
        return None, f"AST rejected: {e}"
    except SyntaxError as e:
        return None, f"syntax error: {e}"

    import multiprocessing
    ctx = multiprocessing.get_context("fork")
    queue = ctx.Queue()
    proc = ctx.Process(target=_sandbox_worker, args=(code, list(pos), list(neg), queue))
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(2)
        return None, "timeout"
    try:
        result, err = queue.get(timeout=5)
    except Exception:
        return None, "no result (worker crashed)"
    return result, err
