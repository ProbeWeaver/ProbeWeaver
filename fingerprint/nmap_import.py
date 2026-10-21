"""Import supported generic response signatures into the Go rule engine. Translate compatible regex syntax to RE2, reject unsupported high-byte/rune assumptions and version-locked service rules, then deduplicate and rank signatures."""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
NMAP_SERVICE_TO_CLUSTER: Dict[str, str] = {
    "ssh": "ssh",
    "telnet": "telnet",
    "ftp": "ftp",
    "smtp": "smtp",
    "pop3": "pop3",
    "imap": "imapv4",
    "irc": "irc",
    "http": "http",
    "rtsp": "rtsp",
    "redis": "redis",
    "amqp": "amqp",
    "memcached": "memcached",
    "memcache": "memcached",
    "microsoft-ds": "smb",
    "ms-wbt-server": "rdp",
    "bittorrent": "bittorrentv10",
    "mongodb": "mongodb",
    "ldap": "ldap",
    "socks5": "socks5",
    "sip": "sip",

}

_UNSUPPORTED_PATTERNS = [
    (r"\(\?[<=!]", "lookahead/lookbehind"),   
    (r"\\[1-9]", "backreference"),
    (r"[*+?]\+", "possessive quantifier"),     # *+ / ++ / ?+
    (r"\}\+", "possessive quantifier"),        # {n,m}+
]

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

#

HAND_RULES: List[dict] = [
    {"service": "ssh",           "type": "banner", "pattern": r"^SSH-"},
    {"service": "smb",           "type": "magic",  "magic_hex": "ff534d42"},   # \xffSMB
    {"service": "smb",           "type": "magic",  "magic_hex": "fe534d42"},   # \xfeSMB (SMB2)
    {"service": "telnet",        "type": "magic",  "magic_hex": "ff"},          
    {"service": "ftp",           "type": "banner", "pattern": r"(?i)^220[ -][^\r\n]*ftp"},
    {"service": "smtp",          "type": "banner", "pattern": r"(?i)^220[ -][^\r\n]*(?:e?smtp|mail)"},
    {"service": "pop3",          "type": "banner", "pattern": r"^\+OK"},
    {"service": "imapv4",        "type": "banner", "pattern": r"^\* OK"},
    {"service": "irc",           "type": "banner", "pattern": r"^(?::[A-Za-z0-9._-]+ \d{3} |NOTICE AUTH )"},
    {"service": "http",          "type": "banner", "pattern": r"^HTTP/[0-9]\.[0-9] [0-9]{3}"},
    {"service": "rtsp",          "type": "banner", "pattern": r"^RTSP/[0-9]\.[0-9] [0-9]{3}"},
    {"service": "redis",         "type": "banner", "pattern": r"^-(?:ERR|NOAUTH|BUSY|WRONGPASS|LOADING|MOVED|ASK|CLUSTERDOWN|NOREPLICAS) "},
    {"service": "amqp",          "type": "magic",  "pattern": r"^AMQP\x00"},
    {"service": "memcached",     "type": "banner", "pattern": r"^(?:ERROR\r\n|STAT |CLIENT_ERROR|SERVER_ERROR)"},
    {"service": "bittorrentv10", "type": "magic",  "pattern": r"^\x13BitTorrent protocol"},
]

# hand_code_rules.py → scripts/deploy_code_rules.py → PW_Scanner/lib/fingerprint/code_rules.go

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def _find_closing_delim(s: str, start: int, delim: str) -> int:
    """Find the next unescaped pattern delimiter."""
    i = start
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 2  
            continue
        if c == delim:
            return i
        i += 1
    raise ValueError(f"missing closing delimiter {delim!r}: {s!r}")

def translate_body(body: str, opts: str) -> str:
    """Translate a compatible regex body and flags to Go RE2."""
    flags = "".join(c for c in "is" if c in opts)  
    prefix = f"(?{flags})" if flags else ""
    for pat, _name in _UNSUPPORTED_PATTERNS:
        if re.search(pat, body):
            raise ValueError(f"unsupported RE2 construct {pat!r}: body={body!r}")
    
    return prefix + body.replace("(?>", "(?:")

def translate_pattern(token: str) -> Tuple[str, str]:
    """Parse and translate an Nmap match token to a Go-compatible pattern."""
    token = token.strip()
    if not token.startswith("m") or len(token) < 3:
        raise ValueError(f"invalid match pattern: {token!r}")
    delim = token[1]
    close = _find_closing_delim(token, 2, delim)
    body = token[2:close]
    opts = re.match(r"[is]*", token[close + 1:]).group(0)  
    return translate_body(body, opts), opts

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def _strip_for_invariant(body: str) -> str:
    """Remove escapes and character classes before version-literal analysis."""
    out = []
    i, n = 0, len(body)
    in_cls = False
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            nxt = body[i + 1]
            if nxt == "x" and i + 3 < n:  
                i += 4
                continue
            i += 2  
            continue
        if c == "[":
            in_cls = True
            i += 1
            continue
        if c == "]":
            in_cls = False
            i += 1
            continue
        if in_cls:
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)

def looks_version_locked(body: str) -> bool:
    """Detect version-dependent literals unsuitable for service-level invariants."""
    cleaned = _strip_for_invariant(body)
    if re.search(r"\d+[._]\d+", cleaned):  
        return True
    if re.search(r"[A-Za-z][A-Za-z0-9_]{19,}", cleaned):  
        return True
    return False

def has_high_byte_literal(body: str) -> bool:
    """Reject raw byte literals above 0x7f for Go's UTF-8 rune regex engine; use byte matchers instead."""
    for h in re.findall(r"\\x([0-9a-fA-F]{2})", body):
        if int(h, 16) >= 0x80:
            return True
    return False

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

class Directive:
    __slots__ = ("kind", "service", "body", "opts", "probe")

    def __init__(self, kind: str, service: str, body: str, opts: str, probe: str):
        self.kind = kind        # 'match' | 'softmatch'
        self.service = service  # nmap service name
        self.body = body        
        self.opts = opts
        self.probe = probe      

def parse_probes(path: Path) -> List[Directive]:
    """Parse match and softmatch directives in encounter order."""
    directives: List[Directive] = []
    cur_probe = "?"
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        
        if line.startswith("Probe "):
            parts = line.split(None, 3)
            cur_probe = parts[2] if len(parts) > 2 else "?"
            continue
        kind = None
        if line.startswith("match "):
            kind = "match"
        elif line.startswith("softmatch "):
            kind = "softmatch"
        else:
            continue  
        rest = line[len(kind):].strip()
        try:
            service, patpart = rest.split(None, 1)
        except ValueError:
            continue
        
        if not patpart.startswith("m") or len(patpart) < 3:
            continue
        delim = patpart[1]
        try:
            close = _find_closing_delim(patpart, 2, delim)
        except ValueError:
            continue
        body = patpart[2:close]
        opts = re.match(r"[is]*", patpart[close + 1:]).group(0)
        directives.append(Directive(kind, service, body, opts, cur_probe))
    return directives

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def _rule_type(go_pattern: str) -> str:
    core = re.sub(r"^\(\?[is]*\)", "", go_pattern)
    body = core[1:] if core.startswith("^") else core
    
    if body.startswith("\\x") or body.startswith("\\0"):
        return "magic"
    return "banner"

def build_rules(
    directives: List[Directive],
    max_per_cluster: int,
    verbose: bool = False,
) -> Tuple[List[dict], Dict[str, int]]:
    """Filter, translate, deduplicate and rank generic signatures."""
    
    per_cluster: Dict[str, dict] = defaultdict(dict)
    stats = defaultdict(int)
    stats["_total_directives"] = len(directives)

    for d in directives:
        cluster = NMAP_SERVICE_TO_CLUSTER.get(d.service)
        if cluster is None:
            stats["unmapped_service"] += 1
            continue
        try:
            go_pattern = translate_body(d.body, d.opts)
        except ValueError as e:
            stats["unsupported_re2"] += 1
            if verbose:
                print(f"  [skip unsupported] {d.service}: {e}", file=sys.stderr)
            continue
        
        core = re.sub(r"^\(\?[is]*\)", "", go_pattern)
        if not core.startswith("^"):
            stats["not_anchored"] += 1
            continue
        if looks_version_locked(d.body):
            stats["version_locked"] += 1
            continue
        if has_high_byte_literal(d.body):
            
            stats["high_byte_skipped"] += 1
            continue
        per_cluster[cluster][go_pattern] = d.kind
        stats["kept_before_cap"] += 1

    rules: List[dict] = []
    for cluster, pats in per_cluster.items():
        
        ordered = sorted(
            pats.items(),
            key=lambda kv: (0 if kv[1] == "softmatch" else 1, len(kv[0]), kv[0]),
        )
        for go_pattern, _kind in ordered[:max_per_cluster]:
            rules.append({
                "service": cluster,
                "pattern": go_pattern,
                "type": _rule_type(go_pattern),
                "source": "nmap",
            })
        stats[f"cluster:{cluster}"] = min(len(ordered), max_per_cluster)

    rules.sort(key=lambda r: (r["service"], len(r["pattern"]), r["pattern"]))
    return rules, dict(stats)

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def merge_with_existing(new_rules: List[dict], out_path: Path) -> List[dict]:
    """Preserve existing hand/generated rules while replacing imported signatures."""
    kept: List[dict] = []
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text(encoding="utf-8"))
            for r in existing:
                if r.get("source") in ("hand", "llm", "deterministic", "code"):
                    kept.append(r)
        except (json.JSONDecodeError, ValueError):
            pass
    seen = {(r.get("service"), r.get("pattern"), r.get("magic_hex"), r.get("code"))
            for r in kept}
    for r in new_rules:
        key = (r.get("service"), r.get("pattern"), r.get("magic_hex"), r.get("code"))
        if key not in seen:
            kept.append(r)
            seen.add(key)
    return kept

def merge_member_rules(new_rules: List[dict], out_path: Path) -> List[dict]:
    """Merge implementation rules while preserving explicit generated entries."""
    kept: List[dict] = []
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text(encoding="utf-8"))
            for r in existing:
                if r.get("source") in ("member_hand", "member_llm",
                                       "member_deterministic", "member_code"):
                    kept.append(r)
        except (json.JSONDecodeError, ValueError):
            pass
    seen = {(r.get("service"), r.get("member"),
             r.get("pattern"), r.get("magic_hex"), r.get("code")) for r in kept}
    for r in new_rules:
        r.setdefault("source", "member_llm")
        key = (r.get("service"), r.get("member"),
               r.get("pattern"), r.get("magic_hex"), r.get("code"))
        if key not in seen:
            kept.append(r)
            seen.add(key)
    return kept

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Parse generic response signatures and export compatible rules.json entries.")
    ap.add_argument("--probes", default="nmap/nmap-service-probe.txt",
                    help="Path to the generic probe-signature source")
    ap.add_argument("--out", "-o", default="PW_Scanner/rules.json",
                    help="Output rules.json (default: PW_Scanner/rules.json)")
    ap.add_argument("--max-per-cluster", type=int, default=5,
                    help="Maximum signatures per service after ranking (default: 5)")
    ap.add_argument("--no-merge", action="store_true",
                    help="Overwrite the output rather than retaining existing hand/generated rules")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    probes_path = Path(args.probes)
    if not probes_path.exists():
        print(f"[error] probes file missing: {probes_path}", file=sys.stderr)
        return 1
    out_path = Path(args.out)

    directives = parse_probes(probes_path)
    rules, stats = build_rules(directives, args.max_per_cluster, verbose=args.verbose)
    hand = [dict(r, source="hand") for r in HAND_RULES]
    
    new_rules = hand + rules
    final = new_rules if args.no_merge else merge_with_existing(new_rules, out_path)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(final, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    nmap_clusters = sorted({r["service"] for r in final if r.get("source") == "nmap"})
    hand_clusters = sorted({r["service"] for r in final if r.get("source") == "hand"})
    print(f"parsed {stats.get('_total_directives', 0)} match/softmatch directives")
    for k in ("unmapped_service", "unsupported_re2", "not_anchored",
              "version_locked", "high_byte_skipped", "kept_before_cap"):
        print(f"  {k}: {stats.get(k, 0)}")
    print(f"exported {len(rules)} generic signatures ({len(nmap_clusters)} services) + {len(hand)} hand-written generic signatures ({len(hand_clusters)} services)")
    print(f"Final rules.json: {len(final)} entries -> {out_path}")
    if args.verbose:
        for r in final:
            print(f"  [{r.get('source','?'):4}] {r['service']:14} {r.get('type','?'):6} {r['pattern']}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
