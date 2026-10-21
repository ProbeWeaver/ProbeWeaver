"""Reject request-derived constants unless response-side evidence independently supports them. Track directly reflected bytes and probe-derived response regions; compare against all current construction packets."""

import re
from dataclasses import dataclass
from typing import Iterable, List, Mapping, Optional, Sequence, Set, Tuple

ECHO_GUARD_SCHEMA_VERSION = 1

DEFAULT_MIN_CONSTANT_BYTES = 4

@dataclass(frozen=True)
class EchoFlag:
    """A rule constant requiring response-side provenance."""
    constant_hex: str          
    origin: str                # string | raw_string | byte_slice
    offset: int                
    overlap_hex: str = ""      

_INTERPRETED_STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_RAW_STRING = re.compile(r"`([^`]*)`")
# Scan comments, strings and rune literals together so quotes inside a rune
# or raw string do not create imaginary interpreted-string constants.
_GO_LEXEMES = re.compile(
    r'//[^\n]*|/\*.*?\*/|"(?:[^"\\\n]|\\.)*"|`[^`]*`|\x27(?:[^\x27\\\n]|\\.)*\x27',
    re.DOTALL)

_BYTE_SLICE = re.compile(
    r"\[\]byte\s*\{((?:\s*0[xX][0-9a-fA-F]{1,2}\s*,?\s*)+)\}")
_BYTE_VALUE = re.compile(r"0[xX][0-9a-fA-F]{1,2}")

_SIMPLE_ESCAPES = {
    "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
    "v": "\v", "\\": "\\", "'": "'", '"': '"',
}

def _decode_go_string(literal: str) -> bytes:
    """Decode Go byte, octal and Unicode escapes; preserve unknown escapes conservatively."""
    out = bytearray()
    i = 0
    while i < len(literal):
        ch = literal[i]
        if ch != "\\" or i + 1 >= len(literal):
            out.extend(ch.encode("utf-8"))
            i += 1
            continue
        nxt = literal[i + 1]
        if nxt == "x":
            hexpart = literal[i + 2:i + 4]
            if len(hexpart) == 2:
                try:
                    out.append(int(hexpart, 16))
                    i += 4
                    continue
                except ValueError:
                    pass
        if nxt in "01234567":
            octpart = literal[i + 1:i + 4]
            try:
                out.append(int(octpart, 8) & 0xFF)
                i += 1 + len(octpart)
                continue
            except ValueError:
                pass
        if nxt in "uU":
            width = 4 if nxt == "u" else 8
            hexpart = literal[i + 2:i + 2 + width]
            if len(hexpart) == width:
                try:
                    out.extend(chr(int(hexpart, 16)).encode("utf-8"))
                    i += 2 + width
                    continue
                except ValueError:
                    pass
        if nxt in _SIMPLE_ESCAPES:
            out.extend(_SIMPLE_ESCAPES[nxt].encode("utf-8"))
            i += 2
            continue
        
        out.extend(("\\" + nxt).encode("utf-8"))
        i += 2
    return bytes(out)

def extract_go_constants(body: str,
                         min_bytes: int = DEFAULT_MIN_CONSTANT_BYTES
                         ) -> List[EchoFlag]:
    """Extract sufficiently long byte/string constants from a Go function body."""
    flags: List[EchoFlag] = []
    seen = set()
    code_only = list(body)
    for match in _GO_LEXEMES.finditer(body):
        token = match.group(0)
        code_only[match.start():match.end()] = ' ' * len(token)
        if token.startswith('"'):
            decoded, origin = _decode_go_string(token[1:-1]), 'string'
        elif token.startswith('`'):
            decoded, origin = token[1:-1].encode('utf-8'), 'raw_string'
        else:
            continue
        if len(decoded) >= min_bytes:
            key = (decoded.hex(), origin)
            if key not in seen:
                seen.add(key)
                flags.append(EchoFlag(decoded.hex(), origin, match.start()))
    for match in _BYTE_SLICE.finditer(''.join(code_only)):
        values = _BYTE_VALUE.findall(match.group(1))
        blob = bytes(int(v, 16) for v in values)
        if len(blob) >= min_bytes:
            key = (blob.hex(), "byte_slice")
            if key not in seen:
                seen.add(key)
                flags.append(EchoFlag(blob.hex(), "byte_slice", match.start()))
    return flags

def _longest_common_substring(left: bytes, right: bytes,
                              minimum: int) -> bytes:
    """Return the longest contiguous common bytes, breaking ties lexicographically."""
    if minimum <= 0 or len(left) < minimum or len(right) < minimum:
        return b""
    best = b""

    for width in range(min(len(left), len(right)), minimum - 1, -1):
        hits = {left[i:i + width] for i in range(len(left) - width + 1)
                if left[i:i + width] in right}
        if hits:
            return min(hits)
    return best

def _observation_pair(value: Mapping) -> Optional[Tuple[bytes, bytes]]:
    packet = value.get("packet")
    response = value.get("response")
    if isinstance(packet, str):
        try:
            packet = bytes.fromhex(packet)
        except ValueError:
            return None
    if isinstance(response, str):
        try:
            response = bytes.fromhex(response)
        except ValueError:
            return None
    if not isinstance(packet, bytes) or not isinstance(response, bytes):
        return None
    return packet, response

def flag_echo_constants(body: str, packets: Iterable[bytes],
                        min_bytes: int = DEFAULT_MIN_CONSTANT_BYTES,
                        observations: Iterable[Mapping] = (),
                        taint_overlap_bytes: int = 2) -> List[EchoFlag]:
    """Find constants copied from probes or probe-derived response regions."""
    packet_blobs = [p for p in packets if p]
    tainted_response_spans: Set[bytes] = set()
    for raw in observations or ():
        if not isinstance(raw, Mapping):
            continue
        pair = _observation_pair(raw)
        if pair is None:
            continue
        packet, response = pair
        overlap = _longest_common_substring(packet, response, min_bytes)
        if overlap:
            tainted_response_spans.add(overlap)
    flagged: List[EchoFlag] = []
    for flag in extract_go_constants(body, min_bytes=min_bytes):
        constant = bytes.fromhex(flag.constant_hex)
        overlap = b""
        for packet in packet_blobs:
            candidate = _longest_common_substring(constant, packet, min_bytes)
            if len(candidate) > len(overlap) or (
                    len(candidate) == len(overlap) and candidate < overlap):
                overlap = candidate
        for tainted in tainted_response_spans:
            candidate = _longest_common_substring(
                constant, tainted, taint_overlap_bytes)
            if len(candidate) > len(overlap) or (
                    len(candidate) == len(overlap) and candidate < overlap):
                overlap = candidate
        if overlap:
            flagged.append(EchoFlag(
                flag.constant_hex, flag.origin, flag.offset, overlap.hex()))
    return flagged

def check_echo_guard(body: str, packets: Iterable[bytes],
                     justification: Sequence[Mapping] = (),
                     min_bytes: int = DEFAULT_MIN_CONSTANT_BYTES,
                     observations: Iterable[Mapping] = (),
                     allowed_evidence_ids: Optional[Iterable[str]] = None) -> dict:
    """Evaluate all flagged constants against independent response evidence."""
    packet_list = [p for p in packets if p]
    flagged = flag_echo_constants(
        body, packet_list, min_bytes=min_bytes, observations=observations)
    allowed = (None if allowed_evidence_ids is None else
               {str(value) for value in allowed_evidence_ids if str(value)})
    covered = set()
    unmatched: List[str] = []
    for entry in justification or ():
        if not isinstance(entry, Mapping):
            continue
        constant_hex = str(entry.get("constant_hex", "") or "").strip().lower()
        basis = str(entry.get("basis", "") or "").strip()
        if not constant_hex or not basis:
            continue
        evidence_ids = entry.get("evidence_ids") or []
        if allowed is not None:
            if (not isinstance(evidence_ids, list) or not evidence_ids
                    or any(str(evidence) not in allowed
                           for evidence in evidence_ids)):
                continue
        if constant_hex in {f.constant_hex for f in flagged}:
            covered.add(constant_hex)
        else:
            unmatched.append(constant_hex)
    uncovered = sorted({f.constant_hex for f in flagged} - covered)
    status = "fail" if uncovered else "pass"
    reason = (
        "echo guard: constants keyed on construction probe bytes without "
        "justification: " + ", ".join(uncovered)
        if status == "fail" else "ok")
    return {
        "schema_version": ECHO_GUARD_SCHEMA_VERSION,
        "status": status,
        "flagged": sorted({f.constant_hex for f in flagged}),
        "overlaps": {f.constant_hex: f.overlap_hex for f in flagged},
        "justified": sorted(covered),
        "uncovered": uncovered,
        "unmatched_justifications": unmatched,
        "reason": reason,
    }

def packet_hexes_to_bytes(packet_hexes: Iterable[str]) -> List[bytes]:
    """Decode packet hex strings, skipping malformed entries."""
    out: List[bytes] = []
    for hx in packet_hexes:
        try:
            blob = bytes.fromhex(str(hx))
        except ValueError:
            continue
        if blob:
            out.append(blob)
    return out
