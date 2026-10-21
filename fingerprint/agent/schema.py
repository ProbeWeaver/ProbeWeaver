"""Typed byte-invariant findings exchanged between analysis and rule construction."""

from dataclasses import dataclass, field
from typing import List

@dataclass
class Finding:
    """One byte-level invariant observation."""
    kind: str            # "prefix" | "offset" | "mask"
    offset: int
    value_hex: str       
    mask_hex: str = ""   

@dataclass
class Findings:
    findings: List[Finding] = field(default_factory=list)
    rationale: str = ""

    def __bool__(self) -> bool:           # noqa: D401
        return bool(self.findings)

def finding_to_dict(f: Finding) -> dict:
    return {"kind": f.kind, "offset": f.offset, "value_hex": f.value_hex, "mask_hex": f.mask_hex}

def findings_to_dict(fs: Findings) -> dict:
    return {"findings": [finding_to_dict(f) for f in fs.findings], "rationale": fs.rationale}

def dict_to_findings(d: dict) -> Findings:
    """Restore typed findings from the JSON analysis contract."""
    if isinstance(d, Findings):
        return d
    fnds: List[Finding] = []
    for f in (d or {}).get("findings", []):
        try:
            fnds.append(Finding(
                kind=f["kind"],
                offset=int(f["offset"]),
                value_hex=f["value_hex"],
                mask_hex=f.get("mask_hex", "") or "",
            ))
        except (KeyError, ValueError, TypeError):
            continue
    return Findings(fnds, rationale=(d or {}).get("rationale", "") or "")
