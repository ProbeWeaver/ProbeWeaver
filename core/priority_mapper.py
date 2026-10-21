"""
Priority-based field analysis for mutation planning.

Assigns priority scores to fields based on field type, separates ordinary
mutation fields from dependency-managed ones, and provides candidate values.

Scoring rules (no LLM needed):
  SURVIVAL/TERMINATOR  → 5  (separator errors = parse failure)
  SURVIVAL/OTHER       → 4  (flags/offset, affect processing logic)
  STRUCTURE            → 3  (magic/version, must match to be accepted)
  PAYLOAD              → 2  (data content, last to consider)
  SURVIVAL/LENGTH      → learnable special arm; repaired unless selected
  SURVIVAL/CHECKSUM    → auto (always recalculated after mutation)
"""

import struct
import hashlib
import zlib
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict

from protocol.field import (
    FieldDefinition,
    FieldType,
    SurvivalType,
    PositionedField,
    UnifiedProtocolSpec,
)

logger = logging.getLogger(__name__)

# --- Priority scoring table ---
PRIORITY_SCORES = {
    (FieldType.SURVIVAL, SurvivalType.TERMINATOR): 5,
    (FieldType.SURVIVAL, SurvivalType.OTHER): 4,
    (FieldType.STRUCTURE, None): 3,
    (FieldType.PAYLOAD, None): 2,
}

@dataclass
class FieldPlan:
    """Mutation plan for a single field."""

    field: FieldDefinition
    positioned: PositionedField
    score: Optional[int]  # None = auto_calc (LENGTH/CHECKSUM)
    auto_calc: bool
    candidates: List[bytes]  # [seed_value] + expected_values (deduplicated)

@dataclass
class BlockInfo:
    """Resolved byte range for a named block."""

    name: str
    start_byte: int  # byte after BLOCK_BEGIN
    end_byte: int  # byte at BLOCK_END
    inclusive_length_fields: List[FieldPlan]  # LENGTH fields inside this block
    exclusive_length_fields: List[FieldPlan]  # LENGTH fields outside this block

def _score_field(field: FieldDefinition) -> Optional[int]:
    if field.field_type in (FieldType.BLOCK_BEGIN, FieldType.BLOCK_END):
        return None
    if field.field_type == FieldType.SURVIVAL and field.survival_type in (
        SurvivalType.LENGTH,
        SurvivalType.CHECKSUM,
    ):
        return None
    key = (
        field.field_type,
        field.survival_type if field.field_type == FieldType.SURVIVAL else None,
    )
    return PRIORITY_SCORES.get(key, 2)

def _get_candidates(field: FieldDefinition, seed_value: bytes) -> List[bytes]:
    """Return [seed_value] + expected_values, deduplicated."""
    candidates = [seed_value]
    for v in field.expected_values + field.negative_values:
        if v not in candidates:
            candidates.append(v)
    return candidates

class PriorityMapper:
    """Analyzes a protocol spec and seed packet, producing field mutation plans."""

    def analyze(self, spec: UnifiedProtocolSpec, seed_bytes: bytes) -> List[FieldPlan]:
        positioned_fields = spec.iter_positioned_fields()

        padded_seed = bytearray(seed_bytes)
        max_len = max((pf.end_byte for pf in positioned_fields), default=0)
        if len(padded_seed) < max_len:
            padded_seed.extend(b"\x00" * (max_len - len(padded_seed)))

        plans: List[FieldPlan] = []
        for positioned in positioned_fields:
            fd = positioned.field

            # Skip block markers
            if fd.field_type in (FieldType.BLOCK_BEGIN, FieldType.BLOCK_END):
                continue

            start = positioned.start_byte
            end = min(positioned.end_byte, len(padded_seed))
            seed_value = bytes(padded_seed[start:end])

            score = _score_field(fd)
            is_auto = score is None and (
                fd.field_type == FieldType.SURVIVAL
                and fd.survival_type in (SurvivalType.LENGTH, SurvivalType.CHECKSUM)
            )

            candidates = _get_candidates(fd, seed_value)

            plans.append(
                FieldPlan(
                    field=fd,
                    positioned=positioned,
                    score=score,
                    auto_calc=is_auto,
                    candidates=candidates,
                )
            )

        return plans

    @staticmethod
    def separate(
        plans: List[FieldPlan],
    ) -> Tuple[List[FieldPlan], List[FieldPlan]]:
        """Split into (manual_fields, auto_fields)."""
        manual = [p for p in plans if not p.auto_calc]
        auto = [p for p in plans if p.auto_calc]
        return manual, auto

    @staticmethod
    def resolve_blocks(
        spec: UnifiedProtocolSpec, plans: List[FieldPlan]
    ) -> Dict[str, BlockInfo]:
        """Build a dict of block_name → BlockInfo from spec field ordering."""
        positioned_fields = spec.iter_positioned_fields()

        # Collect block boundaries
        block_starts: Dict[str, int] = {}
        block_ends: Dict[str, int] = {}
        block_field_order: Dict[str, List[str]] = {}  # block_name → fields seen before its BLOCK_BEGIN
        fields_seen_before: Dict[str, bool] = {}  # block_name → whether BLOCK_BEGIN seen

        for pf in positioned_fields:
            fd = pf.field
            if fd.field_type == FieldType.BLOCK_BEGIN and fd.block_name:
                block_starts[fd.block_name] = pf.end_byte  # byte after the marker
                fields_seen_before[fd.block_name] = True
            if fd.field_type == FieldType.BLOCK_END and fd.block_name:
                block_ends[fd.block_name] = pf.start_byte  # byte at the marker

        # Classify LENGTH fields as inclusive vs exclusive
        length_plans = [p for p in plans if p.auto_calc and p.field.survival_type == SurvivalType.LENGTH]

        inclusive_map: Dict[str, List[FieldPlan]] = {}
        exclusive_map: Dict[str, List[FieldPlan]] = {}

        for lp in length_plans:
            bn = lp.field.block_name
            if bn is None:
                continue
            # LENGTH field is inside the block if its start_byte >= block_starts[bn]
            bs = block_starts.get(bn, 0)
            if lp.positioned.start_byte >= bs:
                inclusive_map.setdefault(bn, []).append(lp)
            else:
                exclusive_map.setdefault(bn, []).append(lp)

        result: Dict[str, BlockInfo] = {}
        for bn in block_starts:
            if bn in block_ends:
                result[bn] = BlockInfo(
                    name=bn,
                    start_byte=block_starts[bn],
                    end_byte=block_ends[bn],
                    inclusive_length_fields=inclusive_map.get(bn, []),
                    exclusive_length_fields=exclusive_map.get(bn, []),
                )
        return result

    @staticmethod
    def has_mutable_candidates(manual_fields: List[FieldPlan]) -> bool:
        """Check whether any manual field has more than 1 candidate value."""
        return any(len(f.candidates) > 1 for f in manual_fields)

    @staticmethod
    def get_length_field_names(plans: List[FieldPlan]) -> List[str]:
        """Return names of LENGTH (auto-calc) fields for bandit registration.

        CHECKSUM fields are intentionally excluded per proposal §2.6.5.
        """
        return [
            p.field.name
            for p in plans
            if p.field.survival_type == SurvivalType.LENGTH
        ]

# ---------------------------------------------------------------------------
# Auto-calculation helpers
# ---------------------------------------------------------------------------

def encode_int(value: int, length: int, endian: str) -> bytes:
    """Encode an integer as bytes with given length and endianness."""
    if length <= 0:
        return b""
    fmt = (">" if endian == "big" else "<")
    if length == 1:
        return struct.pack("B", value & 0xFF)
    elif length == 2:
        return struct.pack(fmt + "H", value & 0xFFFF)
    elif length == 4:
        return struct.pack(fmt + "I", value & 0xFFFFFFFF)
    elif length == 8:
        return struct.pack(fmt + "Q", value & 0xFFFFFFFFFFFFFFFF)
    else:
        return value.to_bytes(length, endian)

def calc_checksum(data: bytes, algorithm: str, length: int, endian: str) -> bytes:
    """Calculate a checksum over *data* using the specified algorithm."""
    fmt = (">" if endian == "big" else "<")

    if algorithm == "crc32":
        return struct.pack(fmt + "L", zlib.crc32(data) & 0xFFFFFFFF)[:length]
    elif algorithm == "crc32c":
        try:
            import crc32c
            return struct.pack(fmt + "L", crc32c.crc32(data))[:length]
        except ImportError:
            return struct.pack(fmt + "L", zlib.crc32(data) & 0xFFFFFFFF)[:length]
    elif algorithm == "adler32":
        return struct.pack(fmt + "L", zlib.adler32(data) & 0xFFFFFFFF)[:length]
    elif algorithm == "md5":
        digest = hashlib.md5(data).digest()
        if endian == ">":
            a, b, c, d = struct.unpack("<LLLL", digest)
            digest = struct.pack(">LLLL", a, b, c, d)
        return digest[:length]
    elif algorithm == "sha1":
        digest = hashlib.sha1(data).digest()
        if endian == ">":
            a, b, c, d, e = struct.unpack("<LLLLL", digest)
            digest = struct.pack(">LLLLL", a, b, c, d, e)
        return digest[:length]
    elif algorithm == "ipv4":
        # Simple 16-bit one's complement sum
        s = 0
        for i in range(0, len(data) - 1, 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        if len(data) % 2:
            s += data[-1] << 8
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return struct.pack(fmt + "H", (~s) & 0xFFFF)[:length]
    else:
        # Fallback: crc32
        return struct.pack(fmt + "L", zlib.crc32(data) & 0xFFFFFFFF)[:length]
