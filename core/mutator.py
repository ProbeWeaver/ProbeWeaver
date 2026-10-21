"""
Field-level mutation helpers for protocol fuzzing.

Provides write_field and recalculate used by BatchMutationGenerator
(reinforcement learning path).  The old combinatorial enumeration methods
(generate_mutants / _generate_depth / _build_mutant) have been removed;
all mutation generation now goes through core/reinforcement_learning.py.
"""

import logging
from typing import List, Dict

from protocol.field import SurvivalType, UnifiedProtocolSpec
from protocol.length_codec import encode_length
from core.priority_mapper import (
    PriorityMapper,
    FieldPlan,
    BlockInfo,
    encode_int,
    calc_checksum,
)

logger = logging.getLogger(__name__)

class FastMutator:
    """
    In-memory mutation helper.

    Holds a PriorityMapper for the given protocol spec and exposes
    write_field / recalculate helpers that BatchMutationGenerator uses
    to build mutated packets.
    """

    def __init__(self, protocol_spec: UnifiedProtocolSpec):
        self.spec = protocol_spec
        self._mapper = PriorityMapper()

    # ------------------------------------------------------------------
    # Public helpers (used by BatchMutationGenerator)
    # ------------------------------------------------------------------

    def write_field(self, pkt: bytearray, plan: FieldPlan, value: bytes) -> None:
        """Write an anchored field action, extending ``pkt`` when necessary.

        ``plan.positioned.start_byte`` is the stable anchor.  The number of
        overwritten bytes is ``len(value)``, which may differ from the field's
        nominal span in legacy/generated specs.  A shorter value therefore
        leaves the remaining seed suffix intact; a longer value can overwrite
        later nominal spans.  Counterfactual replay records this actual write
        width and rejects unsupported variable-width reconstruction.

        No-op if ``value`` is empty.
        """
        start = plan.positioned.start_byte
        end = start + len(value)
        if end > len(pkt):
            pkt.extend(b'\x00' * (end - len(pkt)))
        pkt[start:end] = value

    def recalculate(
        self,
        pkt: bytearray,
        blocks: Dict[str, BlockInfo],
        auto_fields: List[FieldPlan],
    ) -> None:
        """Recalculate all LENGTH and CHECKSUM fields in-place.

        Safe to call repeatedly; idempotent for already-correct fields.
        """
        # Auto-calculate LENGTH fields for each block
        for block_name, block_info in blocks.items():
            block_len = max(0, block_info.end_byte - block_info.start_byte)
            for lp in block_info.inclusive_length_fields:
                encoded = encode_length(block_len, lp.field)
                pos_start = lp.positioned.start_byte
                pos_end = lp.positioned.end_byte
                if pos_end <= len(pkt):
                    pkt[pos_start:pos_end] = encoded
            for lp in block_info.exclusive_length_fields:
                encoded = encode_length(block_len, lp.field)
                pos_start = lp.positioned.start_byte
                pos_end = lp.positioned.end_byte
                if pos_end <= len(pkt):
                    pkt[pos_start:pos_end] = encoded

        # Auto-calculate CHECKSUM fields
        for af in auto_fields:
            if af.field.survival_type != SurvivalType.CHECKSUM:
                continue
            bn = af.field.block_name
            if bn and bn in blocks:
                bi = blocks[bn]
                block_data = bytes(pkt[bi.start_byte:bi.end_byte])
                checksum = calc_checksum(
                    block_data,
                    af.field.algorithm or 'crc32',
                    af.field.length,
                    af.field.endian,
                )
                pos_start = af.positioned.start_byte
                pos_end = af.positioned.end_byte
                if pos_end <= len(pkt):
                    pkt[pos_start:pos_end] = checksum
