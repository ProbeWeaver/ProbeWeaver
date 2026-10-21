# Protocol Field Definitions

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional

class FieldType(Enum):
    """
    Field classification based on server parsing behavior:
    - SURVIVAL: Length, end marker - packet dropped if wrong
    - STRUCTURE: Magic, version - parsed but may return error
    - PAYLOAD: Opcode, data - flexible, usually error response
    - BLOCK_BEGIN: Zero-length marker that opens a calculated block
    - BLOCK_END: Zero-length marker that closes a calculated block
    """

    SURVIVAL = "survival"
    STRUCTURE = "structure"
    PAYLOAD = "payload"
    BLOCK_BEGIN = "block_begin"
    BLOCK_END = "block_end"

class SurvivalType(Enum):
    """
    Sub-type for SURVIVAL fields:
    - LENGTH: Length field - the mutation engine recalculates it unless selected
    - CHECKSUM: Checksum field - the mutation engine always recalculates it
    - TERMINATOR: End marker/delimiter
    - OTHER: All other survival fields (offset, flags, etc.)
    """

    LENGTH = "length"
    CHECKSUM = "checksum"
    TERMINATOR = "terminator"
    OTHER = "other"

@dataclass
class FieldDefinition:
    """
    Unified field definition for both compatibility calculation and fuzzing mutation.

    Specs record nominal field lengths. Byte anchors are derived once from field
    order; ordinary mutation writes begin at those anchors.  Candidate values in
    legacy specs may have a different width, but such writes do not relocate the
    downstream anchors.  Generated specs are admitted only when literal values
    match their nominal width, unless a future schema explicitly models dynamic
    layout.
    """

    name: str
    length: int
    field_type: FieldType

    # --- For Compatibility Calculation (StructProtocols) ---
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    expected_values: List[bytes] = field(default_factory=list)
    endian: str = "big"

    # --- For SURVIVAL sub-type ---
    survival_type: Optional[SurvivalType] = None

    # --- For CHECKSUM fields ---
    # algorithm: Checksum algorithm (crc32, crc32c, adler32, md5, sha1, ipv4, udp)
    algorithm: Optional[str] = None
    # ipv4_src_block_name: Required for 'udp' algorithm, name of IPv4 source block
    ipv4_src_block_name: Optional[str] = None
    # ipv4_dst_block_name: Required for 'udp' algorithm, name of IPv4 destination block
    ipv4_dst_block_name: Optional[str] = None

    # --- For Block-based Length Field Calculation ---
    # block_name: Name of the block this field belongs to (for s_block/s_size/s_checksum)
    # Used by: BLOCK_BEGIN, BLOCK_END, LENGTH fields, CHECKSUM fields
    # Block boundaries are determined by BLOCK_BEGIN/BLOCK_END field positions:
    #   - BLOCK_BEGIN before LENGTH → LENGTH is inside the block (inclusive)
    #   - BLOCK_BEGIN after LENGTH → LENGTH is outside the block (exclusive)
    block_name: Optional[str] = None

    description: str = ""

    # Expected values belong to the selected fixed-layout profile. Deliberately
    # malformed values are a separate, width-preserving mutation vocabulary.
    negative_values: List[bytes] = field(default_factory=list)
    length_encoding: str = "binary"  # binary, ascii_decimal, ber, mqtt_varint
    length_mask: int = 0             # e.g. RPC last-fragment bit

@dataclass(frozen=True)
class PositionedField:
    """Runtime-only field span derived from ordered field lengths."""

    field: FieldDefinition
    start_byte: int
    end_byte: int

class UnifiedProtocolSpec:
    """
    Base class for unified protocol specifications.
    Each protocol should inherit from this and define its fields.
    """

    name: str = "Unknown"
    default_port: int = 0
    description: str = ""
    transport: str = "tcp"  # "tcp", "udp", or "both"
    fields: List[FieldDefinition] = field(default_factory=list)

    profile_version: str = "legacy"
    source_refs: tuple = ()
    profile_scope: str = ""

    def for_transport(self, transport: str):
        """Select framing at generation time, never per receiving service."""
        from protocol.profile import transport_profile
        return transport_profile(self, transport)

    def build_seed(self) -> bytes:
        """Serialize the documented default and repair dependency fields."""
        from protocol.profile import build_seed
        return build_seed(self)

    def iter_positioned_fields(self) -> List[PositionedField]:
        """
        Derive byte spans from field order and field length.

        Zero-length fields are valid block markers and do not advance the cursor.
        """

        positioned_fields: List[PositionedField] = []
        cursor = 0

        for field_def in self.fields:
            field_length = max(field_def.length, 0)
            start = cursor
            end = start + field_length
            positioned_fields.append(
                PositionedField(field=field_def, start_byte=start, end_byte=end)
            )
            cursor = end

        return positioned_fields
