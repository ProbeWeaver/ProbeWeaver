"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class Smb2Spec(UnifiedProtocolSpec):
    name = "smb"
    default_port = 445
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("MS-SMB2 §§2.2.1,2.2.3; MS-SMB direct TCP transport",)
    profile_scope = "Direct TCP SMB2.002 NEGOTIATE with one dialect; no SMB3.1.1 contexts"
    description = profile_scope
    fields = [
        I("direct_tcp_zero", 1, 0), L("direct_tcp_length", 3, "smb"), B("smb"),
        F("protocol_id", b"\xfeSMB"), I("header_structure_size", 2, 64, endian="little"),
        I("credit_charge", 2, 0, endian="little"), I("channel_reserved", 4, 0, endian="little"),
        I("command", 2, 0, endian="little"), I("credits", 2, 1, endian="little"),
        I("flags", 4, 0, endian="little"), I("next_command", 4, 0, endian="little"),
        I("message_id", 8, 0, endian="little", kind=FieldType.PAYLOAD), I("process_id", 4, 0, endian="little"),
        I("tree_id", 4, 0, endian="little"), I("session_id", 8, 0, endian="little", kind=FieldType.PAYLOAD), F("signature", bytes(16)),
        I("negotiate_structure_size", 2, 36, endian="little"), I("dialect_count", 2, 1, endian="little", kind=FieldType.SURVIVAL, survival_type=SurvivalType.OTHER),
        I("security_mode", 2, 1, endian="little"), I("reserved", 2, 0, endian="little"),
        I("capabilities", 4, 0, endian="little"), F("client_guid", bytes.fromhex("00112233445566778899aabbccddeeff"), kind=FieldType.PAYLOAD),
        I("client_start_time", 8, 0, endian="little"),
        I("dialect", 2, 0x0202, 0x0210, endian="little"), E("smb")
    ]
