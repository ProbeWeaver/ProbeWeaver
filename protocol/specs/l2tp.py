"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class L2TPSpec(UnifiedProtocolSpec):
    name = "l2tp"
    default_port = 1701
    transport = "udp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 2661 §§3.1,4.4,5.1.1",)
    profile_scope = "L2TPv2 SCCRQ with all required AVPs; tunnel establishment request, not a full session"
    description = profile_scope
    fields = [
        B("message"), I("flags_version", 2, 0xc802), L("length", 2, "message"),
        I("tunnel_id", 2, 0), I("session_id", 2, 0, kind=FieldType.PAYLOAD), I("ns", 2, 0), I("nr", 2, 0),
        F("message_type_avp", bytes.fromhex("8008000000000001")),
        F("protocol_version_avp", bytes.fromhex("8008000000020100")),
        F("framing_capabilities_avp", bytes.fromhex("800a0000000300000003")),
        F("host_name_avp", bytes.fromhex("800c00000007") + b"fuzzer"),
        F("assigned_tunnel_avp", bytes.fromhex("8008000000090001")), E("message")
    ]
