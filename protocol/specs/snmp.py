"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class SNMPSpec(UnifiedProtocolSpec):
    name = "snmp"
    default_port = 161
    transport = "udp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 1157 §§4,4.1.2; ASN.1 Message/PDUs",)
    profile_scope = "SNMPv1 public-community GetRequest for sysDescr.0; community may differ"
    description = profile_scope
    fields = [
        I("message_tag", 1, 0x30), L("message_length", 1, "message", encoding="ber"), B("message"),
        F("version", b"\x02\x01\x00"), F("community_tag", b"\x04"),
        L("community_length", 1, "community", encoding="ber"), B("community"), F("community", b"public", kind=FieldType.PAYLOAD), E("community"),
        I("pdu_tag", 1, 0xa0), L("pdu_length", 1, "pdu", encoding="ber"), B("pdu"),
        F("request_id", b"\x02\x01\x01", b"\x02\x01\x02", kind=FieldType.PAYLOAD),
        F("error_status", b"\x02\x01\x00"), F("error_index", b"\x02\x01\x00"),
        I("varbinds_tag", 1, 0x30), L("varbinds_length", 1, "varbinds", encoding="ber"), B("varbinds"),
        I("binding_tag", 1, 0x30), L("binding_length", 1, "binding", encoding="ber"), B("binding"),
        F("oid_tag", b"\x06"), L("oid_length", 1, "oid", encoding="ber"), B("oid"),
        F("oid", b"\x2b\x06\x01\x02\x01\x01\x01\x00", b"\x2b\x06\x01\x02\x01\x01\x05\x00", kind=FieldType.PAYLOAD), E("oid"),
        F("value_null", b"\x05\x00"), E("binding"), E("varbinds"), E("pdu"), E("message")
    ]
