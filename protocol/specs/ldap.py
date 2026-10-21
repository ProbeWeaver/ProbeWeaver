"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class ldapSpec(UnifiedProtocolSpec):
    name = "ldap"
    default_port = 389
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 4511 §§4.1.1,4.2,5.1",)
    profile_scope = "LDAPv3 anonymous simple BindRequest; no credentials"
    description = profile_scope
    fields = [
        I("message_tag", 1, 0x30), L("message_length", 1, "message", encoding="ber"), B("message"),
        F("message_id", b"\x02\x01\x01", b"\x02\x01\x02", kind=FieldType.PAYLOAD),
        I("bind_tag", 1, 0x60), L("bind_length", 1, "bind", encoding="ber"), B("bind"),
        F("version", b"\x02\x01\x03"), F("name", b"\x04\x00"), F("simple_auth", b"\x80\x00"), E("bind"), E("message")
    ]
