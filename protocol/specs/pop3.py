"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class Pop3Spec(UnifiedProtocolSpec):
    name = "pop3"
    default_port = 110
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 1939 §7 USER",)
    profile_scope = "USER authorization command only; test identity, no password"
    description = profile_scope
    fields = [
        F("command", b"USER"), F("space", b" ", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR), F("user", b"testuser00", b"testuser01", kind=FieldType.PAYLOAD), F("crlf", b"\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR)
    ]
