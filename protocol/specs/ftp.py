"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class FTPSpec(UnifiedProtocolSpec):
    name = "ftp"
    default_port = 21
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 959 §4.1.3",)
    profile_scope = "NOOP control command; reply may depend on login policy"
    description = profile_scope
    fields = [
        F("command", b"NOOP", b"HELP"), F("crlf", b"\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR)
    ]
