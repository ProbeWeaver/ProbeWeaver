"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class ImapV4rev1Spec(UnifiedProtocolSpec):
    name = "imapv4"
    default_port = 143
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 3501 §6.1.1",)
    profile_scope = "Tagged CAPABILITY command, valid in any connection state"
    description = profile_scope
    fields = [
        F("tag", b"A001", b"A002"), F("space", b" ", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR), F("command", b"CAPABILITY"), F("crlf", b"\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR)
    ]
