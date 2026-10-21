"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class SshSpec(UnifiedProtocolSpec):
    name = "ssh"
    default_port = 22
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 4253 §4.2",)
    profile_scope = "SSH 2.0 identification line only; no key exchange"
    description = profile_scope
    fields = [
        F("prefix", b"SSH-"), F("version", b"2.0"), F("separator", b"-", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR),
        F("software", b"ProtoFuzz_1", b"ProtoFuzz_2", kind=FieldType.PAYLOAD), F("crlf", b"\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR)
    ]
