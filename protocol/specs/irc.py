"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class IRCSpec(UnifiedProtocolSpec):
    name = "irc"
    default_port = 6667
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 1459 §§4.1.2,4.1.3",)
    profile_scope = "NICK plus USER registration; server policy may require PASS or deny nickname"
    description = profile_scope
    fields = [
        F("nick_prefix", b"NICK "), F("nickname", b"testuser", b"probefuz", kind=FieldType.PAYLOAD), F("nick_crlf", b"\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR),
        F("user_prefix", b"USER "), F("username", b"fuzzuser", b"testuser", kind=FieldType.PAYLOAD),
        F("user_tail", b" 0 * :Protocol Fuzzer\r\n")
    ]
