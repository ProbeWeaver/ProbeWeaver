"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class RedisSpec(UnifiedProtocolSpec):
    name = "redis"
    default_port = 6379
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("Redis RESP specification: arrays and bulk strings; PING command",)
    profile_scope = "RESP2 one-element PING command"
    description = profile_scope
    fields = [
        F("array_header", b"*1\r\n"), F("bulk_prefix", b"$"), L("bulk_length", 1, "command", encoding="ascii_decimal"),
        F("length_crlf", b"\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR), B("command"), F("command", b"PING"), E("command"), F("end_crlf", b"\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR)
    ]
