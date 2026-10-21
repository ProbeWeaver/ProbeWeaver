"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class MongoDBWireProtocolSpec(UnifiedProtocolSpec):
    name = "mongodb"
    default_port = 27017
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("MongoDB Wire Protocol OP_MSG; BSON specification",)
    profile_scope = "OP_MSG hello command with $db=admin; uncompressed, no checksum"
    description = profile_scope
    fields = [
        B("message"), L("message_length", 4, "message", endian="little"), I("request_id", 4, 1, 2, endian="little", kind=FieldType.PAYLOAD),
        I("response_to", 4, 0, endian="little"), I("opcode", 4, 2013, endian="little"),
        I("flags", 4, 0, endian="little"), I("section_kind", 1, 0),
        B("bson"), L("bson_length", 4, "bson", endian="little"),
        I("hello_type", 1, 0x10), F("hello_key", b"hello\0"), I("hello_value", 4, 1, endian="little"),
        I("db_type", 1, 2), F("db_key", b"$db\0"), L("db_length", 4, "db_value", endian="little"),
        B("db_value"), F("db_value", b"admin\0"), E("db_value"), I("bson_terminator", 1, 0, kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR), E("bson"), E("message")
    ]
