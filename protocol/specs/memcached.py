"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class MemcacheBinaryProtocolSpec(UnifiedProtocolSpec):
    name = "memcached"
    default_port = 11211
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("Memcached Binary Protocol: header and GET request",)
    profile_scope = "Binary GET with key only; no extras or value, no storage mutation"
    description = profile_scope
    fields = [
        I("magic", 1, 0x80), I("opcode", 1, 0), L("key_length", 2, "key"),
        L("extras_length", 1, "extras"), I("datatype", 1, 0), I("vbucket", 2, 0),
        L("body_length", 4, "body"), I("opaque", 4, 1, 2, kind=FieldType.PAYLOAD), I("cas", 8, 0),
        B("body"), B("extras"), E("extras"), B("key"),
        F("key", b"protocol-fuzzer", b"protocol-prober", kind=FieldType.PAYLOAD), E("key"), E("body")
    ]
