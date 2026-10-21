"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec
from protocol.profile import F, I, B, E, L

class RethinkdbV10Spec(UnifiedProtocolSpec):
    name = "rethinkdb"
    default_port = 28015
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RethinkDB Writing drivers: V1_0 first exchange",)
    profile_scope = "Four-byte V1_0 first exchange only; await server JSON before SCRAM"
    description = profile_scope
    fields = [
        F("magic", b"\xc3\xbd\xc2\x34", endian="little")
    ]
