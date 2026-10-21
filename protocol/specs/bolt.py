"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec
from protocol.profile import F, I, B, E, L

class BOLTSpec(UnifiedProtocolSpec):
    name = "bolt"
    default_port = 7687
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("Bolt handshake specification: magic and four version proposals",)
    profile_scope = "Legacy fixed four-version negotiation, no authentication or queries"
    description = profile_scope
    fields = [
        F("magic", b"\x60\x60\xb0\x17"), I("version1", 4, 0x00000304, 0x00000104),
        I("version2", 4, 0x00000004), I("version3", 4, 0x00000003), I("version4", 4, 0)
    ]
