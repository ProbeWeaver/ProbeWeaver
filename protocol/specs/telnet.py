"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec
from protocol.profile import F, I, B, E, L

class TelnetSpec(UnifiedProtocolSpec):
    name = "telnet"
    default_port = 23
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 854 TELNET command structure; RFC 857 ECHO",)
    profile_scope = "IAC DO ECHO option negotiation; option octet is mandatory for DO"
    description = profile_scope
    fields = [
        I("iac", 1, 255), I("negotiation", 1, 253), I("option", 1, 1, 3)
    ]
