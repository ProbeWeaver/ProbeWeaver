"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec
from protocol.profile import F, I, B, E, L

class amqpSpec(UnifiedProtocolSpec):
    name = "amqp"
    default_port = 5672
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("AMQP 1.0 Part 2 Transport §2.2",)
    profile_scope = "AMQP 1.0 version negotiation; not an AMQP 0-9-1 session"
    description = profile_scope
    fields = [
        F("protocol", b"AMQP"), I("protocol_id", 1, 0), I("major", 1, 1), I("minor", 1, 0), I("revision", 1, 0)
    ]
