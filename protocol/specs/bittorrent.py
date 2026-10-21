"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class BittorrentV10Spec(UnifiedProtocolSpec):
    name = "bittorrentv10"
    default_port = 6881
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("BEP 3 peer protocol handshake",)
    profile_scope = "Peer handshake; zero info_hash is a structural fixture and MUST be replaced by a known test swarm hash for acceptance tests"
    description = profile_scope
    fields = [
        L("protocol_length", 1, "protocol"), B("protocol"), F("protocol", b"BitTorrent protocol"), E("protocol"),
        F("reserved", bytes(8)), F("info_hash", bytes(20), kind=FieldType.PAYLOAD),
        F("peer_id", b"-PF0001-012345678901", b"-PF0001-012345678902", kind=FieldType.PAYLOAD)
    ]
