"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class NtpV4Spec(UnifiedProtocolSpec):
    name = "ntpv4"
    default_port = 123
    transport = "udp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 5905 §7.3",)
    profile_scope = "NTPv4 client request, fixed 48-byte base header; timestamp fixture, not a clock measurement"
    description = profile_scope
    fields = [
        I("li_vn_mode", 1, 0x23), I("stratum", 1, 0), I("poll", 1, 6, 4), I("precision", 1, 0xec),
        I("root_delay", 4, 0), I("root_dispersion", 4, 0), I("reference_id", 4, 0),
        I("reference_timestamp", 8, 0), I("origin_timestamp", 8, 0), I("receive_timestamp", 8, 0),
        I("transmit_timestamp", 8, 0xe000000000000001, 0xe000000000000002, kind=FieldType.PAYLOAD)
    ]
