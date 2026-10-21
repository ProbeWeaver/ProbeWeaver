"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class Socks5Spec(UnifiedProtocolSpec):
    name = "socks5"
    default_port = 1080
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 1928 §3",)
    profile_scope = "SOCKS5 one-method greeting; no CONNECT request"
    description = profile_scope
    fields = [
        I("version", 1, 5), I("method_count", 1, 1, kind=FieldType.SURVIVAL, survival_type=SurvivalType.OTHER), I("method", 1, 0, 2)
    ]
