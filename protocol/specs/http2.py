"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec
from protocol.profile import F, I, B, E, L

class HTTP2Spec(UnifiedProtocolSpec):
    name = "http2"
    default_port = 80
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 7540 §§3.4,3.5,4.1,6.5 (bounded prior-knowledge profile)",)
    profile_scope = "Cleartext prior-knowledge HTTP/2 preface plus empty SETTINGS; not a TLS ClientHello"
    description = profile_scope
    fields = [
        F("connection_preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
        L("frame_length", 3, "settings"), I("frame_type", 1, 4), I("flags", 1, 0),
        I("stream_id", 4, 0), B("settings"), E("settings")
    ]
