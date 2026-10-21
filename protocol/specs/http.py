"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec
from protocol.profile import F, I, B, E, L

class HTTPSpec(UnifiedProtocolSpec):
    name = "http"
    default_port = 80
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 2616 §§5,14.23 (local HTTP snapshot)",)
    profile_scope = "HTTP/1.1 GET root with Host; no request body"
    description = profile_scope
    fields = [
        F("method", b"GET"), F("request_tail", b" / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
    ]
