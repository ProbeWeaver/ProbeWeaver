"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class SIPSpec(UnifiedProtocolSpec):
    name = "sip"
    default_port = 5060
    transport = "both"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 3261 §§8.1.1,11,18,20",)
    profile_scope = "OPTIONS, zero body, coherent From/To/Via/Call-ID/CSeq; Via matches selected transport"
    description = profile_scope
    fields = [
        F("method", b"OPTIONS"), F("request_tail", b" sip:localhost SIP/2.0\r\n"),
        F("via_prefix", b"Via: SIP/2.0/"), F("via_transport", b"UDP"),
        F("via_tail", b" localhost:5060;branch=z9hG4bK-probefuzz\r\n"),
        F("max_forwards", b"Max-Forwards: 70\r\n"),
        F("from", b"From: <sip:probe@localhost>;tag=probe001\r\n"), F("to", b"To: <sip:localhost>\r\n"),
        F("call_id", b"Call-ID: probe001@localhost\r\n"), F("cseq", b"CSeq: 1 OPTIONS\r\n"),
        F("length_prefix", b"Content-Length: "), L("content_length", 1, "body", encoding="ascii_decimal"),
        F("end_headers", b"\r\n\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR), B("body"), E("body")
    ]
