"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class RTSPSpec(UnifiedProtocolSpec):
    name = "rtsp"
    default_port = 554
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 2326 §§9.1,12.17",)
    profile_scope = "RTSP/1.0 OPTIONS star request with mandatory CSeq"
    description = profile_scope
    fields = [
        F("method", b"OPTIONS"), F("space1", b" ", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR), F("uri", b"*"), F("space2", b" ", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR),
        F("version", b"RTSP/1.0"), F("request_crlf", b"\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR), F("cseq_header", b"CSeq: "),
        F("cseq", b"1", b"2"), F("end_headers", b"\r\n\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR)
    ]
