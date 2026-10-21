"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class CwmpSpec(UnifiedProtocolSpec):
    name = "cwmp"
    default_port = 7547
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("TR-069 Amendment 6 Corrigendum 1 §§3.4,A.3.1.1; SOAP 1.1",)
    profile_scope = "Complete SOAP GetRPCMethods request within an established CWMP session; NOT an initial Inform; HTTP/TLS/auth/session prerequisites separate"
    description = profile_scope
    fields = [
        F("request_line", b"POST / HTTP/1.1\r\n"),
        F("host", b"Host: localhost\r\n"), F("content_type", b"Content-Type: text/xml; charset=utf-8\r\n"),
        F("soap_action", b'SOAPAction: ""\r\n'), F("length_prefix", b"Content-Length: "),
        L("content_length", 3, "body", encoding="ascii_decimal"), F("end_headers", b"\r\n\r\n", kind=FieldType.SURVIVAL, survival_type=SurvivalType.TERMINATOR),
        B("body"), F("xml_declaration", b'<?xml version="1.0" encoding="UTF-8"?>'),
        F("envelope_open", b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">'),
        F("soap_header", b'<soap:Header><cwmp:ID soap:mustUnderstand="1">1</cwmp:ID></soap:Header>'),
        F("soap_body", b"<soap:Body><cwmp:GetRPCMethods/></soap:Body>"),
        F("envelope_close", b"</soap:Envelope>"), E("body")
    ]
