"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class DNSSpec(UnifiedProtocolSpec):
    name = "dns"
    default_port = 53
    transport = "both"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 1035 §§4.1.1,4.1.2,4.2.2",)
    profile_scope = "One uncompressed question, example.com IN A; TCP profile adds two-byte length"
    description = profile_scope
    fields = [
        I("transaction_id", 2, 1, 2, kind=FieldType.PAYLOAD), I("flags", 2, 0x0100), I("question_count", 2, 1, kind=FieldType.SURVIVAL, survival_type=SurvivalType.OTHER),
        I("answer_count", 2, 0, kind=FieldType.SURVIVAL, survival_type=SurvivalType.OTHER), I("authority_count", 2, 0, kind=FieldType.SURVIVAL, survival_type=SurvivalType.OTHER), I("additional_count", 2, 0, kind=FieldType.SURVIVAL, survival_type=SurvivalType.OTHER),
        F("qname", b"\x07example\x03com\0", b"\x07example\x03net\0", kind=FieldType.PAYLOAD),
        I("qtype", 2, 1, 28, 16, kind=FieldType.PAYLOAD), I("qclass", 2, 1)
    ]
