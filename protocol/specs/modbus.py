"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class MODBUSSpec(UnifiedProtocolSpec):
    name = "modbus"
    default_port = 502
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("Modbus Messaging on TCP/IP Implementation Guide §3.1.3; function 03",)
    profile_scope = "Read Holding Registers, address 0 quantity 1; no write function"
    description = profile_scope
    fields = [
        I("transaction_id", 2, 1, 2, kind=FieldType.PAYLOAD), I("protocol_id", 2, 0), L("mbap_length", 2, "adu_body"),
        B("adu_body"), I("unit_id", 1, 1, 2), I("function", 1, 3),
        I("start_address", 2, 0, 1, kind=FieldType.PAYLOAD), I("quantity", 2, 1, 2), E("adu_body")
    ]
