"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class ikeSpec(UnifiedProtocolSpec):
    name = "ikev2"
    default_port = 500
    transport = "both"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 5996 §§3.1–3.3,3.4,3.9; RFC 9329 §§3,4",)
    profile_scope = "IKE_SA_INIT with a legacy group-2/AES128/SHA1 proposal and deterministic DH/nonce fixtures; NOT production key establishment"
    description = profile_scope
    fields = [
        B("ike"), F("initiator_spi", bytes.fromhex("0102030405060708"), kind=FieldType.PAYLOAD), I("responder_spi", 8, 0),
        I("next_payload", 1, 33), I("version", 1, 0x20), I("exchange_type", 1, 34),
        I("flags", 1, 8), I("message_id", 4, 0, kind=FieldType.PAYLOAD), L("ike_length", 4, "ike"),
        B("sa"), I("sa_next", 1, 34), I("sa_critical_reserved", 1, 0), L("sa_length", 2, "sa"),
        F("proposal_header", bytes.fromhex("0000002c01010004")),
        F("encryption_transform", bytes.fromhex("0300000c0100000c800e0080")),
        F("prf_transform", bytes.fromhex("0300000802000002")),
        F("integrity_transform", bytes.fromhex("0300000803000002")),
        F("dh_transform", bytes.fromhex("0000000804000002")), E("sa"),
        B("ke"), I("ke_next", 1, 40), I("ke_critical_reserved", 1, 0), L("ke_length", 2, "ke"),
        I("dh_group", 2, 2), I("ke_reserved", 2, 0), F("dh_public_value", bytes(127) + b"\x02", kind=FieldType.PAYLOAD), E("ke"),
        B("nonce"), I("nonce_next", 1, 0), I("nonce_critical_reserved", 1, 0), L("nonce_length", 2, "nonce"),
        F("nonce", bytes.fromhex("00112233445566778899aabbccddeeff"), kind=FieldType.PAYLOAD), E("nonce"), E("ike")
    ]
