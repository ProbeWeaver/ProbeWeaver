"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class PortMapperV2Spec(UnifiedProtocolSpec):
    name = "portmapv2"
    default_port = 111
    transport = "both"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 1833 Appendix A; RFC 5531 §§9,11 record marking",)
    profile_scope = "RPCv2 Portmapper program 100000 version 2 NULL/AUTH_NONE; TCP adds last-fragment marker"
    description = profile_scope
    fields = [
        I("xid", 4, 1, 2, kind=FieldType.PAYLOAD), I("message_type", 4, 0), I("rpc_version", 4, 2),
        I("program", 4, 100000), I("program_version", 4, 2), I("procedure", 4, 0),
        I("credential_flavor", 4, 0), L("credential_length", 4, "credential"), B("credential"), E("credential"),
        I("verifier_flavor", 4, 0), L("verifier_length", 4, "verifier"), B("verifier"), E("verifier")
    ]
