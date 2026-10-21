"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec
from protocol.profile import F, I, B, E, L

class RdpSpec(UnifiedProtocolSpec):
    name = "rdp"
    default_port = 3389
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("MS-RDPBCGR 20250407 §§2.2.1.1–2.2.1.1.1; TPKT/X.224",)
    profile_scope = "Remote Desktop TCP negotiation only, no TLS/CredSSP authentication"
    description = profile_scope
    fields = [
        B("tpkt"), I("tpkt_version", 1, 3), I("tpkt_reserved", 1, 0), L("tpkt_length", 2, "tpkt"),
        L("x224_length_indicator", 1, "x224"), B("x224"), I("x224_cr", 1, 0xe0),
        I("dst_ref", 2, 0), I("src_ref", 2, 0), I("class_options", 1, 0),
        B("negotiation"), I("neg_type", 1, 1), I("neg_flags", 1, 0),
        L("neg_length", 2, "negotiation", endian="little"),
        I("requested_protocols", 4, 3, 1, 11, endian="little"), E("negotiation"), E("x224"), E("tpkt")
    ]
