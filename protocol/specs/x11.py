"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec
from protocol.profile import F, I, B, E, L

class X11Spec(UnifiedProtocolSpec):
    name = "x11"
    default_port = 6000
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("RFC 1013 Connection Setup",)
    profile_scope = "X11 little-endian setup with no authentication; refusal is allowed"
    description = profile_scope
    fields = [
        F("byte_order", b"l"), I("unused", 1, 0), I("major_version", 2, 11, endian="little"),
        I("minor_version", 2, 0, endian="little"), L("auth_name_length", 2, "auth_name", endian="little"),
        L("auth_data_length", 2, "auth_data", endian="little"), I("unused2", 2, 0),
        B("auth_name"), E("auth_name"), B("auth_data"), E("auth_data")
    ]
