"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class MqttV311Spec(UnifiedProtocolSpec):
    name = "mqttv311"
    default_port = 1883
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("MQTT 3.1.1 §§2.2.3,3.1.2,3.1.3",)
    profile_scope = "CONNECT with clean session, nonempty ClientId, no Will/user/password"
    description = profile_scope
    fields = [
        I("connect_header", 1, 0x10), L("remaining_length", 1, "remaining", encoding="mqtt_varint"), B("remaining"),
        L("protocol_name_length", 2, "protocol_name"), B("protocol_name"), F("protocol_name", b"MQTT"), E("protocol_name"),
        I("protocol_level", 1, 4), I("connect_flags", 1, 2, 0), I("keepalive", 2, 60, 30),
        L("client_id_length", 2, "client_id"), B("client_id"), F("client_id", b"testuser", b"probefuz", kind=FieldType.PAYLOAD), E("client_id"), E("remaining")
    ]
