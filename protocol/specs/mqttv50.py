"""Document-backed fixed-layout profile. See protocol/spec_sources.json."""
from protocol.field import UnifiedProtocolSpec, FieldType, SurvivalType
from protocol.profile import F, I, B, E, L

class MqttV50Spec(UnifiedProtocolSpec):
    name = "mqttv50"
    default_port = 1883
    transport = "tcp"
    profile_version = "documented-v1-20260913"
    source_refs = ("MQTT 5.0 §§2.2.2,3.1.2.11,3.1.3",)
    profile_scope = "CONNECT clean start, empty properties, nonempty ClientId, no Will/user/password"
    description = profile_scope
    fields = [
        I("connect_header", 1, 0x10), L("remaining_length", 1, "remaining", encoding="mqtt_varint"), B("remaining"),
        L("protocol_name_length", 2, "protocol_name"), B("protocol_name"), F("protocol_name", b"MQTT"), E("protocol_name"),
        I("protocol_level", 1, 5), I("connect_flags", 1, 2, 0), I("keepalive", 2, 60, 30),
        L("properties_length", 1, "properties", encoding="mqtt_varint"), B("properties"), E("properties"),
        L("client_id_length", 2, "client_id"), B("client_id"), F("client_id", b"testuser", b"probefuz", kind=FieldType.PAYLOAD), E("client_id"), E("remaining")
    ]
