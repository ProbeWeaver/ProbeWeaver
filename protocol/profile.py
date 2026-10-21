"""Builders for bounded, document-backed, fixed-layout probe profiles.

Zero/FF patterns are explicitly negative fuzz actions, NOT normative values.
Variable-width alternatives require a separate profile, not padded literals.
"""
from copy import deepcopy
from protocol.field import FieldDefinition, FieldType, SurvivalType

def F(name, value, *alternatives, kind=FieldType.STRUCTURE, endian="big", survival_type=None):
    values = list(dict.fromkeys((value,) + alternatives))
    if any(not isinstance(v, bytes) or len(v) != len(value) for v in values):
        raise ValueError(f"{name}: alternative changes nominal width")
    negative = [v for v in (bytes(len(value)), b"\xff" * len(value)) if v not in values]
    return FieldDefinition(name, len(value), kind, expected_values=values,
                           endian=endian, negative_values=negative,
                           survival_type=survival_type,
                           description="Fixed-profile value; zero/FF actions are negative tests.")

def I(name, width, value, *alternatives, endian="big", kind=FieldType.STRUCTURE, survival_type=None):
    return F(name, value.to_bytes(width, endian),
             *(v.to_bytes(width, endian) for v in alternatives), endian=endian,
             kind=kind, survival_type=survival_type)

def B(name):
    return FieldDefinition(name + "_begin", 0, FieldType.BLOCK_BEGIN, block_name=name)

def E(name):
    return FieldDefinition(name + "_end", 0, FieldType.BLOCK_END, block_name=name)

def L(name, width, block, *, endian="big", encoding="binary", mask=0):
    return FieldDefinition(name, width, FieldType.SURVIVAL, endian=endian,
                           survival_type=SurvivalType.LENGTH, block_name=block,
                           length_encoding=encoding, length_mask=mask)

def build_seed(spec):
    from core.priority_mapper import PriorityMapper
    from core.mutator import FastMutator
    packet = bytearray()
    for field in spec.fields:
        if field.field_type in (FieldType.BLOCK_BEGIN, FieldType.BLOCK_END):
            continue
        if field.survival_type in (SurvivalType.LENGTH, SurvivalType.CHECKSUM):
            packet.extend(bytes(field.length))
        elif field.expected_values and len(field.expected_values[0]) == field.length:
            packet.extend(field.expected_values[0])
        else:
            raise ValueError(f"{spec.name}/{field.name}: missing width-correct default")
    mapper = PriorityMapper()
    plans = mapper.analyze(spec, bytes(packet))
    _, automatic = mapper.separate(plans)
    FastMutator(spec).recalculate(packet, mapper.resolve_blocks(spec, plans), automatic)
    return bytes(packet)

def transport_profile(spec, transport):
    if transport not in ("tcp", "udp"):
        raise ValueError("transport must be tcp or udp")
    if spec.transport not in (transport, "both"):
        raise ValueError(f"{spec.name} does not define a {transport} profile")
    result = deepcopy(spec)
    # Most specs declare fields as class attributes; deepcopy(instance) alone
    # does NOT detach them. TCP/UDP profiles must never mutate each other.
    result.fields = deepcopy(spec.fields)
    result.transport = transport
    # Legacy custom specs are intentionally not silently reframed.
    if spec.profile_version == "legacy" or spec.transport != "both":
        return result
    if spec.name == "sip":
        for field in result.fields:
            if field.name == "via_transport":
                field.expected_values = [transport.upper().encode("ascii")]
    elif transport == "tcp":
        if spec.name == "dns":
            result.fields = [L("tcp_length", 2, "transport_message"), B("transport_message")] + result.fields + [E("transport_message")]
        elif spec.name == "portmapv2":
            result.fields = [L("record_marker", 4, "transport_message", mask=0x80000000), B("transport_message")] + result.fields + [E("transport_message")]
        elif spec.name == "ikev2":
            # RFC 9329 §3: length includes itself and the non-ESP marker.
            result.default_port = 4500
            result.fields = [F("stream_prefix", b"IKETCP"), B("transport_message"), L("tcp_length", 2, "transport_message"), F("non_esp_marker", bytes(4))] + result.fields + [E("transport_message")]
        else:
            raise ValueError(f"missing framing for {spec.name}/{transport}")
    return result
