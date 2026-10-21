"""Fixed-width wire encodings. Overflow fails closed; never shifts anchors."""

def encode_length(value, field):
    if value < 0:
        raise ValueError("negative length")
    width = field.length
    encoding = field.length_encoding
    if encoding == "binary":
        if value & field.length_mask:
            raise ValueError("length overlaps reserved mask bits")
        return (value | field.length_mask).to_bytes(width, field.endian)
    if field.length_mask:
        raise ValueError("mask requires binary encoding")
    if encoding == "ascii_decimal":
        data = str(value).encode("ascii")
        if len(data) > width:
            raise ValueError("ASCII length exceeds fixed profile width")
        return data.rjust(width, b"0")
    if encoding == "ber":
        data = bytes([value]) if value < 128 else (
            bytes([0x80 | ((value.bit_length() + 7) // 8)])
            + value.to_bytes((value.bit_length() + 7) // 8, "big"))
    elif encoding == "mqtt_varint":
        if value > 268435455:
            raise ValueError("MQTT Remaining Length overflow")
        data = bytearray()
        while True:
            digit, value = value % 128, value // 128
            data.append(digit | (128 if value else 0))
            if not value:
                break
        data = bytes(data)
    else:
        raise ValueError(f"unknown length encoding: {encoding}")
    if len(data) != width:
        raise ValueError("encoded length changes fixed profile width")
    return data

def decode_length(data, field):
    if field.length_encoding == "binary":
        return int.from_bytes(data, field.endian) & ~field.length_mask
    if field.length_encoding == "ascii_decimal":
        if not data or not data.isdigit():
            raise ValueError("nondecimal length")
        return int(data)
    if field.length_encoding == "ber":
        if not data or data[0] == 0x80 or (data[0] < 128 and len(data) != 1) or (data[0] & 128 and data[0] != 0x80 | (len(data) - 1)):
            raise ValueError("invalid definite BER length")
        return int.from_bytes(data[1:], "big") if data[0] & 128 else data[0]
    if field.length_encoding == "mqtt_varint":
        if not 1 <= len(data) <= 4 or any(not x & 128 for x in data[:-1]) or data[-1] & 128:
            raise ValueError("invalid MQTT variable integer")
        return sum((x & 127) << (7 * i) for i, x in enumerate(data))
    raise ValueError("unknown length encoding")

def wrong_lengths(real, field):
    """Wrong *numeric* values with the field's encoding, width and endianness."""
    result = []
    for number in sorted({0, 1, max(0, real - 1), real + 1, 127, 255, 65535}):
        if number == real:
            continue
        try:
            result.append(encode_length(number, field))
        except (ValueError, OverflowError):
            pass
    if not result:
        raise ValueError("no width-preserving length mutation")
    return result
