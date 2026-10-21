"""Offline admission checks for bounded probe profiles, not service coverage tests.

Wire checks intentionally parse independently of FieldDefinition block offsets.
They cover the named profile, not every message allowed by the full protocol.
"""
import re
import struct
import xml.etree.ElementTree as ET
from protocol.field import FieldType, SurvivalType
from protocol.length_codec import decode_length

def require(condition, message):
    if not condition:
        raise ValueError(message)

def uint(data, start, width, endian="big"):
    require(start >= 0 and start + width <= len(data), "truncated integer")
    return int.from_bytes(data[start:start + width], endian)

def tlv(data, start=0):
    require(start + 2 <= len(data), "truncated BER header")
    tag, length = data[start:start + 2]
    pos = start + 2
    if length & 128:
        width = length & 127
        require(0 < width <= 4 and pos + width <= len(data), "invalid BER definite length")
        length = uint(data, pos, width)
        pos += width
    end = pos + length
    require(end <= len(data), "BER value overrun")
    return tag, data[pos:end], end

def children(data):
    result, pos = [], 0
    while pos < len(data):
        tag, value, pos = tlv(data, pos)
        result.append((tag, value))
    return result

def headers(packet):
    require(b"\r\n\r\n" in packet, "missing header terminator")
    head, body = packet.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    result = {}
    for line in lines[1:]:
        require(b":" in line, "invalid header")
        name, value = line.split(b":", 1)
        require(name.lower() not in result, "duplicate header in bounded profile")
        result[name.lower()] = value.strip()
    if b"content-length" in result:
        value = result[b"content-length"]
        require(value.isdigit() and int(value) == len(body), "ASCII Content-Length mismatch")
    return lines[0], result, body

def validate_wire(name, transport, data):
    """Raise ValueError for an invalid bounded-profile wire message."""
    p = bytes(data)
    require(bool(p), "empty packet")
    if name == "dns" and transport == "tcp":
        require(uint(p, 0, 2) == len(p) - 2, "DNS TCP length")
        p = p[2:]
    if name == "portmapv2" and transport == "tcp":
        require(uint(p, 0, 4) == 0x80000000 | (len(p) - 4), "RPC record marker")
        p = p[4:]
    if name == "ikev2" and transport == "tcp":
        require(p[:6] == b"IKETCP" and uint(p, 6, 2) == len(p) - 6 and p[8:12] == bytes(4), "IKE TCP framing")
        p = p[12:]
    if name == "rdp":
        require(len(p) == 19 and p[:2] == b"\x03\0" and uint(p, 2, 2) == len(p), "RDP TPKT")
        require(p[4] == len(p) - 5 and p[5:11] == bytes.fromhex("e00000000000"), "RDP X.224")
        require(p[11:15] == b"\x01\0\x08\0" and uint(p, 15, 4, "little") in (1, 3, 11), "RDP_NEG_REQ")
    elif name in ("snmp", "ldap"):
        tag, body, end = tlv(p)
        require(tag == 0x30 and end == len(p), "outer BER SEQUENCE")
        parts = children(body)
        if name == "ldap":
            require(len(parts) == 2 and parts[0][0] == 2 and parts[0][1] in (b"\1", b"\2") and parts[1][0] == 0x60, "LDAP message envelope")
            require(children(parts[1][1]) == [(2, b"\3"), (4, b""), (0x80, b"")], "LDAPv3 anonymous BindRequest")
        else:
            require(len(parts) == 3 and parts[0] == (2, b"\0") and parts[1] == (4, b"public") and parts[2][0] == 0xa0, "SNMPv1 envelope")
            fields = children(parts[2][1])
            require(len(fields) == 4 and fields[0][0] == 2 and fields[0][1] in (b"\1", b"\2") and fields[1:3] == [(2, b"\0"), (2, b"\0")] and fields[3][0] == 0x30, "GetRequest fields")
            bindings = children(fields[3][1])
            require(len(bindings) == 1 and bindings[0][0] == 0x30, "varbind list")
            binding = children(bindings[0][1])
            require(len(binding) == 2 and binding[0][0] == 6 and binding[0][1] in (bytes.fromhex("2b06010201010100"), bytes.fromhex("2b06010201010500")) and binding[1] == (5, b""), "OID/NULL binding")
    elif name == "ntpv4":
        require(len(p) == 48 and p[0] == 0x23 and p[1] == 0 and any(p[40:48]), "NTP client base header")
    elif name == "http2":
        require(p[:24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "HTTP/2 preface")
        require(len(p) == 33 and p[24:] == bytes.fromhex("000000040000000000"), "empty SETTINGS frame")
    elif name == "redis":
        require(re.fullmatch(rb"\*1\r\n\$[0-9]+\r\nPING\r\n", p) is not None, "RESP PING")
        require(int(p.split(b"\r\n")[1][1:]) == 4, "RESP bulk length")
    elif name in ("http", "cwmp", "rtsp", "sip"):
        start, hdr, body = headers(p)
        if name == "http":
            require(start == b"GET / HTTP/1.1" and hdr.get(b"host") == b"localhost" and not body, "HTTP request")
        elif name == "rtsp":
            require(start == b"OPTIONS * RTSP/1.0" and hdr.get(b"cseq", b"").isdigit() and not body, "RTSP OPTIONS/CSeq")
        elif name == "sip":
            require(start == b"OPTIONS sip:localhost SIP/2.0" and not body, "SIP request")
            require(all(k in hdr for k in (b"via", b"from", b"to", b"call-id", b"cseq", b"max-forwards", b"content-length")), "mandatory SIP headers")
            require(hdr[b"via"].startswith(b"SIP/2.0/" + transport.upper().encode()) and b";branch=z9hG4bK" in hdr[b"via"], "SIP Via transport/branch")
            require(b";tag=" in hdr[b"from"] and hdr[b"cseq"] == b"1 OPTIONS", "SIP From tag / CSeq method")
        else:
            require(start == b"POST / HTTP/1.1" and hdr.get(b"host") and hdr.get(b"content-type", b"").startswith(b"text/xml") and hdr.get(b"soapaction") == b'""', "CWMP HTTP binding")
            root = ET.fromstring(body)
            ns = "{http://schemas.xmlsoap.org/soap/envelope/}"
            require(root.tag == ns + "Envelope", "SOAP Envelope")
            soap_body = root.find(ns + "Body")
            require(soap_body is not None and len(soap_body) == 1 and soap_body[0].tag == "{urn:dslforum-org:cwmp-1-0}GetRPCMethods" and len(soap_body[0]) == 0, "SOAP GetRPCMethods body")
    elif name == "mongodb":
        require(len(p) >= 26 and uint(p, 0, 4, "little") == len(p) and uint(p, 12, 4, "little") == 2013, "MongoDB header")
        require(p[8:12] == bytes(4) and p[16:21] == bytes(5), "OP_MSG flags/kind0")
        bson = p[21:]
        require(uint(bson, 0, 4, "little") == len(bson) and bson[-1] == 0, "BSON inclusive length/EOO")
        pos, values = 4, {}
        while pos < len(bson) - 1:
            kind = bson[pos]
            key_end = bson.index(0, pos + 1)
            key, pos = bson[pos + 1:key_end].decode("ascii"), key_end + 1
            require(key not in values, "duplicate BSON key")
            if kind == 0x10:
                values[key], pos = uint(bson, pos, 4, "little"), pos + 4
            elif kind == 2:
                size = uint(bson, pos, 4, "little")
                pos += 4
                require(size > 0 and pos + size < len(bson) and bson[pos + size - 1] == 0, "BSON string")
                values[key], pos = bson[pos:pos + size - 1].decode("ascii"), pos + size
            else:
                raise ValueError("unsupported BSON kind in hello profile")
        require(pos == len(bson) - 1 and values == {"hello": 1, "$db": "admin"}, "hello command")
    elif name == "smb":
        require(len(p) == 106 and p[0] == 0 and uint(p, 1, 3) == len(p) - 4, "SMB direct TCP length")
        p = p[4:]
        require(p[:4] == b"\xfeSMB" and uint(p, 4, 2, "little") == 64 and p[12:14] == bytes(2), "SMB2 header")
        require(uint(p, 64, 2, "little") == 36 and uint(p, 66, 2, "little") == 1 and uint(p, 100, 2, "little") in (0x0202, 0x0210), "SMB negotiate structure/count/dialect")
        require(p[92:100] == bytes(8), "no SMB3.1.1 contexts")
    elif name == "x11":
        require(p == bytes.fromhex("6c000b000000000000000000"), "X11 no-auth setup")
    elif name == "l2tp":
        require(len(p) >= 12 and uint(p, 0, 2) == 0xc802 and uint(p, 2, 2) == len(p) and p[4:12] == bytes(8), "L2TP control header")
        pos, avps = 12, {}
        while pos < len(p):
            flags_len, vendor, kind = uint(p, pos, 2), uint(p, pos + 2, 2), uint(p, pos + 4, 2)
            size = flags_len & 1023
            require(flags_len & 0xfc00 == 0x8000 and vendor == 0 and size >= 6 and pos + size <= len(p) and kind not in avps, "L2TP AVP framing/M bit")
            avps[kind], pos = p[pos + 6:pos + size], pos + size
        require(list(avps)[0] == 0 and avps == {0:b"\0\1",2:b"\1\0",3:b"\0\0\0\3",7:b"fuzzer",9:b"\0\1"}, "SCCRQ required AVPs")
    elif name == "modbus":
        require(len(p) == 12 and p[2:4] == bytes(2) and uint(p, 4, 2) == len(p) - 6 and p[7] == 3 and 1 <= uint(p, 10, 2) <= 125, "Modbus MBAP / Read Holding Registers")
    elif name == "memcached":
        require(len(p) >= 24 and p[:2] == b"\x80\0" and p[4] == 0 and uint(p, 8, 4) == len(p) - 24 == uint(p, 2, 2) and p[16:24] == bytes(8), "Memcached GET key-only body")
    elif name in ("mqttv311", "mqttv50"):
        require(len(p) >= 14 and p[0] == 0x10 and p[1] < 128 and p[1] == len(p) - 2 and p[2:8] == b"\0\4MQTT", "MQTT fixed header/name/remaining length")
        level = 4 if name == "mqttv311" else 5
        require(p[8] == level and p[9] in (0, 2), "MQTT flags/profile dependencies")
        pos = 12
        if level == 5:
            require(p[pos] == 0, "MQTT5 property length")
            pos += 1
        size = uint(p, pos, 2)
        require(size > 0 and pos + 2 + size == len(p) and b"\0" not in p[pos + 2:], "MQTT ClientId")
        p[pos + 2:].decode("utf-8")
    elif name == "dns":
        require(len(p) >= 17 and p[4:12] == b"\0\1" + bytes(6), "DNS question counts")
        pos = 12
        while True:
            require(pos < len(p), "DNS truncated QNAME")
            size = p[pos]
            pos += 1
            if not size:
                break
            require(size <= 63 and pos + size < len(p), "DNS label length")
            pos += size
        require(pos + 4 == len(p) and uint(p, pos, 2) in (1, 28, 16) and uint(p, pos + 2, 2) == 1, "DNS QTYPE/QCLASS positioning")
    elif name == "portmapv2":
        require(len(p) == 40 and struct.unpack("!9I", p[4:]) == (0, 2, 100000, 2, 0, 0, 0, 0, 0), "Portmapper NULL RPC call")
    elif name == "ikev2":
        require(len(p) >= 28 and uint(p, 24, 4) == len(p) and any(p[:8]) and p[8:16] == bytes(8) and p[16:24] == bytes.fromhex("2120220800000000"), "IKE_SA_INIT header")
        kind, pos, payloads = 33, 28, {}
        while kind:
            require(kind not in payloads, "duplicate IKE payload")
            size = uint(p, pos + 2, 2)
            require(size >= 4 and pos + size <= len(p) and p[pos + 1] == 0, "IKE payload size/reserved")
            payloads[kind] = p[pos + 4:pos + size]
            kind, pos = p[pos], pos + size
        require(pos == len(p) and set(payloads) == {33, 34, 40}, "SA/KE/Nonce chain")
        sa = payloads[33]
        require(sa[:2] == bytes(2) and uint(sa, 2, 2) == len(sa) and sa[4:8] == b"\1\1\0\4", "IKE proposal")
        pos, transforms = 8, []
        for i in range(4):
            size = uint(sa, pos + 2, 2)
            require(sa[pos] == (3 if i < 3 else 0) and sa[pos + 1] == 0 and size in (8, 12) and pos + size <= len(sa), "IKE transform framing")
            transforms.append(sa[pos + 4:pos + size])
            pos += size
        require(pos == len(sa) and transforms == [bytes.fromhex(x) for x in ("0100000c800e0080","02000002","03000002","04000002")], "complete compatible transform suite")
        ke = payloads[34]
        require(len(ke) == 132 and ke[:4] == b"\0\2\0\0" and int.from_bytes(ke[4:], "big") == 2 and len(payloads[40]) == 16, "IKE group2 KE/reserved/nonce")
    elif name == "amqp":
        require(p == b"AMQP\0\1\0\0", "AMQP1.0 header")
    elif name == "bittorrentv10":
        require(len(p) == 68 and p[0] == 19 and p[1:20] == b"BitTorrent protocol" and p[20:28] == bytes(8), "BitTorrent handshake")
    elif name == "bolt":
        require(len(p) == 20 and p[:4] == bytes.fromhex("6060b017") and uint(p, 4, 4) in (0x304, 0x104) and p[8:] == bytes.fromhex("000000040000000300000000"), "Bolt version proposals")
    elif name == "rethinkdb":
        require(p == bytes.fromhex("c3bdc234"), "RethinkDB V1_0 initial magic")
    elif name == "socks5":
        require(len(p) == 3 and p[:2] == b"\5\1" and p[2] in (0, 2), "SOCKS5 method count")
    elif name == "telnet":
        require(len(p) == 3 and p[:2] == b"\xff\xfd" and p[2] in (1, 3), "Telnet DO option")
    else:
        patterns = {
            "ssh": rb"SSH-2\.0-[!-~]+\r\n",
            "ftp": rb"(?:NOOP|HELP)\r\n",
            "imapv4": rb"A00[12] CAPABILITY\r\n",
            "irc": rb"NICK [A-Za-z][A-Za-z0-9]{7}\r\nUSER [A-Za-z0-9]{8} 0 \* :Protocol Fuzzer\r\n",
            "pop3": rb"USER testuser0[01]\r\n",
        }
        require(name in patterns, f"no independent wire validator for {name}")
        require(re.fullmatch(patterns[name], p) is not None, f"{name} command syntax")

def validate_spec(spec, *, alternatives=True):
    """Generic schema + independent wire parse + all single-field positive values.

    Multi-field positive independence is a human-review requirement, not implied
    by these single-field checks. Negative fuzz actions are NOT required to parse.
    """
    seen, stack, blocks = set(), [], {}
    for pos in spec.iter_positioned_fields():
        f = pos.field
        require(f.name not in seen, f"duplicate field {f.name}")
        seen.add(f.name)
        require(isinstance(f.length, int) and f.length >= 0, f"negative width {f.name}")
        require(f.endian in ("big", "little"), f"invalid endian {f.name}")
        if f.field_type == FieldType.BLOCK_BEGIN:
            require(f.length == 0 and f.block_name and f.block_name not in blocks and all(n != f.block_name for n, _ in stack), "duplicate/invalid block begin")
            stack.append((f.block_name, pos.start_byte))
        elif f.field_type == FieldType.BLOCK_END:
            require(f.length == 0 and stack and stack[-1][0] == f.block_name, "unbalanced/crossed block")
            name, start = stack.pop()
            blocks[name] = (start, pos.start_byte)
        else:
            require(f.length > 0, "zero-width non-marker field")
            for value in f.expected_values + f.negative_values:
                require(isinstance(value, bytes) and len(value) == f.length, f"{f.name}: width mismatch")
            require(not set(f.expected_values) & set(f.negative_values), "positive/negative overlap")
    require(not stack, "unclosed block")
    for f in spec.fields:
        if f.survival_type in (SurvivalType.LENGTH, SurvivalType.CHECKSUM):
            require(f.block_name in blocks, f"{f.name}: missing dependency block")
            require(not f.expected_values and not f.negative_values, "calculated field has literal candidates")
    p = spec.build_seed()
    for pos in spec.iter_positioned_fields():
        if pos.field.survival_type == SurvivalType.LENGTH:
            start, end = blocks[pos.field.block_name]
            require(decode_length(p[pos.start_byte:pos.end_byte], pos.field) == end - start, "length dependency mismatch")
    validate_wire(spec.name, spec.transport, p)
    tested = 0
    if alternatives:
        for pos in spec.iter_positioned_fields():
            for value in pos.field.expected_values[1:]:
                candidate = p[:pos.start_byte] + value + p[pos.end_byte:]
                validate_wire(spec.name, spec.transport, candidate)
                tested += 1
    try:
        validate_wire(spec.name, spec.transport, p[:-1])
    except (ValueError, IndexError, UnicodeError, ET.ParseError):
        pass
    else:
        raise ValueError("negative control: truncated default incorrectly admitted")
    return {"protocol": spec.name, "transport": spec.transport, "bytes": len(p),
            "default_port": spec.default_port,
            "packet_hex": p.hex(), "fields": len(spec.fields),
            "positive_alternatives_checked": tested,
            "truncation_negative_rejected": True, "scope": spec.profile_scope}
