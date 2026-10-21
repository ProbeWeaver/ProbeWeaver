"""Generic protocol-format fallback bodies, invoked after rules and RF."""


def hand_code_rules():
    """Return independent bounded Go function bodies for published services."""
    return [{'code': 'return bytes.HasPrefix(resp, []byte("AMQP"))',
      'family': 'amqp',
      'service': 'amqp',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return len(resp) >= 4 && resp[0] == 0x03 && resp[1] == 0x00',
      'family': 'rdp',
      'service': 'rdp',
      'source': 'hand',
      'type': 'code'},
     {'code': 'h := resp\n'
              'if len(h) > 12 {\n'
              '\th = h[:12]\n'
              '}\n'
              'if bytes.Contains(h, []byte{0xfe, 0x53, 0x4d, 0x42}) ||\n'
              '\tbytes.Contains(h, []byte{0xfd, 0x53, 0x4d, 0x42}) ||\n'
              '\tbytes.Contains(h, []byte{0xff, 0x53, 0x4d, 0x42}) ||\n'
              '\tbytes.Contains(h, []byte{0x53, 0x4d, 0x42, 0x40}) {\n'
              '\treturn true\n'
              '}\n'
              'return len(resp) >= 1 && len(resp) <= 8 && resp[0] >= 0x82 && resp[0] <= 0x85',
      'family': 'smb',
      'service': 'smb',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return len(resp) >= 2 && resp[0] == 0xff && resp[1] >= 0xfb && resp[1] <= 0xfe',
      'family': 'telnet',
      'service': 'telnet',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return len(resp) >= 8 && resp[0] == 0x00 && resp[1] == 0x00 && resp[3] == 0x04',
      'family': 'http2',
      'service': 'http2',
      'source': 'hand',
      'type': 'code'},
     {'code': 'if len(resp) < 8 || len(resp) > 260 {\n'
              '\treturn false\n'
              '}\n'
              'if resp[2] != 0x00 || resp[3] != 0x00 {\n'
              '\treturn false\n'
              '}\n'
              'ml := int(binary.BigEndian.Uint16(resp[4:6]))\n'
              'if ml < 2 || ml > 253 {\n'
              '\treturn false\n'
              '}\n'
              'if 6+ml != len(resp) {\n'
              '\treturn false\n'
              '}\n'
              'if !((resp[7] >= 1 && resp[7] <= 43) || (resp[7] >= 0x81 && resp[7] <= 0xAB)) {\n'
              '\treturn false\n'
              '}\n'
              'if resp[0] == 0x30 && resp[1] >= 0x81 && resp[1] <= 0x84 {\n'
              '\treturn false\n'
              '}\n'
              'return true',
      'family': 'modbus',
      'service': 'modbus',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return len(resp) >= 8 && resp[0] == 0x80',
      'family': 'portmap',
      'service': 'portmapv2',
      'source': 'hand',
      'type': 'code'},
     {'code': 'if bytes.HasPrefix(resp, []byte{0x00, 0x00, 0x03, 0x04}) {\n'
              '\treturn true\n'
              '}\n'
              'h := resp\n'
              'if len(h) > 16 {\n'
              '\th = h[:16]\n'
              '}\n'
              'if bytes.Contains(h, []byte{0x60, 0x60, 0xb0, 0x17}) {\n'
              '\treturn true\n'
              '}\n'
              'return bytes.Contains(resp, []byte("Memgraph.ExecutionException")) ||\n'
              '\tbytes.Contains(resp, []byte("Neo.ClientError")) ||\n'
              '\tbytes.Contains(resp, []byte("Neo.DatabaseError")) ||\n'
              '\tbytes.Contains(resp, []byte("Neo.TransientError"))',
      'family': 'bolt',
      'service': 'bolt',
      'source': 'hand',
      'type': 'code'},
     {'code': 'if len(resp) < 1 || resp[0] != 0x30 {\n'
              '\treturn false\n'
              '}\n'
              'h := resp\n'
              'if len(h) > 64 {\n'
              '\th = h[:64]\n'
              '}\n'
              'return bytes.Contains(h, []byte("public"))',
      'family': 'snmp',
      'service': 'snmp',
      'source': 'hand',
      'type': 'code'},
     {'code': 'if len(resp) >= 1 && resp[0] == 0x30 {\n'
              '\tif len(resp) >= 5 && resp[2] == 0x02 {\n'
              '\t\tidx := 4 + int(resp[3])\n'
              '\t\tif idx < len(resp) && resp[idx] >= 0x60 && resp[idx] <= 0x7f {\n'
              '\t\t\treturn true\n'
              '\t\t}\n'
              '\t}\n'
              '\th := resp\n'
              '\tif len(h) > 32 {\n'
              '\t\th = h[:32]\n'
              '\t}\n'
              '\tfor _, c := range h {\n'
              '\t\tif c == 0x61 {\n'
              '\t\t\treturn true\n'
              '\t\t}\n'
              '\t}\n'
              '}\n'
              'return bytes.Contains(resp, []byte("1.3.6.1.4.1.1466.20036")) ||\n'
              '\tbytes.Contains(resp, []byte("unknown LDAP request")) ||\n'
              '\tbytes.Contains(resp, []byte("for an LDAP request"))',
      'family': 'ldap',
      'service': 'ldap',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return len(resp) >= 2 && len(resp) <= 8 && resp[0] == 0x05 && (resp[1] == 0x00 || '
              'resp[1] == 0xff)',
      'family': 'socks',
      'service': 'socks5',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return len(resp) >= 2 && len(resp) <= 64 && resp[0] == 0x20',
      'family': 'mqtt',
      'service': 'mqttv311',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return len(resp) >= 2 && len(resp) <= 64 && resp[0] == 0x20',
      'family': 'mqtt',
      'service': 'mqttv50',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return bytes.Contains(resp, []byte("MongoDB")) ||\n'
              '\tbytes.Contains(resp, []byte("OP_QUERY")) ||\n'
              '\tbytes.Contains(resp, []byte("bad object in message"))',
      'family': 'mongodb',
      'service': 'mongodb',
      'source': 'hand',
      'type': 'code'},
     {'code': 'if bytes.HasPrefix(resp, []byte("\\x13BitTorrent protocol")) {\n'
              '\treturn true\n'
              '}\n'
              'return bytes.Contains(resp, []byte("Transmission")) ||\n'
              '\tbytes.Contains(resp, []byte("qBittorrent")) ||\n'
              '\tbytes.Contains(resp, []byte("deluge")) ||\n'
              '\tbytes.Contains(resp, []byte("BitTorrent"))',
      'family': 'bittorrent',
      'service': 'bittorrentv10',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return bytes.Contains(resp, []byte("unsupported protocol version")) ||\n'
              '\tbytes.Contains(resp, []byte("RethinkDB"))',
      'family': 'rethinkdb',
      'service': 'rethinkdb',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return bytes.HasPrefix(resp, []byte("SSH-"))',
      'family': 'ssh',
      'service': 'ssh',
      'source': 'hand',
      'type': 'code'},
     {'code': 'h := resp\nif len(h) > 64 {\n\th = h[:64]\n}\nreturn bytes.Contains(h, []byte("RTSP/"))',
      'family': 'rtsp',
      'service': 'rtsp',
      'source': 'hand',
      'type': 'code'},
     {'code': 'h := resp\nif len(h) > 64 {\n\th = h[:64]\n}\nreturn bytes.Contains(h, []byte("SIP/"))',
      'family': 'sip',
      'service': 'sip',
      'source': 'hand',
      'type': 'code'},
     {'code': 'h := resp\n'
              'if len(h) > 16 {\n'
              '\th = h[:16]\n'
              '}\n'
              'return bytes.HasPrefix(resp, []byte("HTTP/")) || bytes.Contains(h, []byte("HTTP/1."))',
      'family': 'http',
      'service': 'http',
      'source': 'hand',
      'type': 'code'},
     {'code': 'h := resp\n'
              'if len(h) > 80 {\n'
              '\th = h[:80]\n'
              '}\n'
              'return bytes.HasPrefix(resp, []byte("220")) &&\n'
              '\t!bytes.Contains(h, []byte("ESMTP")) && !bytes.Contains(h, []byte("SMTP"))',
      'family': 'ftp',
      'service': 'ftp',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return bytes.HasPrefix(resp, []byte("+OK"))',
      'family': 'pop3',
      'service': 'pop3',
      'source': 'hand',
      'type': 'code'},
     {'code': 'h := resp\nif len(h) > 16 {\n\th = h[:16]\n}\nreturn bytes.Contains(h, []byte("* OK"))',
      'family': 'imap',
      'service': 'imapv4',
      'source': 'hand',
      'type': 'code'},
     {'code': 'if bytes.HasPrefix(resp, []byte("+PONG")) {\n'
              '\treturn true\n'
              '}\n'
              'if bytes.Contains(resp, []byte("NOAUTH Authentication required")) {\n'
              '\treturn true\n'
              '}\n'
              "if len(resp) >= 3 && resp[0] == '-' {\n"
              '\ti := 1\n'
              "\tfor i < len(resp) && resp[i] >= 'A' && resp[i] <= 'Z' {\n"
              '\t\ti++\n'
              '\t}\n'
              '\tif i-1 >= 2 {\n'
              '\t\treturn true\n'
              '\t}\n'
              '}\n'
              'return false',
      'family': 'redis',
      'service': 'redis',
      'source': 'hand',
      'type': 'code'},
     {'code': 'if bytes.HasPrefix(resp, []byte("ERROR\\r\\n")) ||\n'
              '\tbytes.HasPrefix(resp, []byte("STAT ")) ||\n'
              '\tbytes.HasPrefix(resp, []byte("VERSION ")) {\n'
              '\treturn true\n'
              '}\n'
              'h := resp\n'
              'if len(h) > 64 {\n'
              '\th = h[:64]\n'
              '}\n'
              'return bytes.Contains(h, []byte("CLIENT_ERROR")) || bytes.Contains(h, '
              '[]byte("SERVER_ERROR"))',
      'family': 'memcached',
      'service': 'memcached',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return bytes.Contains(resp, []byte("Protocol version"))',
      'family': 'x11',
      'service': 'x11',
      'source': 'hand',
      'type': 'code'},
     {'code': 'if bytes.HasPrefix(resp, []byte("ERROR :")) {\n'
              '\treturn true\n'
              '}\n'
              'if len(resp) >= 1 && resp[0] == \':\' && bytes.Contains(resp, []byte(" NOTICE ")) {\n'
              '\treturn true\n'
              '}\n'
              'return bytes.Contains(resp, []byte("Connection not regist"))',
      'family': 'irc',
      'service': 'irc',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return len(resp) >= 2 && resp[0] == 0xc8 && resp[1] == 0x02',
      'family': 'l2tp',
      'service': 'l2tp',
      'source': 'hand',
      'type': 'code'},
     {'code': 'if len(resp) < 28 || resp[16] >= 0x38 {\n'
              '\treturn false\n'
              '}\n'
              'if resp[17] != 0x10 && resp[17] != 0x20 {\n'
              '\treturn false\n'
              '}\n'
              'switch resp[18] {\n'
              'case 0x02, 0x04, 0x05, 0x06, 0x22, 0x23, 0x24, 0x25, 0x26, 0x2e, 0x2f:\n'
              '\treturn true\n'
              '}\n'
              'return false',
      'family': 'ike',
      'service': 'ikev2',
      'source': 'hand',
      'type': 'code'},
     {'code': 'if len(resp) < 48 {\n'
              '\treturn false\n'
              '}\n'
              'vn := (resp[0] >> 3) & 0x07\n'
              'mode := resp[0] & 0x07\n'
              'return (vn == 1 || vn == 2 || vn == 3 || vn == 4) && (mode == 2 || mode == 4 || mode == '
              '5)',
      'family': 'ntp',
      'service': 'ntpv4',
      'source': 'hand',
      'type': 'code'},
     {'code': 'return len(resp) >= 12 && (resp[2]&0x80) != 0 && (resp[3]&0x0f) <= 10',
      'family': 'dns',
      'service': 'dns',
      'source': 'hand',
      'type': 'code'}]
