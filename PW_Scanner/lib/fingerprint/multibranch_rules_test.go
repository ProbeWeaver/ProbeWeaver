package fingerprint

import (
	"encoding/hex"
	"testing"
)

func TestDocumentedMultiBranchServiceRules(t *testing.T) {
	cases := []struct{ service, hex string }{
		{"mqtt", "20020000"},
		{"mqtt", "2003008400"},
		{"mqtt", "201200000f22000a250027001e84802100052401e00182"},
		{"modbus", "340000000003ff0300"},
		{"modbus", "001d00000003000100"},
		{"modbus", "000100000003018301"},
		{"rethinkdb", hex.EncodeToString([]byte("SUCCESS\x00"))},
		{"rethinkdb", hex.EncodeToString([]byte("{\"min_protocol_version\":0,\"max_protocol_version\":1,\"server_version\":\"3.0.1\"}\x00"))},
	}
	for _, tc := range cases {
		resp, err := hex.DecodeString(tc.hex)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, match := range MatchAllCode(resp) {
			if match.Source == "code" && match.Service == tc.service {
				found = true
			}
		}
		if !found {
			t.Errorf("new service rule did not identify %s: %s", tc.service, tc.hex)
		}
	}
}

func TestPrecisionFirstPartialOverlay(t *testing.T) {
	cases := []struct {
		service string
		resp    []byte
		want    bool
	}{
		{"http2", []byte{0, 0, 0, 4, 1, 0, 0, 0, 0}, true},
		{"http2", []byte("HTTP/1.1 400 Bad Request\r\n\r\n"), false},
		{"dns", []byte{0x12, 0x34, 0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0}, true},
		{"sip", []byte("SIP/2.0 400 Bad Request\r\nVia: SIP/2.0/UDP example\r\n\r\n"), true},
		{"sip", []byte("\r\n\r\n"), false},
		{"telnet", []byte{0xff, 0xfd, 24}, true},
		{"telnet", []byte{0xff, 0xfc, 0x54}, false},
	}
	for _, tc := range cases {
		found := false
		for _, match := range MatchAllCode(tc.resp) {
			if match.Source == "code" && match.Service == tc.service {
				found = true
			}
		}
		if found != tc.want {
			t.Errorf("partial %s: match=%v want=%v", tc.service, found, tc.want)
		}
	}
}
