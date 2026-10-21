package fingerprint

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestMemberResolveCode(t *testing.T) {
	cases := []struct {
		name    string
		cluster string
		hexResp string
		want    string // Response identification metadata.
	}{
		{"ssh-dropbear", "ssh", "5353482d322e302d64726f70626561725f323032302e38310d0a", "ssh-dropbear"},
		{"ssh-lsh", "ssh", "5353482d322e302d6c7368642d322e31206c7368202d206120474e55207373680d0a", "ssh-lsh"},
		// Banner-only AsyncSSH proposal failed full identity coverage (KEX-only
		// observations); it is intentionally not admitted as a code rule.
		{"ssh-asyncssh-unadmitted", "ssh", "5353482d322e302d4173796e635353485f322e32332e310d0a", ""},
		{"ssh-openssh-indistinguishable", "ssh", "5353482d322e302d4f70656e5353485f382e397031", ""},
		// ftp：banner token
		{"ftp-proftpd-shared-errors", "ftp", "3232302050726f46545044205365727665720d0a", ""},
		{"ftp-pure-ftpd", "ftp", "3232302d2d2d2d2d2d2d2d2d2d2d2057656c636f6d6520746f20507572652d46545064", "ftp-pure-ftpd"},
		{"http-nginx", "http", "485454502f312e31203430302042616420526571756573740d0a5365727665723a206e67696e782f312e30", "http"},
		{"http-apache", "http", "485454502f312e31203430302042616420526571756573740d0a5365727665723a204170616368652f322e34", "http-apache"},
		{"mongodb-shared-variants", "mongodb", "fb0000009a000000010000000100000008000000", ""},
		{"ntpv4", "ntpv4", "240a00e600000000000000007f7f0101ee534119c1c73171e000000000000001ee53415410c6e95bee53415410caba5a", "ntpv4"},
		{"modbus-shared-errors", "modbus", "00010000000701030400020002", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := hex.DecodeString(c.hexResp)
			if err != nil {
				t.Fatalf("hex decode: %v", err)
			}
			got, ok := MemberResolveCode(c.cluster, resp)
			if c.want == "" {
				if ok {
					t.Errorf("MemberResolveCode(%q) = (%q,true), want (\"\",false)", c.cluster, got)
				}
				return
			}
			if !ok || got != c.want {
				t.Errorf("MemberResolveCode(%q) = (%q,%v), want (%q,true)", c.cluster, got, ok, c.want)
			}
		})
	}
}

func TestMemberResolveCode_NilSafe(t *testing.T) {
	if m, ok := MemberResolveCode("nonexistent-cluster", []byte("anything")); ok || m != "" {
		t.Errorf("unknown cluster = (%q,%v), want (\"\",false)", m, ok)
	}
	if m, ok := MemberResolveCode("ssh", nil); ok || m != "" {
		t.Errorf("nil resp = (%q,%v), want (\"\",false)", m, ok)
	}
}

func TestLoadMemberRules_SkipsCodeEntries(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/member_rules.json"
	rules := []map[string]interface{}{
		{"service": "ssh", "member": "ssh-dropbear", "type": "member_code",
			"code": "return bytes.HasPrefix(resp, []byte(\"SSH-2.0-dropbear\"))"},
		{"service": "ssh", "member": "ssh-openssh-cfg", "type": "banner",
			"pattern": "^SSH-2.0-OpenSSH_", "source": "member_hand"},
	}
	b, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	engine, err := LoadMemberRules(path)
	if err != nil {
		t.Fatalf("LoadMemberRules: %v", err)
	}
	if engine.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (code entry skipped)", engine.Len())
	}
}
