package fingerprint

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRuleEngine_MatchFirstWins(t *testing.T) {
	engine, err := CompileRules([]RuleSpec{
		{Service: "ssh", Pattern: `^SSH-\x32\.0-`, Type: "banner", Source: "nmap"},
		{Service: "http", Pattern: `^HTTP/[\d.]+ \d`, Type: "banner", Source: "nmap"},
		{Service: "amqp", Pattern: `^AMQP\x00`, Type: "magic", Source: "nmap"},
		// magic_hex for ≥0x80 bytes (Go regexp can't match raw \xff):
		{Service: "smb", MagicHex: "ff534d42", Type: "magic", Source: "hand"}, // \xffSMB
		{Service: "smb", MagicHex: "fe534d42", Type: "magic", Source: "hand"}, // \xfeSMB
		{Service: "telnet", MagicHex: "ff", Type: "magic", Source: "hand"},    // IAC (after smb)
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	if engine.Len() != 6 {
		t.Fatalf("Len = %d, want 6", engine.Len())
	}

	cases := []struct {
		name string
		resp []byte
		want string
		ok   bool
	}{
		{"ssh banner", []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"), "ssh", true},
		{"http status line", []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n"), "http", true},
		{"amqp magic", []byte("AMQP\x00\x00\x09\x01"), "amqp", true},
		{"smb1 magic ffSMB", []byte{0xff, 'S', 'M', 'B', 0, 0, 0, 0}, "smb", true},
		{"smb2 magic feSMB", []byte{0xfe, 'S', 'M', 'B', 0xc0, 0}, "smb", true},
		{"telnet IAC (not smb)", []byte{0xff, 0xfb, 0x01, 'h', 'i'}, "telnet", true},
		{"random bytes no match", []byte{0x00, 0x01, 0x02, 0xff, ' ', 'x'}, "", false},
		{"empty", []byte(""), "", false},
	}
	for _, c := range cases {
		svc, ok := engine.Match(c.resp)
		if ok != c.ok || svc != c.want {
			t.Errorf("Match(%q) = (%q, %v), want (%q, %v)", c.name, svc, ok, c.want, c.ok)
		}
	}
}

func TestRuleEngine_NilSafe(t *testing.T) {
	var engine *RuleEngine
	if svc, ok := engine.Match([]byte("SSH-2.0-x")); ok || svc != "" {
		t.Errorf("nil Match = (%q,%v), want (\"\",false)", svc, ok)
	}
	if engine.Len() != 0 {
		t.Errorf("nil Len = %d, want 0", engine.Len())
	}
}

func TestCompileRules_BadPatternFails(t *testing.T) {
	// RE2 rejects unmatched paren → fail-fast.
	if _, err := CompileRules([]RuleSpec{{Service: "x", Pattern: "^("}}); err == nil {
		t.Fatal("expected error for bad pattern, got nil")
	}
	// empty service/pattern rejected
	if _, err := CompileRules([]RuleSpec{{Service: "", Pattern: "^x"}}); err == nil {
		t.Fatal("expected error for empty service, got nil")
	}
}

func TestRuleEngine_OffsetMagic(t *testing.T) {
	// modbus: bytes 0-1 vary (txn id), bytes 2-3 constant 0000 (protocol id).
	engine, err := CompileRules([]RuleSpec{
		{Service: "modbus", MagicHex: "0000", Offset: 2, Type: "offset", Source: "deterministic"},
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	cases := []struct {
		name string
		resp []byte
		want string
		ok   bool
	}{
		{"offset match", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03}, "modbus", true},
		{"offset differ", []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x03}, "", false},
		{"too short", []byte{0x00, 0x01, 0x00}, "", false},
	}
	for _, c := range cases {
		svc, ok := engine.Match(c.resp)
		if ok != c.ok || svc != c.want {
			t.Errorf("Match(%q) = (%q,%v), want (%q,%v)", c.name, svc, ok, c.want, c.ok)
		}
	}
}

func TestRuleEngine_Mask(t *testing.T) {
	// ntpv4: byte0 low 3 bits = mode; server mode = 4 (mask 0x07, value 0x04).
	engine, err := CompileRules([]RuleSpec{
		{Service: "ntpv4", MaskHex: "07", MaskValueHex: "04", Offset: 0, Type: "mask", Source: "llm"},
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	cases := []struct {
		name string
		resp []byte
		ok   bool
	}{
		{"mode server 0xd4", []byte{0xd4, 0x00, 0x00, 0x00}, true},  // 0xd4 & 0x07 = 0x04
		{"mode server 0xe4", []byte{0xe4, 0x00}, true},              // 0xe4 & 0x07 = 0x04
		{"mode other 0xc2", []byte{0xc2, 0x00, 0x00}, false},        // 0xc2 & 0x07 = 0x02
		{"empty", []byte{}, false},
	}
	for _, c := range cases {
		svc, ok := engine.Match(c.resp)
		if ok != c.ok || (ok && svc != "ntpv4") {
			t.Errorf("Match(%q) = (%q,%v), want ok=%v", c.name, svc, ok, c.ok)
		}
	}
}

func TestCompileRules_MaskAndOffset(t *testing.T) {
	// mask_hex without mask_value_hex
	if _, err := CompileRules([]RuleSpec{{Service: "x", MaskHex: "07"}}); err == nil {
		t.Fatal("expected error: mask_hex without mask_value_hex")
	}
	// mask length mismatch
	if _, err := CompileRules([]RuleSpec{{Service: "x", MaskHex: "0707", MaskValueHex: "04"}}); err == nil {
		t.Fatal("expected error: mask length mismatch")
	}
	// bad mask hex
	if _, err := CompileRules([]RuleSpec{{Service: "x", MaskHex: "zz", MaskValueHex: "04"}}); err == nil {
		t.Fatal("expected error: bad mask hex")
	}
	// negative offset
	if _, err := CompileRules([]RuleSpec{{Service: "x", MagicHex: "00", Offset: -1}}); err == nil {
		t.Fatal("expected error: negative offset")
	}
}

func TestRuleEngine_TierPartition(t *testing.T) {
	engine, err := CompileRules([]RuleSpec{
		{Service: "ssh", Pattern: `^SSH-`, Source: "hand"},               // baseline
		{Service: "ssh", Pattern: `^SSH-2\.0-dropbear_`, Source: "llm"},  // specific
		{Service: "modbus", MagicHex: "0000", Offset: 2, Source: "deterministic"}, // specific
		{Service: "http", Pattern: `^HTTP/`, Source: "nmap"},             // baseline
		{Service: "x", Pattern: `^FOO`},                                  // empty source → baseline
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	if svc, ok := engine.MatchSpecific([]byte("SSH-2.0-dropbear_2024\r\n")); !ok || svc != "ssh" {
		t.Errorf("MatchSpecific dropbear = (%q,%v), want (\"ssh\",true)", svc, ok)
	}
	if svc, ok := engine.MatchSpecific([]byte("HTTP/1.0 200 OK\r\n")); ok || svc != "" {
		t.Errorf("MatchSpecific http (baseline rule) = (%q,%v), want (\"\",false)", svc, ok)
	}
	if svc, ok := engine.MatchBaseline([]byte("HTTP/1.0 200 OK\r\n")); !ok || svc != "http" {
		t.Errorf("MatchBaseline http = (%q,%v), want (\"http\",true)", svc, ok)
	}
	if svc, ok := engine.MatchBaseline([]byte("SSH-2.0-OpenSSH\r\n")); !ok || svc != "ssh" {
		t.Errorf("MatchBaseline ssh (hand broad) = (%q,%v), want (\"ssh\",true)", svc, ok)
	}
}

func TestRuleEngine_SpecificitySort_MongoDBOverHTTP(t *testing.T) {
	engine, err := CompileRules([]RuleSpec{
		{Service: "http", Pattern: `^HTTP/[0-9]\.[0-9] [0-9]{3}`, Type: "banner", Source: "hand"},
		{Service: "mongodb", Pattern: `^HTTP/1\.0 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 85\r\n\r\nIt looks like you are trying to access MongoDB over HTTP on the native driver port\.`, Type: "banner", Source: "nmap"},
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	resp := []byte("HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 85\r\n\r\nIt looks like you are trying to access MongoDB over HTTP on the native driver port.\n\n")

	if svc, ok := engine.Match(resp); !ok || svc != "http" {
		t.Errorf("Match (file-order) = (%q,%v), want (\"http\",true) — file-order semantics must be unchanged", svc, ok)
	}
	if svc, ok := engine.MatchBaseline(resp); !ok || svc != "mongodb" {
		t.Errorf("MatchBaseline = (%q,%v), want (\"mongodb\",true)", svc, ok)
	}
	if svc, ok := engine.MatchSpecific(resp); ok || svc != "" {
		t.Errorf("MatchSpecific = (%q,%v), want (\"\",false)", svc, ok)
	}
}

func TestRuleEngine_NilSafe_Tiered(t *testing.T) {
	var engine *RuleEngine
	if svc, ok := engine.MatchSpecific([]byte("x")); ok || svc != "" {
		t.Errorf("nil MatchSpecific = (%q,%v), want (\"\",false)", svc, ok)
	}
	if svc, ok := engine.MatchBaseline([]byte("x")); ok || svc != "" {
		t.Errorf("nil MatchBaseline = (%q,%v), want (\"\",false)", svc, ok)
	}
}

func TestMemberRuleEngine_SpecificitySort(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/member_rules.json"
	rules := []MemberRuleSpec{
		{RuleSpec: RuleSpec{Service: "ssh", Pattern: `^SSH-2\.0-`, Source: "member_llm"}, Member: "ssh-openssh-cfg"},
		{RuleSpec: RuleSpec{Service: "ssh", Pattern: `^SSH-2\.0-dropbear_`, Source: "member_llm"}, Member: "ssh-dropbear"},
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
	if m, ok := engine.Match("ssh", []byte("SSH-2.0-dropbear_2024.78\r\n")); !ok || m != "ssh-dropbear" {
		t.Errorf("Match ssh/dropbear = (%q,%v), want (\"ssh-dropbear\",true)", m, ok)
	}
	if m, ok := engine.Match("ssh", []byte("SSH-2.0-OpenSSH_8.9p1\r\n")); !ok || m != "ssh-openssh-cfg" {
		t.Errorf("Match ssh/openssh = (%q,%v), want (\"ssh-openssh-cfg\",true)", m, ok)
	}
}

func TestRuleEngine_ProductionRules_MongoDBOverHTTP(t *testing.T) {
	path := "../../rules.json" // Response identification metadata.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("production rules.json not found at %s: %v", path, err)
	}
	var specs []RuleSpec
	if err := json.Unmarshal(data, &specs); err != nil {
		t.Fatalf("unmarshal rules.json: %v", err)
	}
	engine, err := CompileRules(specs)
	if err != nil {
		t.Fatalf("CompileRules production: %v", err)
	}
	resp := []byte("HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 85\r\n\r\nIt looks like you are trying to access MongoDB over HTTP on the native driver port.\r\n")
	if svc, ok := engine.MatchBaseline(resp); !ok || svc != "mongodb" {
		t.Errorf("production MatchBaseline MongoDB-over-HTTP = (%q,%v), want (\"mongodb\",true)", svc, ok)
	}
	if svc, ok := engine.Match(resp); !ok || svc != "http" {
		t.Errorf("production Match (file-order) = (%q,%v), want (\"http\",true)", svc, ok)
	}
}

func TestTierOf(t *testing.T) {
	cases := map[string]int{
		"code":         1,
		"llm":          1,
		"deterministic": 1,
		"rf":           2,
		"nmap":         3,
		"hand":         3,
		"hand_code":    3,
		"":             3,
		"garbage":      3,
	}
	for src, want := range cases {
		if got := TierOf(src); got != want {
			t.Errorf("TierOf(%q) = %d, want %d", src, got, want)
		}
	}
}

func TestRuleEngine_MatchAll(t *testing.T) {
	engine, err := CompileRules([]RuleSpec{
		{Service: "ssh", Pattern: `^SSH-`, Source: "hand"},
		{Service: "http", Pattern: `^HTTP/`, Source: "hand"},
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	got := services(engine.MatchAllBaseline([]byte("SSH-2.0-x\r\n")))
	if len(got) != 1 || got[0] != "ssh" {
		t.Errorf("MatchAllBaseline ssh-only = %v, want [ssh]", got)
	}
	var nilEng *RuleEngine
	if out := nilEng.MatchAllBaseline([]byte("x")); out != nil {
		t.Errorf("nil MatchAllBaseline = %v, want nil", out)
	}
}

func services(in []MatchInfo) []string {
	out := make([]string, 0, len(in))
	for _, m := range in {
		out = append(out, m.Service)
	}
	return out
}
