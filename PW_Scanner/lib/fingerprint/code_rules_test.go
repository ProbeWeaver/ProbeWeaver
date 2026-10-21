package fingerprint

import (
	"bytes"
	"testing"
)

func containsService(out []MatchInfo, svc string) bool {
	for _, m := range out {
		if m.Service == svc {
			return true
		}
	}
	return false
}

func sourceOf(out []MatchInfo, svc string) string {
	for _, m := range out {
		if m.Service == svc {
			return m.Source
		}
	}
	return ""
}

func TestMatchAllCode_Registry(t *testing.T) {
	cases := []struct {
		name string
		resp []byte
		want string // Response identification metadata.
	}{
		{"ssh banner", []byte("SSH-2.0-OpenSSH_8.9p1\r\n"), "ssh"},
		{"amqp magic", []byte("AMQP\x00\x00\x09\x01"), "amqp"},
		{"smb ffSMB", []byte{0xff, 'S', 'M', 'B', 0, 0, 0, 0}, "smb"},
		{"pop3 +OK", []byte("+OK Dovecot ready.\r\n"), "pop3"},
	}
	for _, c := range cases {
		out := MatchAllCode(c.resp)
		if !containsService(out, c.want) {
			t.Errorf("%s: MatchAllCode missing %q (got %v)", c.name, c.want, out)
		}
	}
}

func TestMatchAllCode_NoDedup(t *testing.T) {
	out := MatchAllCode([]byte("AMQP\x00\x00\x09\x01"))
	count := 0
	for _, m := range out {
		if m.Service == "amqp" {
			count++
		}
	}
	if count < 2 {
		t.Errorf("amqp expected ≥2 entries (agent+hand, no dedup), got %d (out=%v)", count, out)
	}
	hasCode, hasHand := false, false
	for _, m := range out {
		if m.Service == "amqp" && m.Source == "code" {
			hasCode = true
		}
		if m.Service == "amqp" && m.Source == "hand_code" {
			hasHand = true
		}
	}
	if !hasCode || !hasHand {
		t.Errorf("amqp expected both code(T1) and hand_code(T3) sources, got code=%v hand=%v", hasCode, hasHand)
	}
}

func TestMatchAllCode_TierTags(t *testing.T) {
	out := MatchAllCode([]byte("AMQP\x00\x00\x09\x01"))
	if src := sourceOf(out, "amqp"); src != "code" && src != "hand_code" {
		t.Errorf("amqp source = %q, want code or hand_code", src)
	}
	for _, m := range out {
		if m.Service == "amqp" && m.Source == "code" && m.Tier != 1 {
			t.Errorf("amqp/code Tier = %d, want 1", m.Tier)
		}
		if m.Service == "amqp" && m.Source == "hand_code" && m.Tier != 3 {
			t.Errorf("amqp/hand_code Tier = %d, want 3", m.Tier)
		}
	}
}

func TestMatchAllCode_NilSafe(t *testing.T) {
	out := MatchAllCode(nil)
	if containsService(out, "ssh") || containsService(out, "amqp") {
		t.Errorf("MatchAllCode(nil) unexpectedly matched known cluster: %v", out)
	}
	out2 := MatchAllCode([]byte{})
	if containsService(out2, "ssh") || containsService(out2, "smb") {
		t.Errorf("MatchAllCode(empty) unexpectedly matched known cluster: %v", out2)
	}
	out3 := MatchAllCode(bytes.Repeat([]byte{0xAB}, 16))
	for _, svc := range []string{"ssh", "amqp", "smb", "pop3"} {
		if containsService(out3, svc) {
			t.Errorf("MatchAllCode(random) unexpectedly matched %q", svc)
		}
	}
}
