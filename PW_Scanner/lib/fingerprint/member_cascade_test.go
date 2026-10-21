package fingerprint

import "testing"

func TestMemberCascadeGates(t *testing.T) {
	features := make([]float64, len(FeatureNames))
	for _, cluster := range []string{"", "unknown"} {
		if m, _, _ := ResolveMember(cluster, []byte("SSH-2.0-dropbear_2024"), features, true, 0); m != "" {
			t.Fatal("unconfirmed cluster was refined")
		}
	}
	if m, src, _ := ResolveMember("socks5", []byte{5, 255}, features, false, 0); m != "" || src != "unknown" {
		t.Fatal("rules-only mode invoked member RF")
	}
	if m, _, _ := ResolveMember("socks5", []byte{5, 255}, nil, true, 0); m != "" {
		t.Fatal("invalid feature vector invoked RF")
	}
	if m, src, _ := ResolveMember("socks5", []byte{5, 255}, features, true, 0); m == "" || src != "member_rf" {
		t.Fatal("opt-in member RF unavailable")
	}
}
