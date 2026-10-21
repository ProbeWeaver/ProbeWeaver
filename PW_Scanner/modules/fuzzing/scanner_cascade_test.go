package fuzzing

import (
	"testing"

	fingerprint "github.com/zmap/zgrab2/lib/fingerprint"
)

func TestSourceSubPriority(t *testing.T) {
	cases := map[string]int{
		"code": 0, "llm": 1, "deterministic": 2,
		"rf": 3,
		"nmap": 4, "hand": 5, "hand_code": 6,
	}
	for src, want := range cases {
		if got := sourceSubPriority(src); got != want {
			t.Errorf("sourceSubPriority(%q) = %d, want %d", src, got, want)
		}
	}
	if sourceSubPriority("garbage") != 7 {
		t.Errorf("sourceSubPriority(garbage) = %d, want 7", sourceSubPriority("garbage"))
	}
}

func TestDedupSortMatches(t *testing.T) {
	in := []fingerprint.MatchInfo{
		{Service: "mongodb", Source: "hand_code", Tier: 3},
		{Service: "http", Source: "nmap", Tier: 3},
	}
	out := dedupSortMatches(in)
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2 (both kept): %v", len(out), out)
	}
	if out[0].Service != "http" || out[1].Service != "mongodb" {
		t.Errorf("order = %s,%s; want http(=nmap,sub4) before mongodb(=hand_code,sub6)",
			out[0].Service, out[1].Service)
	}

	in2 := []fingerprint.MatchInfo{
		{Service: "amqp", Source: "hand_code", Tier: 3},
		{Service: "amqp", Source: "code", Tier: 1},
	}
	out2 := dedupSortMatches(in2)
	if len(out2) != 1 || out2[0].Source != "code" {
		t.Errorf("dedup amqp = %v, want single [code] (sub min)", out2)
	}

	if got := dedupSortMatches(nil); got != nil {
		t.Errorf("dedupSortMatches(nil) = %v, want nil", got)
	}
}
