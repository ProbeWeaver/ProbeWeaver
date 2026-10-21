package fuzzing

// Distinguishability batch harness (P1-7): runs the scanner-exact rules-only
// cascade (IdentifyRulesOnly, same lib/fingerprint calls + same-package
// dedupSortMatches/sourceSubPriority that scanner.go uses) over a JSONL of
// responses, with NO network scanning. Gated by DISTINGUISH_BATCH=1 (pattern
// copied from IDENT_EVAL) so normal `go test ./modules/fuzzing/` is unaffected.
//
// Env contract (invoked by scripts/evaluate_distinguishability.py):
//
//	DISTINGUISH_BATCH=1            enable
//	DISTINGUISH_INPUT=<path>       input JSONL: {"id": "...", "response_hex": "..."}
//	DISTINGUISH_OUTPUT=<path>      output JSONL: {"id","pred","source","tier",
//	                               "matches":[{"service","source","tier"}],
//	                               "member","member_source"}
//	DISTINGUISH_META=<path>        engine meta JSON: {"engine_mode",
//	                               "code_rule_services", "member_code_rule_clusters"}
//	DISTINGUISH_RULES=<path>       optional rules.json (same file runtime loads)

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	fingerprint "github.com/zmap/zgrab2/lib/fingerprint"
)

type batchInputRecord struct {
	ID          string `json:"id"`
	ResponseHex string `json:"response_hex"`
}

func TestDistinguishBatchHarness(t *testing.T) {
	if os.Getenv("DISTINGUISH_BATCH") != "1" {
		t.Skip("set DISTINGUISH_BATCH=1 to enable the distinguishability harness")
	}
	inPath := os.Getenv("DISTINGUISH_INPUT")
	outPath := os.Getenv("DISTINGUISH_OUTPUT")
	metaPath := os.Getenv("DISTINGUISH_META")
	if inPath == "" || outPath == "" || metaPath == "" {
		t.Fatal("DISTINGUISH_INPUT / DISTINGUISH_OUTPUT / DISTINGUISH_META are required")
	}

	var rules *fingerprint.RuleEngine
	if rulesPath := os.Getenv("DISTINGUISH_RULES"); rulesPath != "" {
		engine, err := fingerprint.LoadRules(rulesPath)
		if err != nil {
			t.Fatalf("failed to load rules %s: %v", rulesPath, err)
		}
		rules = engine
		t.Logf("loaded %d rules from %s", engine.Len(), rulesPath)
	}

	inFile, err := os.Open(inPath)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create output: %v", err)
	}
	defer outFile.Close()

	writer := bufio.NewWriterSize(outFile, 1<<20)
	enc := json.NewEncoder(writer)
	scanner := bufio.NewScanner(inFile)
	scanner.Buffer(make([]byte, 0, 1<<20), 32<<20) // Response identification metadata.

	n := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec batchInputRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("bad input line %d: %v", n, err)
		}
		resp, err := hex.DecodeString(rec.ResponseHex)
		if err != nil {
			t.Fatalf("bad response_hex on line %d: %v", n, err)
		}
		result := IdentifyRulesOnly(rules, resp)
		out := map[string]interface{}{
			"id":            rec.ID,
			"pred":          result.Pred,
			"source":        result.Source,
			"tier":          result.Tier,
			"matches":       result.Matches,
			"candidates":    result.Candidates,
			"ambiguous":     result.Ambiguous,
			"member":        result.Member,
			"member_source": result.MemberSource,
		}
		if err := enc.Encode(out); err != nil {
			t.Fatalf("encode output line %d: %v", n, err)
		}
		n++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan input: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("flush output: %v", err)
	}

	meta := map[string]interface{}{
		"engine_mode":               "rules_only_tier_cascade",
		"code_rule_services":        fingerprint.CodeRuleServices(),
		"member_code_rule_clusters": fingerprint.MemberCodeRuleClusters(),
		"n_responses":               n,
	}
	metaBlob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(metaPath, metaBlob, 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	t.Logf("identified %d responses -> %s (meta %s)", n, outPath, metaPath)
}

func TestIdentifyRulesOnlyCascadeSemantics(t *testing.T) {
	amqpResp := []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}
	got := IdentifyRulesOnly(nil, amqpResp)
	if got.Pred != "amqp" || got.Tier != 1 || got.Source != "code" {
		t.Fatalf("tier1 short-circuit failed: %+v", got)
	}
	if len(got.Candidates) != 1 || got.Candidates[0] != "amqp" || got.Ambiguous {
		t.Fatalf("single-label candidates failed: %+v", got)
	}

	rules, err := fingerprint.CompileRules([]fingerprint.RuleSpec{
		{Service: "zzz-hand", Pattern: "^AMQP", Source: "hand"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got = IdentifyRulesOnly(rules, amqpResp)
	if got.Pred != "amqp" || got.Tier != 1 {
		t.Fatalf("tier1 must short-circuit tier3: %+v", got)
	}

	rules2, err := fingerprint.CompileRules([]fingerprint.RuleSpec{
		{Service: "aaa-hand", Pattern: "^XYZQ", Source: "hand"},
		{Service: "zzz-nmap", Pattern: "^XYZQ", Source: "nmap"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got = IdentifyRulesOnly(rules2, []byte("XYZQ----"))
	if got.Pred != "zzz-nmap" || got.Tier != 3 || got.Source != "nmap" {
		t.Fatalf("same-tier primary ordering failed: %+v", got)
	}
	if len(got.Matches) != 2 {
		t.Fatalf("same-tier multi-match must keep all matches: %+v", got.Matches)
	}
	if len(got.Candidates) != 2 || !got.Ambiguous {
		t.Fatalf("multi-match candidates must be explicit: %+v", got)
	}

	got = IdentifyRulesOnly(rules2, []byte("\x01\x02\x03\x04"))
	if got.Pred != "" || got.Source != "unknown" || got.Member != "" || got.MemberSource != "" {
		t.Fatalf("unknown semantics failed: %+v", got)
	}

	rules3, err := fingerprint.CompileRules([]fingerprint.RuleSpec{
		{Service: "ftp", Pattern: "^220", Source: "hand"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got = IdentifyRulesOnly(rules3, []byte("220 Pure-FTPd Server ready."))
	if got.Pred != "ftp" || got.Tier != 1 || got.Source != "code" {
		t.Fatalf("ftp tier1 (compiled code rule) failed: %+v", got)
	}
	if got.Member != "ftp-pure-ftpd" || got.MemberSource != "member_code" {
		t.Fatalf("stage B member_code failed: %+v", got)
	}

	rules4, err := fingerprint.CompileRules([]fingerprint.RuleSpec{
		{Service: "zzz-hand", Pattern: "^ZZQQ", Source: "hand"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got = IdentifyRulesOnly(rules4, []byte("ZZQQ-no-member-rules"))
	if got.Pred != "zzz-hand" || got.Tier != 3 || got.Source != "hand" {
		t.Fatalf("zzz-hand tier3 failed: %+v", got)
	}
	if got.Member != "" || got.MemberSource != "unknown" {
		t.Fatalf("stage B ran-but-unresolved semantics failed: %+v", got)
	}
	got = IdentifyRulesOnly(rules4, []byte("garbage-matches-nothing"))
	if got.Pred != "" || got.MemberSource != "" || got.Member != "" {
		t.Fatalf("stage B must not run when cluster unknown: %+v", got)
	}
}

func TestIdentificationEquivalenceCandidates(t *testing.T) {
	candidates := candidateServices([]fingerprint.MatchInfo{{
		Service: "mqtt", Source: "code", Tier: 1,
	}})
	if len(candidates) != 2 || candidates[0] != "mqttv311" || candidates[1] != "mqttv50" {
		t.Fatalf("mqtt canonical label must expand to both probe-service candidates: %v", candidates)
	}
	candidates = candidateServices([]fingerprint.MatchInfo{
		{Service: "ssh", Source: "code", Tier: 1},
		{Service: "redis", Source: "code", Tier: 1},
	})
	if len(candidates) != 2 || candidates[0] != "redis" || candidates[1] != "ssh" {
		t.Fatalf("cross-group candidates were not preserved: %v", candidates)
	}
}

// TestIdentifyRulesOnlyPhaseAgnosticInput verifies the scanner's intentional
// public contract: Banner bytes, post-payload bytes, or their concatenation
// are all handed to the same cluster/member cascade.  Phase metadata is a
// local training/evaluation concern and is never a runtime match condition.
func TestIdentifyRulesOnlyPhaseAgnosticInput(t *testing.T) {
	rules, err := fingerprint.CompileRules([]fingerprint.RuleSpec{
		{Service: "zzz-phase-compatible", Pattern: "BANNER-ALPHA", Source: "hand"},
		{Service: "zzz-phase-compatible", Pattern: "POST-OMEGA", Source: "hand"},
	})
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]byte{
		"banner":       []byte("BANNER-ALPHA"),
		"post":         []byte("POST-OMEGA"),
		"concatenated": []byte("BANNER-ALPHA\r\nPOST-OMEGA"),
	}
	for name, response := range inputs {
		t.Run(name, func(t *testing.T) {
			got := IdentifyRulesOnly(rules, response)
			if got.Pred != "zzz-phase-compatible" || got.Tier != 3 {
				t.Fatalf("same cascade must accept %s response bytes: %+v", name, got)
			}
		})
	}
}
