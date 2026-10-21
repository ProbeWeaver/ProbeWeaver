package fuzzing

// Offline identification eval: runs the EXACT Tier-short-circuit cascade
// (same lib/fingerprint calls + same-package dedupSortMatches/sourceSubPriority/
// confidenceThreshold that scanner.go uses) over captured (payload, response)
// pairs from data/results, with NO network scanning. Gated by IDENT_EVAL=1 so
// normal `go test ./modules/fuzzing/` is unaffected.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	fingerprint "github.com/zmap/zgrab2/lib/fingerprint"
)

type evalRecord struct {
	PayloadHex  string         `json:"payload_hex"`
	ResponseHex string         `json:"response_hex"`
	GT          map[string]int `json:"gt"`
}

type evalOutput struct {
	NPairs            int                       `json:"n_pairs"`
	WeightedTotal     int                       `json:"weighted_total"`
	WeightedCorrect   int                       `json:"weighted_correct"`
	Accuracy          float64                   `json:"accuracy"`
	RecallAtK         float64                   `json:"recall_at_k"` // gt appears anywhere in matches[]
	WeightedInMatches int                       `json:"weighted_in_matches"`
	PerSource         map[string]map[string]int `json:"per_source"`
	PerGT             map[string]map[string]int `json:"per_gt"`
	Confusion         map[string]int            `json:"confusion"`
	UnknownWeight     int                       `json:"unknown_weight"`
	TierHit           map[int]map[string]int    `json:"tier_hit"`
	Errors            []map[string]interface{}  `json:"errors"`
}

// identify mirrors scanner.go Stage A exactly (Tier short-circuit, multi-match).
// UseML=true (full three-tier). Returns pred service / source / tier + FULL matches + ML diag.
func identifyOffline(ruleEngine *fingerprint.RuleEngine, payload, resp []byte) (pred, src string, tier int, matches []fingerprint.MatchInfo, mlSvc string, mlConf float64, mlRel bool) {
	codeMatches := fingerprint.MatchAllCode(resp)
	var t1 []fingerprint.MatchInfo
	for _, m := range codeMatches {
		if m.Tier == 1 {
			t1 = append(t1, m)
		}
	}
	if ruleEngine != nil {
		t1 = append(t1, ruleEngine.MatchAllSpecific(resp)...)
	}
	t1 = dedupSortMatches(t1)
	if len(t1) > 0 {
		return t1[0].Service, t1[0].Source, 1, t1, "", 0, false
	}
	// Tier 2: ML (lazy feature extract — identical result to upfront, faster)
	features := fingerprint.ExtractFeaturesWithContext(payload, resp)
	ml := fingerprint.PredictServiceWithConfidence(features, confidenceThreshold)
	if ml.IsReliable {
		m := []fingerprint.MatchInfo{{Service: ml.Service, Source: "rf", Tier: 2}}
		return ml.Service, "rf", 2, m, ml.Service, ml.Confidence, ml.IsReliable
	}
	// Tier 3: 4-form baseline + hand code
	var t3 []fingerprint.MatchInfo
	if ruleEngine != nil {
		t3 = append(t3, ruleEngine.MatchAllBaseline(resp)...)
	}
	for _, m := range codeMatches {
		if m.Tier == 3 {
			t3 = append(t3, m)
		}
	}
	t3 = dedupSortMatches(t3)
	if len(t3) > 0 {
		return t3[0].Service, t3[0].Source, 3, t3, ml.Service, ml.Confidence, ml.IsReliable
	}
	return "", "unknown", 0, nil, ml.Service, ml.Confidence, ml.IsReliable
}

func TestOfflineIdentifyEval(t *testing.T) {
	if os.Getenv("IDENT_EVAL") != "1" {
		t.Skip("set IDENT_EVAL=1 to run offline identification eval")
	}
	inPath := os.Getenv("IDENT_INPUT")
	if inPath == "" {
		inPath = "/tmp/ident_eval_input.json"
	}
	rulesPath := os.Getenv("IDENT_RULES")
	if rulesPath == "" {
		rulesPath = filepath.Join("..", "..", "rules.json")
	}
	outPath := os.Getenv("IDENT_OUTPUT")
	if outPath == "" {
		outPath = "/tmp/ident_eval_output.json"
	}

	raw, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatalf("read input %s: %v", inPath, err)
	}
	var recs []evalRecord
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ruleEngine, err := fingerprint.LoadRules(rulesPath)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	t.Logf("loaded %d rules; %d pairs to evaluate", ruleEngine.Len(), len(recs))

	out := evalOutput{
		PerSource: map[string]map[string]int{},
		PerGT:     map[string]map[string]int{},
		Confusion: map[string]int{},
		TierHit:   map[int]map[string]int{},
		Errors:    []map[string]interface{}{},
	}
	ensure := func(m map[string]map[string]int, k string) map[string]int {
		if _, ok := m[k]; !ok {
			m[k] = map[string]int{"correct": 0, "total": 0}
		}
		return m[k]
	}
	ensureInt := func(m map[int]map[string]int, k int) map[string]int {
		if _, ok := m[k]; !ok {
			m[k] = map[string]int{"correct": 0, "total": 0}
		}
		return m[k]
	}

	for ri, r := range recs {
		resp, err := hex.DecodeString(r.ResponseHex)
		if err != nil || len(resp) == 0 {
			continue
		}
		payload, _ := hex.DecodeString(r.PayloadHex)
		pred, src, tier, matches, mlSvc, mlConf, mlRel := identifyOffline(ruleEngine, payload, resp)
		matchSet := map[string]bool{}
		for _, m := range matches {
			matchSet[m.Service] = true
		}
		n := 0
		for _, c := range r.GT {
			n += c
		}
		out.NPairs++
		out.WeightedTotal += n
		ensure(out.PerSource, src)["total"] += n
		out.PerSource[src]["n_pairs"]++
		ensureInt(out.TierHit, tier)["total"] += n
		if src == "unknown" {
			out.UnknownWeight += n
		}
		for gt, c := range r.GT {
			ensure(out.PerGT, gt)["total"] += c
			if matchSet[gt] {
				out.WeightedInMatches += c
			}
			if pred == gt {
				out.WeightedCorrect += c
				ensure(out.PerGT, gt)["correct"] += c
				ensure(out.PerSource, src)["correct"] += c
				ensureInt(out.TierHit, tier)["correct"] += c
			} else {
				key := fmt.Sprintf("%s->%s", gt, pred)
				out.Confusion[key] += c
				if len(out.Errors) < 300 {
					out.Errors = append(out.Errors, map[string]interface{}{
						"gt": gt, "pred": pred, "source": src, "tier": tier,
						"n": c, "ml_service": mlSvc, "ml_conf": mlConf, "ml_reliable": mlRel,
						"response_hex": r.ResponseHex, "resp_len": len(resp),
						"resp_preview": previewASCII(resp, 80),
					})
				}
			}
		}
		if (ri+1)%5000 == 0 {
			t.Logf("  ...%d/%d pairs", ri+1, len(recs))
		}
	}
	if out.WeightedTotal > 0 {
		out.Accuracy = float64(out.WeightedCorrect) / float64(out.WeightedTotal)
		out.RecallAtK = float64(out.WeightedInMatches) / float64(out.WeightedTotal)
	}

	// top confusion pairs (sorted)
	type cf struct {
		key string
		n   int
	}
	var cfs []cf
	for k, v := range out.Confusion {
		cfs = append(cfs, cf{k, v})
	}
	sort.Slice(cfs, func(i, j int) bool { return cfs[i].n > cfs[j].n })
	t.Logf("=== overall: primary %d/%d = %.4f | recall@k(gt in matches) %d/%d = %.4f | unknown=%d ===",
		out.WeightedCorrect, out.WeightedTotal, out.Accuracy,
		out.WeightedInMatches, out.WeightedTotal, out.RecallAtK, out.UnknownWeight)
	for _, s := range []string{"code", "llm", "deterministic", "rf", "nmap", "hand", "hand_code", "unknown"} {
		if m, ok := out.PerSource[s]; ok {
			acc := 0.0
			if m["total"] > 0 {
				acc = float64(m["correct"]) / float64(m["total"])
			}
			t.Logf("  src=%-12s pairs=%5d  w=%6d  acc=%.4f", s, m["n_pairs"], m["total"], acc)
		}
	}
	for _, tier := range []int{1, 2, 3, 0} {
		if m, ok := out.TierHit[tier]; ok {
			acc := 0.0
			if m["total"] > 0 {
				acc = float64(m["correct"]) / float64(m["total"])
			}
			t.Logf("  tier=%d  w=%6d  acc=%.4f", tier, m["total"], acc)
		}
	}
	t.Logf("top confusion (gt->pred):")
	for i := 0; i < len(cfs) && i < 15; i++ {
		t.Logf("   %3d  %s", cfs[i].n, cfs[i].key)
	}

	buf, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(outPath, buf, 0644); err != nil {
		t.Fatalf("write output: %v", err)
	}
	t.Logf("wrote %s (%d KB)", outPath, len(buf)/1024)
}

func previewASCII(b []byte, max int) string {
	out := make([]byte, 0, max)
	for i := 0; i < len(b) && i < max; i++ {
		c := b[i]
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else if c == '\r' || c == '\n' || c == '\t' {
			out = append(out, '.')
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}
