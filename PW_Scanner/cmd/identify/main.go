// identify runs the full response cascade over JSONL input without network traffic.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	fp "github.com/zmap/zgrab2/lib/fingerprint"
)

type observation struct {
	Transport   string `json:"transport"`
	Phase       string `json:"phase"`
	PayloadHex  string `json:"payload_hex"`
	ResponseHex string `json:"response_hex"`
}

type prediction struct {
	observation
	Pred             string         `json:"pred"`
	Source           string         `json:"source"`
	Tier             int            `json:"tier"`
	Matches          []fp.MatchInfo `json:"matches"`
	Candidates       []string       `json:"candidates"`
	Ambiguous        bool           `json:"ambiguous"`
	MLService        string         `json:"ml_service,omitempty"`
	MLConfidence     float64        `json:"ml_confidence,omitempty"`
	MLReliable       bool           `json:"ml_reliable"`
	Member           string         `json:"member,omitempty"`
	MemberSource     string         `json:"member_source,omitempty"`
	MemberConfidence float64        `json:"member_confidence,omitempty"`
	Version          string         `json:"version,omitempty"`
	VersionSource    string         `json:"version_source,omitempty"`
}

// Same ordering as modules/fuzzing/scanner.go; guarded by offline parity tests.
func priority(source string) int {
	for i, s := range []string{"code", "llm", "deterministic", "rf", "nmap", "hand", "hand_code"} {
		if s == source {
			return i
		}
	}
	return 7
}

func ordered(matches []fp.MatchInfo) []fp.MatchInfo {
	best := map[string]fp.MatchInfo{}
	for _, m := range matches {
		if old, ok := best[m.Service]; !ok || priority(m.Source) < priority(old.Source) {
			best[m.Service] = m
		}
	}
	out := []fp.MatchInfo{}
	for _, m := range best {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if priority(out[i].Source) != priority(out[j].Source) {
			return priority(out[i].Source) < priority(out[j].Source)
		}
		return out[i].Service < out[j].Service
	})
	return out
}

func identify(rules *fp.RuleEngine, o observation, threshold, memberThreshold float64) (prediction, error) {
	out := prediction{observation: o, Source: "unknown", Matches: []fp.MatchInfo{}, Candidates: []string{}}
	if o.Transport != "tcp" && o.Transport != "udp" {
		return out, fmt.Errorf("transport must be tcp or udp")
	}
	if o.Phase != "banner" && o.Phase != "post_payload" {
		return out, fmt.Errorf("phase must be banner or post_payload")
	}
	if o.Transport == "udp" && o.Phase == "banner" {
		return out, fmt.Errorf("UDP has no pre-payload banner")
	}
	payload, err := hex.DecodeString(o.PayloadHex)
	if err != nil {
		return out, fmt.Errorf("payload_hex: %w", err)
	}
	resp, err := hex.DecodeString(o.ResponseHex)
	if err != nil {
		return out, fmt.Errorf("response_hex: %w", err)
	}
	if o.Phase == "banner" && len(payload) != 0 {
		return out, fmt.Errorf("banner request context must be empty")
	}
	// Empty reads are not classified by the non-TLS runtime either. Never strip
	// echoes or shared prefixes: the RF already uses request/response features.
	if len(resp) == 0 {
		return out, nil
	}
	features := fp.ExtractFeaturesWithContext(payload, resp)
	code := fp.MatchAllCode(resp)
	t1 := rules.MatchAllSpecific(resp)
	for _, m := range code {
		if m.Tier == 1 {
			t1 = append(t1, m)
		}
	}
	out.Matches = ordered(t1)
	if len(out.Matches) == 0 {
		ml := fp.PredictServiceWithConfidence(features, threshold)
		out.MLService, out.MLConfidence, out.MLReliable = ml.Service, ml.Confidence, ml.IsReliable
		if ml.IsReliable {
			out.Matches = []fp.MatchInfo{{Service: ml.Service, Source: "rf", Tier: 2}}
		}
	}
	if len(out.Matches) == 0 {
		t3 := rules.MatchAllBaseline(resp)
		for _, m := range code {
			if m.Tier == 3 {
				t3 = append(t3, m)
			}
		}
		out.Matches = ordered(t3)
	}
	if len(out.Matches) > 0 {
		out.Pred, out.Source, out.Tier = out.Matches[0].Service, out.Matches[0].Source, out.Matches[0].Tier
	}
	seen := map[string]bool{}
	for _, m := range out.Matches {
		for _, c := range fp.IdentificationCandidates(m.Service) {
			if c != "" && !seen[c] {
				seen[c] = true
				out.Candidates = append(out.Candidates, c)
			}
		}
	}
	sort.Strings(out.Candidates)
	out.Ambiguous = len(out.Candidates) > 1
	if out.Pred != "" && !out.Ambiguous {
		out.Member, out.MemberSource, out.MemberConfidence = fp.ResolveMember(out.Pred, resp, features, true, memberThreshold)
	}
	if out.Member != "" && fp.IsBannerProtocol(out.Pred) {
		if v, ok := fp.ExtractVersion(out.Pred, resp); ok {
			out.Version, out.VersionSource = v, "extractor"
		} else {
			out.VersionSource = "unknown"
		}
	}
	return out, nil
}

func run() error {
	rulesPath := flag.String("rules", "rules.json", "Generic fallback rules JSON")
	threshold := flag.Float64("threshold", 0.7, "Service RF confidence threshold")
	memberThreshold := flag.Float64("member-threshold", 0.6, "Implementation RF confidence threshold")
	flag.Parse()
	raw, err := os.ReadFile(*rulesPath)
	if err != nil {
		return err
	}
	var specs []fp.RuleSpec
	if err := json.Unmarshal(raw, &specs); err != nil {
		return err
	}
	rules, err := fp.CompileRules(specs)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 65536), 64<<20)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var req struct {
			Responses []observation `json:"responses"`
		}
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields() // truth labels must never enter the classifier
		err := decoder.Decode(&req)
		if err == nil {
			var extra interface{}
			if decoder.Decode(&extra) != io.EOF {
				err = fmt.Errorf("trailing JSON")
			}
		}
		results := []prediction{}
		if err == nil {
			for _, o := range req.Responses {
				var p prediction
				p, err = identify(rules, o, *threshold, *memberThreshold)
				if err != nil {
					break
				}
				results = append(results, p)
			}
		}
		if err != nil {
			if err := encoder.Encode(map[string]string{"error": err.Error()}); err != nil {
				return err
			}
		} else if err := encoder.Encode(map[string]interface{}{"results": results}); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
