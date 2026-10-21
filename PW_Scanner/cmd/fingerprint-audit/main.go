// fingerprint-audit checks exported RF and feature parity without network I/O.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"

	fp "github.com/zmap/zgrab2/lib/fingerprint"
)

type record struct {
	ID               string    `json:"id"`
	Request          string    `json:"request"`
	Response         string    `json:"response"`
	Cluster          string    `json:"cluster"`
	Features         []float64 `json:"features"`
	Service          string    `json:"service"`
	Confidence       float64   `json:"confidence"`
	Member           string    `json:"member"`
	MemberConfidence float64   `json:"member_confidence"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 65536), 16<<20)
	n, bad := 0, 0
	maxFeature, maxScore := 0.0, 0.0
	failures := []map[string]interface{}{}
	for scanner.Scan() {
		var r record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			panic(err)
		}
		req, err := hex.DecodeString(r.Request)
		if err != nil {
			panic(err)
		}
		resp, err := hex.DecodeString(r.Response)
		if err != nil {
			panic(err)
		}
		features := fp.ExtractFeaturesWithContext(req, resp)
		if len(features) != len(r.Features) {
			panic("feature width mismatch")
		}
		delta := 0.0
		for i, v := range features {
			delta = math.Max(delta, math.Abs(v-r.Features[i]))
		}
		got := fp.PredictServiceWithConfidence(features, 0)
		member := fp.PredictMember(r.Cluster, features, 0)
		scoreDelta := math.Abs(got.Confidence - r.Confidence)
		if r.Member != "" {
			scoreDelta = math.Max(scoreDelta, math.Abs(member.Confidence-r.MemberConfidence))
		}
		maxFeature = math.Max(maxFeature, delta)
		maxScore = math.Max(maxScore, scoreDelta)
		if delta > 1e-9 || scoreDelta > 1e-8 || got.Service != r.Service || (r.Member != "" && member.Member != r.Member) {
			bad++
			if len(failures) < 20 {
				failures = append(failures, map[string]interface{}{"id": r.ID, "feature_delta": delta, "score_delta": scoreDelta, "service": got.Service, "expected_service": r.Service, "member": member.Member, "expected_member": r.Member})
			}
		}
		n++
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"samples": n, "mismatches": bad, "max_feature_delta": maxFeature, "max_probability_delta": maxScore, "examples": failures}); err != nil {
		panic(err)
	}
	if bad > 0 {
		fmt.Fprintln(os.Stderr, "RF export parity failed")
		os.Exit(1)
	}
}
