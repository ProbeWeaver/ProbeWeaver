//
// （fingerprint.MatchAllCode / MatchAllSpecific / MatchAllBaseline /
//
// engine_mode = rules_only_tier_cascade：
package fuzzing

import (
	fingerprint "github.com/zmap/zgrab2/lib/fingerprint"
)

type BatchIdentification struct {
	Pred         string                  `json:"pred"`                    // primary predicted cluster（""=unknown）
	Source       string                  `json:"source"`                  // code/llm/deterministic/nmap/hand/hand_code/unknown
	Tier         int                     `json:"tier"`                    // Response identification metadata.
	Matches      []fingerprint.MatchInfo `json:"matches,omitempty"`       // Response identification metadata.
	Candidates   []string                `json:"candidates,omitempty"`    // Response identification metadata.
	Ambiguous    bool                    `json:"ambiguous,omitempty"`     // len(candidates)>1
	Member       string                  `json:"member,omitempty"`        // Response identification metadata.
	MemberSource string                  `json:"member_source,omitempty"` // member_code / unknown / ""(not run)
}

func IdentifyRulesOnly(rules *fingerprint.RuleEngine, resp []byte) BatchIdentification {
	out := BatchIdentification{}
	codeMatches := fingerprint.MatchAllCode(resp)

	var t1 []fingerprint.MatchInfo
	for _, m := range codeMatches {
		if m.Tier == 1 {
			t1 = append(t1, m)
		}
	}
	if rules != nil {
		t1 = append(t1, rules.MatchAllSpecific(resp)...)
	}
	t1 = dedupSortMatches(t1)
	if len(t1) > 0 {
		out.Pred, out.Source, out.Tier, out.Matches = t1[0].Service, t1[0].Source, 1, t1
	} else {
		var t3 []fingerprint.MatchInfo
		if rules != nil {
			t3 = append(t3, rules.MatchAllBaseline(resp)...)
		}
		for _, m := range codeMatches {
			if m.Tier == 3 {
				t3 = append(t3, m)
			}
		}
		t3 = dedupSortMatches(t3)
		if len(t3) > 0 {
			out.Pred, out.Source, out.Tier, out.Matches = t3[0].Service, t3[0].Source, 3, t3
		} else {
			out.Source = "unknown"
		}
	}
	out.Candidates = candidateServices(out.Matches)
	out.Ambiguous = len(out.Candidates) > 1

	if out.Pred != "" && !out.Ambiguous {
		if m, ok := fingerprint.MemberResolveCode(out.Pred, resp); ok {
			out.Member, out.MemberSource = m, "member_code"
		} else {
			out.MemberSource = "unknown"
		}
	}
	return out
}
