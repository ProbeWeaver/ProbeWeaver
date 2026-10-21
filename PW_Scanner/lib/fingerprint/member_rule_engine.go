//

package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type MemberRuleSpec struct {
	RuleSpec
	Member string `json:"member"`
}

type MemberRule struct {
	Rule   *Rule
	Member string
}

type MemberRuleEngine struct {
	byCluster map[string][]*MemberRule
}

//
func (e *MemberRuleEngine) Match(cluster string, resp []byte) (member string, ok bool) {
	if e == nil || e.byCluster == nil {
		return "", false
	}
	for _, mr := range e.byCluster[cluster] {
		if mr.Rule.matches(resp) {
			return mr.Member, true
		}
	}
	return "", false
}

func (e *MemberRuleEngine) Clusters() []string {
	if e == nil {
		return nil
	}
	out := make([]string, 0, len(e.byCluster))
	for c := range e.byCluster {
		out = append(out, c)
	}
	return out
}

func (e *MemberRuleEngine) Len() int {
	if e == nil {
		return 0
	}
	n := 0
	for _, rs := range e.byCluster {
		n += len(rs)
	}
	return n
}

func LoadMemberRules(path string) (*MemberRuleEngine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read member rules file %q: %w", path, err)
	}
	var specs []MemberRuleSpec
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("parse member rules JSON %q: %w", path, err)
	}
	e := &MemberRuleEngine{byCluster: map[string][]*MemberRule{}}
	for i, s := range specs {
		if s.Type == "code" || s.Type == "member_code" {
			continue
		}
		r, err := CompileRule(s.RuleSpec)
		if err != nil {
			return nil, fmt.Errorf("member rule #%d (%s/%s): %w", i, s.Service, s.Member, err)
		}
		if s.Member == "" {
			return nil, fmt.Errorf("member rule #%d (%s): missing member", i, s.Service)
		}
		e.byCluster[s.Service] = append(e.byCluster[s.Service], &MemberRule{Rule: r, Member: s.Member})
	}
	for _, rs := range e.byCluster {
		sort.SliceStable(rs, func(i, j int) bool {
			si, sj := rs[i].Rule.specificity(), rs[j].Rule.specificity()
			if si != sj {
				return si > sj
			}
			return false
		})
	}
	return e, nil
}
