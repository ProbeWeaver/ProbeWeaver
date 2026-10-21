// Layer 1 rule engine for service identification.
//
//
//

package fingerprint

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

type RuleSpec struct {
	Service      string `json:"service"`                       // Response identification metadata.
	Pattern      string `json:"pattern,omitempty"`             // Response identification metadata.
	MagicHex     string `json:"magic_hex,omitempty"`           // Response identification metadata.
	Offset       int    `json:"offset,omitempty"`              // Response identification metadata.
	MaskHex      string `json:"mask_hex,omitempty"`            // Response identification metadata.
	MaskValueHex string `json:"mask_value_hex,omitempty"`      // Response identification metadata.
	Type         string `json:"type,omitempty"`                // advisory: banner / magic / offset / mask
	Source       string `json:"source,omitempty"`              // nmap / hand / llm / deterministic
	Desc         string `json:"desc,omitempty"`                // Response identification metadata.
}

type Rule struct {
	RuleSpec
	re        *regexp.Regexp // Response identification metadata.
	magic     []byte         // Response identification metadata.
	offset    int            // Response identification metadata.
	mask      []byte         // Response identification metadata.
	maskValue []byte         // Response identification metadata.
}

type MatchInfo struct {
	Service string `json:"service"`
	Source  string `json:"source"` // code / llm / deterministic / rf / hand / nmap / hand_code
	Tier    int    `json:"tier"`   // 1=Agent code+specific, 2=ML, 3=nmap/hand baseline
}

func TierOf(source string) int {
	switch source {
	case "code", "llm", "deterministic":
		return 1
	case "rf":
		return 2
	default: // hand / nmap / hand_code / ""
		return 3
	}
}

//
type RuleEngine struct {
	rules    []*Rule
	specific []*Rule
	baseline []*Rule
}

func CompileRule(s RuleSpec) (*Rule, error) {
	r := &Rule{RuleSpec: s}
	hasMatcher := false
	if s.Pattern != "" {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return nil, fmt.Errorf("(%s): bad pattern %q: %w", s.Service, s.Pattern, err)
		}
		r.re = re
		hasMatcher = true
	}
	if s.MagicHex != "" {
		b, err := hex.DecodeString(s.MagicHex)
		if err != nil {
			return nil, fmt.Errorf("(%s): bad magic_hex %q: %w", s.Service, s.MagicHex, err)
		}
		r.magic = b
		hasMatcher = true
	}
	if s.Offset < 0 {
		return nil, fmt.Errorf("(%s): negative offset %d", s.Service, s.Offset)
	}
	r.offset = s.Offset
	if s.MaskHex != "" {
		if s.MaskValueHex == "" {
			return nil, fmt.Errorf("(%s): mask_hex without mask_value_hex", s.Service)
		}
		m, err := hex.DecodeString(s.MaskHex)
		if err != nil {
			return nil, fmt.Errorf("(%s): bad mask_hex %q: %w", s.Service, s.MaskHex, err)
		}
		v, err := hex.DecodeString(s.MaskValueHex)
		if err != nil {
			return nil, fmt.Errorf("(%s): bad mask_value_hex %q: %w", s.Service, s.MaskValueHex, err)
		}
		if len(m) != len(v) {
			return nil, fmt.Errorf("(%s): mask_hex (%d) and mask_value_hex (%d) length mismatch", s.Service, len(m), len(v))
		}
		r.mask, r.maskValue = m, v
		hasMatcher = true
	}
	if s.Service == "" || !hasMatcher {
		return nil, fmt.Errorf("service and (pattern or magic_hex) are required")
	}
	return r, nil
}

func CompileRules(specs []RuleSpec) (*RuleEngine, error) {
	rules := make([]*Rule, 0, len(specs))
	for i, s := range specs {
		r, err := CompileRule(s)
		if err != nil {
			return nil, fmt.Errorf("rule #%d: %w", i, err)
		}
		rules = append(rules, r)
	}
	e := &RuleEngine{rules: rules}
	e.partition()
	return e, nil
}

func (e *RuleEngine) partition() {
	e.specific = nil
	e.baseline = nil
	for _, r := range e.rules {
		if isSpecificSource(r.Source) {
			e.specific = append(e.specific, r)
		} else {
			e.baseline = append(e.baseline, r)
		}
	}
	sortBySpecificity := func(rs []*Rule) {
		sort.SliceStable(rs, func(i, j int) bool {
			si, sj := rs[i].specificity(), rs[j].specificity()
			if si != sj {
				return si > sj // Response identification metadata.
			}
			return false // Response identification metadata.
		})
	}
	sortBySpecificity(e.specific)
	sortBySpecificity(e.baseline)
}

func isSpecificSource(source string) bool {
	switch source {
	case "llm", "deterministic":
		return true
	default:
		return false
	}
}

func (r *Rule) specificity() int {
	best := 0
	if r.re != nil {
		pat := r.Pattern
		if strings.HasPrefix(pat, "(?") {
			if idx := strings.Index(pat, ")"); idx >= 0 && idx <= 4 { // (?i)/(?s)/(?is)
				pat = pat[idx+1:]
			}
		}
		pat = strings.TrimPrefix(pat, "^")
		if len(pat) > best {
			best = len(pat)
		}
	}
	if len(r.magic) > best {
		best = len(r.magic)
	}
	if len(r.mask) > best {
		best = len(r.mask)
	}
	return best
}

func (e *RuleEngine) MatchSpecific(resp []byte) (service string, ok bool) {
	if e == nil {
		return "", false
	}
	for _, r := range e.specific {
		if r.matches(resp) {
			return r.Service, true
		}
	}
	return "", false
}

func (e *RuleEngine) MatchBaseline(resp []byte) (service string, ok bool) {
	if e == nil {
		return "", false
	}
	for _, r := range e.baseline {
		if r.matches(resp) {
			return r.Service, true
		}
	}
	return "", false
}

func (e *RuleEngine) MatchAllSpecific(resp []byte) []MatchInfo {
	if e == nil {
		return nil
	}
	return e.matchAll(e.specific, resp)
}

func (e *RuleEngine) MatchAllBaseline(resp []byte) []MatchInfo {
	if e == nil {
		return nil
	}
	return e.matchAll(e.baseline, resp)
}

func (e *RuleEngine) matchAll(rules []*Rule, resp []byte) []MatchInfo {
	if e == nil {
		return nil
	}
	var out []MatchInfo
	seen := map[string]bool{}
	for _, r := range rules {
		if r.matches(resp) {
			if seen[r.Service] {
				continue
			}
			seen[r.Service] = true
			out = append(out, MatchInfo{Service: r.Service, Source: r.Source, Tier: TierOf(r.Source)})
		}
	}
	return out
}

func (r *Rule) matches(resp []byte) bool {
	if r.re != nil && r.re.Match(resp) {
		return true
	}
	if len(r.mask) > 0 {
		o := r.offset
		if o < 0 || o+len(r.mask) > len(resp) {
			return false
		}
		for i := 0; i < len(r.mask); i++ {
			if resp[o+i]&r.mask[i] != r.maskValue[i] {
				return false
			}
		}
		return true
	}
	if len(r.magic) > 0 {
		o := r.offset
		if o < 0 || o+len(r.magic) > len(resp) {
			return false
		}
		return bytes.Equal(resp[o:o+len(r.magic)], r.magic)
	}
	return false
}

func (e *RuleEngine) Match(resp []byte) (service string, ok bool) {
	if e == nil {
		return "", false
	}
	for _, r := range e.rules {
		if r.matches(resp) {
			return r.Service, true
		}
	}
	return "", false
}

func (e *RuleEngine) Len() int {
	if e == nil {
		return 0
	}
	return len(e.rules)
}

func LoadRules(path string) (*RuleEngine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file %q: %w", path, err)
	}
	var specs []RuleSpec
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("parse rules JSON %q: %w", path, err)
	}
	engine, err := CompileRules(specs)
	if err != nil {
		return nil, fmt.Errorf("compile rules %q: %w", path, err)
	}
	return engine, nil
}
