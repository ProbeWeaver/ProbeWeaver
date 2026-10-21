//
package fingerprint

import "sort"

func CodeRuleServices() []string {
	seen := map[string]bool{}
	for _, e := range codeRuleEntries {
		seen[e.Service] = true
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func MemberCodeRuleClusters() map[string][]string {
	out := map[string][]string{}
	for _, e := range memberCodeEntries {
		out[e.Cluster] = append(out[e.Cluster], e.Member)
	}
	for c := range out {
		sort.Strings(out[c])
	}
	return out
}
