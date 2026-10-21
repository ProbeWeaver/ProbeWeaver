package fingerprint

// ResolveMember keeps implementation refinement nested under a confirmed
// cluster. Rules have priority; the new RF fallback is opt-in through useML.
func ResolveMember(cluster string, resp []byte, features []float64, useML bool, threshold float64) (string, string, float64) {
	if cluster == "" || cluster == "unknown" {
		return "", "", 0
	}
	if member, ok := MemberResolveCode(cluster, resp); ok {
		return member, "member_code", 1
	}
	if useML && len(features) == len(FeatureNames) {
		result := PredictMember(cluster, features, threshold)
		if result.IsReliable {
			return result.Member, "member_rf", result.Confidence
		}
	}
	return "", "unknown", 0
}
