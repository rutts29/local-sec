package lsec

import "strings"

func DefaultPolicy() Policy {
	return Policy{MaturityDays: 7}
}

func riskFlagVerdict(flag RiskFlag) Verdict {
	switch flag.Severity {
	case "block":
		return VerdictBlock
	case "prompt":
		return VerdictPrompt
	default:
		return VerdictAllow
	}
}

func findingVerdict(finding Finding) Verdict {
	switch finding.Severity {
	case "block":
		return VerdictBlock
	case "prompt":
		return VerdictPrompt
	default:
		return VerdictAllow
	}
}

func advisoryVerdict(advisory Advisory) Verdict {
	if strings.EqualFold(advisory.Type, "malware") || strings.EqualFold(advisory.Severity, "critical") {
		return VerdictBlock
	}
	return VerdictPrompt
}

func hasBlockingRiskFlag(analysis CommandAnalysis) bool {
	for _, flag := range analysis.RiskFlags {
		if riskFlagVerdict(flag) == VerdictBlock {
			return true
		}
	}
	return false
}

func hasBlockingFinding(findings []Finding) bool {
	for _, finding := range findings {
		if findingVerdict(finding) == VerdictBlock {
			return true
		}
	}
	return false
}

func hasBlockingAdvisory(advisories []Advisory) bool {
	for _, advisory := range advisories {
		if advisoryVerdict(advisory) == VerdictBlock {
			return true
		}
	}
	return false
}

func (p Policy) Evaluate(analysis CommandAnalysis, version VersionInfo, findings []Finding, advisories ...[]Advisory) Decision {
	var reasons []string
	verdict := VerdictAllow

	if analysis.RemoteShell {
		return decisionWithLane(VerdictBlock, []string{"remote downloader piped to shell is blocked"})
	}
	for _, finding := range findings {
		switch findingVerdict(finding) {
		case VerdictBlock:
			return decisionWithLane(VerdictBlock, []string{finding.Message})
		case VerdictPrompt:
			verdict = VerdictPrompt
			reasons = append(reasons, finding.Message)
		}
	}
	for _, group := range advisories {
		for _, advisory := range group {
			if advisoryVerdict(advisory) == VerdictBlock {
				return decisionWithLane(VerdictBlock, []string{"known malicious or critical advisory: " + advisory.ID})
			}
			verdict = VerdictPrompt
			reasons = append(reasons, "advisory requires review: "+advisory.ID)
		}
	}
	if version.Found && version.AgeDays >= 0 && version.AgeDays < p.MaturityDays {
		verdict = VerdictPrompt
		reasons = append(reasons, "selected version is inside maturity window")
	}
	for _, flag := range analysis.RiskFlags {
		switch riskFlagVerdict(flag) {
		case VerdictBlock:
			return decisionWithLane(VerdictBlock, []string{flag.Message})
		case VerdictPrompt:
			verdict = VerdictPrompt
			reasons = append(reasons, flag.Message)
		}
	}
	if len(analysis.PackageSpecs) == 0 && analysis.Manager != "" {
		if analysis.Manager == "curl" || analysis.Manager == "wget" {
			verdict = VerdictPrompt
			reasons = append(reasons, "remote downloader command requires review")
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no blocking or prompting signals found")
	}
	return decisionWithLane(verdict, uniqueStrings(reasons))
}

func ApplyLLMReview(decision Decision, review LLMReview) Decision {
	decision.Lane = laneForVerdict(decision.Verdict)
	if decision.Verdict == VerdictBlock {
		return decision
	}
	if decision.Verdict == VerdictAllow && (review.Verdict == VerdictPrompt || review.Verdict == VerdictBlock) {
		decision.Verdict = review.Verdict
		decision.Reasons = append(decision.Reasons, review.Reasons...)
	}
	if decision.Verdict == VerdictPrompt && review.Verdict == VerdictBlock {
		decision.Verdict = VerdictBlock
		decision.Reasons = append(decision.Reasons, review.Reasons...)
	}
	decision.Reasons = uniqueStrings(decision.Reasons)
	decision.Lane = laneForVerdict(decision.Verdict)
	return decision
}

func decisionWithLane(verdict Verdict, reasons []string) Decision {
	return Decision{Verdict: verdict, Lane: laneForVerdict(verdict), Reasons: reasons}
}

func laneForVerdict(verdict Verdict) RiskLane {
	switch verdict {
	case VerdictBlock:
		return LaneBlock
	case VerdictPrompt:
		return LaneRisky
	default:
		return LaneTrusted
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
