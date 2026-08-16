package lsec

import "testing"

func TestPolicyBlocksRemoteShell(t *testing.T) {
	decision := DefaultPolicy().Evaluate(CommandAnalysis{
		Manager:     "curl",
		RemoteShell: true,
	}, VersionInfo{}, nil)

	if decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %s, want block", decision.Verdict)
	}
}

func TestPolicyPromptsForImmatureVersion(t *testing.T) {
	decision := DefaultPolicy().Evaluate(CommandAnalysis{
		Manager: "npm",
		PackageSpecs: []PackageSpec{{
			Name:    "left-pad",
			Version: "1.3.0",
		}},
	}, VersionInfo{AgeDays: 2, MatureCandidateSelected: false, Found: true}, nil)

	if decision.Verdict != VerdictPrompt {
		t.Fatalf("verdict = %s, want prompt", decision.Verdict)
	}
}

func TestPolicyAssignsRiskLanes(t *testing.T) {
	allow := DefaultPolicy().Evaluate(CommandAnalysis{Manager: "npm"}, VersionInfo{}, nil)
	prompt := DefaultPolicy().Evaluate(CommandAnalysis{Manager: "npm"}, VersionInfo{AgeDays: 2, Found: true}, nil)
	block := DefaultPolicy().Evaluate(CommandAnalysis{Manager: "curl", RemoteShell: true}, VersionInfo{}, nil)

	if allow.Lane != LaneTrusted {
		t.Fatalf("allow lane = %s, want %s", allow.Lane, LaneTrusted)
	}
	if prompt.Lane != LaneRisky {
		t.Fatalf("prompt lane = %s, want %s", prompt.Lane, LaneRisky)
	}
	if block.Lane != LaneBlock {
		t.Fatalf("block lane = %s, want %s", block.Lane, LaneBlock)
	}
}

func TestPolicyDoesNotLetLLMOverrideBlock(t *testing.T) {
	decision := ApplyLLMReview(Decision{Verdict: VerdictBlock}, LLMReview{Verdict: VerdictAllow})

	if decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %s, want block", decision.Verdict)
	}
	if decision.Lane != LaneBlock {
		t.Fatalf("lane = %s, want %s", decision.Lane, LaneBlock)
	}
}
