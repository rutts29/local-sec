package lsec

import "testing"

func TestSignalVerdicts(t *testing.T) {
	t.Run("risk flags", func(t *testing.T) {
		tests := []struct {
			name     string
			severity string
			want     Verdict
		}{
			{name: "block", severity: "block", want: VerdictBlock},
			{name: "prompt", severity: "prompt", want: VerdictPrompt},
			{name: "empty", want: VerdictAllow},
			{name: "uppercase block is unchanged", severity: "BLOCK", want: VerdictAllow},
			{name: "uppercase prompt is unchanged", severity: "PROMPT", want: VerdictAllow},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := riskFlagVerdict(RiskFlag{Severity: tt.severity}); got != tt.want {
					t.Fatalf("verdict = %s, want %s", got, tt.want)
				}
			})
		}
	})

	t.Run("findings", func(t *testing.T) {
		tests := []struct {
			name     string
			severity string
			want     Verdict
		}{
			{name: "block", severity: "block", want: VerdictBlock},
			{name: "prompt", severity: "prompt", want: VerdictPrompt},
			{name: "empty", want: VerdictAllow},
			{name: "uppercase block is unchanged", severity: "BLOCK", want: VerdictAllow},
			{name: "uppercase prompt is unchanged", severity: "PROMPT", want: VerdictAllow},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := findingVerdict(Finding{Severity: tt.severity}); got != tt.want {
					t.Fatalf("verdict = %s, want %s", got, tt.want)
				}
			})
		}
	})

	t.Run("advisories", func(t *testing.T) {
		tests := []struct {
			name     string
			severity string
			typeName string
			want     Verdict
		}{
			{name: "malware", typeName: "malware", want: VerdictBlock},
			{name: "mixed case malware", typeName: "MaLwArE", want: VerdictBlock},
			{name: "critical", severity: "critical", want: VerdictBlock},
			{name: "mixed case critical", severity: "CrItIcAl", want: VerdictBlock},
			{name: "surrounding whitespace is unchanged", severity: " critical ", want: VerdictPrompt},
			{name: "ordinary advisory", severity: "high", typeName: "vulnerability", want: VerdictPrompt},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				advisory := Advisory{Severity: tt.severity, Type: tt.typeName}
				if got := advisoryVerdict(advisory); got != tt.want {
					t.Fatalf("verdict = %s, want %s", got, tt.want)
				}
			})
		}
	})
}

func TestBlockingSignalQueries(t *testing.T) {
	tests := []struct {
		name       string
		analysis   CommandAnalysis
		findings   []Finding
		advisories []Advisory
		want       bool
		check      func(CommandAnalysis, []Finding, []Advisory) bool
	}{
		{
			name:     "risk flag",
			analysis: CommandAnalysis{RiskFlags: []RiskFlag{{Severity: "BLOCK"}, {Severity: "block"}}},
			want:     true,
			check:    func(analysis CommandAnalysis, _ []Finding, _ []Advisory) bool { return hasBlockingRiskFlag(analysis) },
		},
		{
			name:     "finding",
			findings: []Finding{{Severity: "PROMPT"}, {Severity: "block"}},
			want:     true,
			check:    func(_ CommandAnalysis, findings []Finding, _ []Advisory) bool { return hasBlockingFinding(findings) },
		},
		{
			name:       "advisory",
			advisories: []Advisory{{Severity: "CrItIcAl"}},
			want:       true,
			check: func(_ CommandAnalysis, _ []Finding, advisories []Advisory) bool {
				return hasBlockingAdvisory(advisories)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.check(tt.analysis, tt.findings, tt.advisories); got != tt.want {
				t.Fatalf("blocking = %t, want %t", got, tt.want)
			}
		})
	}
}

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
