package lsec

import (
	"context"
	"testing"
)

func TestSandboxRunnerInterfaceUsesRequestAndResult(t *testing.T) {
	var runner SandboxRunner = sandboxRunnerFunc(func(ctx context.Context, request SandboxRequest) (SandboxResult, error) {
		if request.Mode != SandboxModeFakeCanary {
			t.Fatalf("mode = %q, want %q", request.Mode, SandboxModeFakeCanary)
		}
		return SandboxResult{
			Mode: SandboxModeFakeCanary,
			Findings: []Finding{{
				Code:     "sandbox_observation",
				Severity: "prompt",
				Message:  "sandbox recorded an observation",
			}},
		}, nil
	})

	result, err := runner.RunSandbox(context.Background(), SandboxRequest{Mode: SandboxModeFakeCanary})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != SandboxModeFakeCanary {
		t.Fatalf("mode = %q, want %q", result.Mode, SandboxModeFakeCanary)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one finding", result.Findings)
	}
}

func TestApplySandboxResultBlocksCanaryExfiltration(t *testing.T) {
	report := RunReport{
		Analysis: CommandAnalysis{Manager: "npm"},
		Decision: Decision{Verdict: VerdictAllow, Lane: LaneTrusted},
	}
	result := SandboxResult{
		Mode: SandboxModeFakeCanary,
		Findings: []Finding{{
			Code:     "sandbox_canary_exfiltration",
			Severity: "block",
			Message:  "sandbox observed canary exfiltration",
			Evidence: "OPENAI_API_KEY",
		}},
		Evidence: SandboxEvidence{
			Enabled: true,
			Mode:    string(SandboxModeFakeCanary),
			CanaryEvents: []CanaryEvent{{
				Kind:        "env",
				Marker:      "OPENAI_API_KEY",
				Destination: "https://example.invalid",
			}},
		},
	}

	updated := ApplySandboxResult(report, result)

	if updated.Decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %q, want block; report = %#v", updated.Decision.Verdict, updated)
	}
	if updated.Decision.Lane != LaneBlock {
		t.Fatalf("lane = %q, want block", updated.Decision.Lane)
	}
	if firstFindingSeverity(updated.Findings, "sandbox_canary_exfiltration") != "block" {
		t.Fatalf("findings = %#v, want sandbox_canary_exfiltration block", updated.Findings)
	}
	if !updated.Sandbox.Enabled {
		t.Fatalf("sandbox evidence = %#v, want enabled evidence attached", updated.Sandbox)
	}
	if len(updated.Sandbox.CanaryEvents) != 1 {
		t.Fatalf("canary events = %#v, want one event", updated.Sandbox.CanaryEvents)
	}
}

type sandboxRunnerFunc func(context.Context, SandboxRequest) (SandboxResult, error)

func (f sandboxRunnerFunc) RunSandbox(ctx context.Context, request SandboxRequest) (SandboxResult, error) {
	return f(ctx, request)
}
