package lsec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvidenceBundleKeepsLLMInputSecretFree(t *testing.T) {
	report := RunReport{
		RunID: "run-1",
		Findings: []Finding{{
			Code: "credential_path_reference", File: "setup.py", Message: "path reference only",
		}},
	}

	bundle := BuildEvidenceBundle(report)
	if bundle.RunID != "run-1" {
		t.Fatalf("run id = %q, want run-1", bundle.RunID)
	}
	if bundle.Sandbox.FakeEnvironment != nil {
		t.Fatal("fake environment should not be populated until sandbox evidence exists")
	}
}

func TestEvidenceBundleIncludesDecisionContext(t *testing.T) {
	report := RunReport{
		RunID:    "run-1",
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky, Reasons: []string{"needs review"}},
	}

	body, err := json.Marshal(BuildEvidenceBundle(report))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["decision"].(map[string]any); !ok {
		t.Fatalf("bundle JSON = %s, want decision object", body)
	}
}

func TestEvidenceBundleIncludesStableEvidenceHash(t *testing.T) {
	report := RunReport{
		RunID: "run-1",
		Findings: []Finding{{
			Code: "network_api", File: "setup.py", Message: "network call",
		}},
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky, Reasons: []string{"needs review"}},
	}

	first := evidenceHashFromJSON(t, BuildEvidenceBundle(report))
	second := evidenceHashFromJSON(t, BuildEvidenceBundle(report))
	if first != second {
		t.Fatalf("hashes differ for same evidence: %q vs %q", first, second)
	}

	report.Findings[0].Code = "credential_path_reference"
	changed := evidenceHashFromJSON(t, BuildEvidenceBundle(report))
	if changed == first {
		t.Fatalf("hash did not change after evidence changed: %q", first)
	}
}

func evidenceHashFromJSON(t *testing.T, bundle EvidenceBundle) string {
	t.Helper()

	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	got, _ := doc["evidence_sha256"].(string)
	if !isSHA256Hex(got) {
		t.Fatalf("evidence_sha256 = %q in %s, want 64 hex characters", got, body)
	}
	return got
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		return !('0' <= r && r <= '9') && !('a' <= r && r <= 'f')
	}) == -1
}
