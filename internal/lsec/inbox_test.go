package lsec

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInboxListIncludesPromptUnapprovedAndExcludesBlockedAndApproved(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	hashA := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hashB := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	hashC := "1111111111111111111111111111111111111111111111111111111111111111"
	for _, report := range []RunReport{
		inboxTestReport("run-inbox-open", VerdictPrompt, LaneRisky, "openpkg", hashA),
		inboxTestReport("run-inbox-blocked", VerdictBlock, LaneBlock, "blockedpkg", hashB),
		inboxTestReport("run-inbox-approved", VerdictPrompt, LaneRisky, "approvedpkg", hashC),
	} {
		if err := store.AppendEvent("preflight", report); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.AddApproval(Approval{Ecosystem: "npm", Name: "approvedpkg", Version: "1.0.0", Hash: hashC, Reason: "reviewed"}); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"inbox"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	if !strings.Contains(out, "run-inbox-open") || !strings.Contains(out, "openpkg@1.0.0") {
		t.Fatalf("inbox output = %q, want open prompt run", out)
	}
	for _, excluded := range []string{"run-inbox-blocked", "blockedpkg", "run-inbox-approved", "approvedpkg"} {
		if strings.Contains(out, excluded) {
			t.Fatalf("inbox output = %q, want %q excluded", out, excluded)
		}
	}
}

func TestInboxApproveOnceAddsExactApprovalsAndRefusesBlockedRun(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	hashA := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hashB := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	prompt := inboxTestReport("run-inbox-approve", VerdictPrompt, LaneRisky, "firstpkg", hashA)
	prompt.Artifacts = append(prompt.Artifacts, Artifact{
		Ecosystem: "PyPI",
		Name:      "secondpkg",
		Version:   "2.0.0",
		SHA256:    hashB,
		Kind:      "wheel",
	})
	blocked := inboxTestReport("run-inbox-block-approve", VerdictBlock, LaneBlock, "blockedpkg", hashB)
	for _, report := range []RunReport{prompt, blocked} {
		if err := store.AppendEvent("preflight", report); err != nil {
			t.Fatal(err)
		}
	}

	var stdout strings.Builder
	if err := Run([]string{"inbox", "approve-once", "run-inbox-approve", "reviewed", "locally"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	approvals, err := store.LoadApprovals()
	if err != nil {
		t.Fatal(err)
	}
	if !ArtifactsApproved(approvals, prompt.Artifacts) {
		t.Fatalf("approvals = %#v, want every prompt artifact approved", approvals)
	}
	for _, approval := range approvals {
		if approval.Reason != "reviewed locally" {
			t.Fatalf("approval reason = %q, want joined reason", approval.Reason)
		}
	}
	err = Run([]string{"inbox", "approve-once", "run-inbox-block-approve"}, strings.NewReader(""), &stdout, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("blocked approve-once error = %v, want blocked refusal", err)
	}
}

func TestInboxShowPrintsRedactedEvidence(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := inboxTestReport("run-inbox-show", VerdictPrompt, LaneRisky, "showpkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	report.Analysis.Raw = []string{"pip", "install", "/Users/alice/pkg/sk-abcdefghijklmnopqrstuvwxyz"}
	report.Artifacts[0].Path = "/Users/alice/pkg/dist/showpkg.whl"
	report.Artifacts[0].Dependencies = []DependencyRef{{Raw: "dep @ /Users/alice/dep ghp_abcdefghijklmnopqrstuvwxyz123456"}}
	report.Findings = []Finding{{
		Code:     "secret",
		Severity: "high",
		File:     "/Users/alice/pkg/file.py",
		Message:  "found sk-abcdefghijklmnopqrstuvwxyz",
		Evidence: "marker lsec-canary-openai-api-key",
	}}
	report.Advisories = []Advisory{{
		Source:    "socket",
		ID:        "socket-malware",
		Ecosystem: "npm",
		Name:      "showpkg",
		Version:   "1.0.0",
		Severity:  "critical",
		Type:      "malware",
		Summary:   "advisory mentions /Users/alice/pkg/file.py and lsec-canary-advisory",
		URL:       "file:/Users/alice/pkg/advisory.json?api_key=sk-abcdefghijklmnopqrstuvwxyz",
	}}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"inbox", "show", "run-inbox-show"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	var bundle EvidenceBundle
	if err := json.Unmarshal([]byte(out), &bundle); err != nil {
		t.Fatalf("show output is not EvidenceBundle JSON: %q err=%v", out, err)
	}
	for _, forbidden := range []string{"/Users/", "ghp_", "sk-", "lsec-canary-"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("show output contains %q: %s", forbidden, out)
		}
	}
}

func TestInboxDenyAndViewLaterAppendEventsWithoutApprovals(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("preflight", inboxTestReport("run-inbox-marker", VerdictPrompt, LaneRisky, "markerpkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"inbox", "deny", "run-inbox-marker", "not", "now"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"inbox", "view-later", "run-inbox-marker"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	approvals, err := store.LoadApprovals()
	if err != nil {
		t.Fatal(err)
	}
	if len(approvals) != 0 {
		t.Fatalf("approvals = %#v, want none", approvals)
	}
	body, err := os.ReadFile(paths.Events)
	if err != nil {
		t.Fatal(err)
	}
	log := string(body)
	for _, want := range []string{"inbox_deny", "inbox_view_later", "not now", "inbox-run-inbox-marker"} {
		if !strings.Contains(log, want) {
			t.Fatalf("event log = %q, want %q", log, want)
		}
	}
}

func TestInboxDenyHidesPromptRunFromListButShowStillLoadsReport(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := inboxTestReport("run-inbox-deny", VerdictPrompt, LaneRisky, "denypkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	var before strings.Builder
	if err := Run([]string{"inbox"}, strings.NewReader(""), &before, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(before.String(), "run-inbox-deny") {
		t.Fatalf("inbox output before deny = %q, want prompt run", before.String())
	}
	if err := Run([]string{"inbox", "deny", "run-inbox-deny", "reviewed"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	var after strings.Builder
	if err := Run([]string{"inbox"}, strings.NewReader(""), &after, io.Discard); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(after.String(), "run-inbox-deny") || strings.Contains(after.String(), "denypkg") {
		t.Fatalf("inbox output after deny = %q, want denied run hidden", after.String())
	}
	var show strings.Builder
	if err := Run([]string{"inbox", "show", "run-inbox-deny"}, strings.NewReader(""), &show, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(show.String(), "denypkg") {
		t.Fatalf("show output = %q, want original run report", show.String())
	}
}

func TestInboxViewLaterMarksPromptRunInList(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := inboxTestReport("run-inbox-view-later", VerdictPrompt, LaneRisky, "laterpkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	if err := Run([]string{"inbox", "view-later", "run-inbox-view-later", "after", "review"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	var stdout strings.Builder
	if err := Run([]string{"inbox"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{"run-inbox-view-later", "laterpkg@1.0.0", "view-later", "after review"} {
		if !strings.Contains(out, want) {
			t.Fatalf("inbox output = %q, want %q", out, want)
		}
	}
}

func TestInboxMarkersDoNotShadowRunReports(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := inboxTestReport("run-inbox-shadow", VerdictPrompt, LaneRisky, "shadowpkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"inbox", "deny", "run-inbox-shadow"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"inbox", "view-later", "run-inbox-shadow"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}

	loaded, ok, err := store.LoadRunReport("run-inbox-shadow")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(loaded.Artifacts) != 1 || loaded.Artifacts[0].Name != "shadowpkg" {
		t.Fatalf("loaded report = %#v ok=%v, want original run report after markers", loaded, ok)
	}
	var show strings.Builder
	if err := Run([]string{"inbox", "show", "run-inbox-shadow"}, strings.NewReader(""), &show, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(show.String(), "shadowpkg") {
		t.Fatalf("show output = %q, want original evidence after markers", show.String())
	}
	var list strings.Builder
	if err := Run([]string{"inbox"}, strings.NewReader(""), &list, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list.String(), "run-inbox-shadow") || !strings.Contains(list.String(), "shadowpkg") {
		t.Fatalf("inbox output = %q, want original run listed after markers", list.String())
	}
	var approve strings.Builder
	if err := Run([]string{"inbox", "approve-once", "run-inbox-shadow", "reviewed"}, strings.NewReader(""), &approve, io.Discard); err != nil {
		t.Fatal(err)
	}
	approvals, err := store.LoadApprovals()
	if err != nil {
		t.Fatal(err)
	}
	if !ArtifactsApproved(approvals, report.Artifacts) {
		t.Fatalf("approvals = %#v, want approve-once to approve original artifacts after markers", approvals)
	}
}

func TestInboxListSummarizesOnlyUnapprovedExactArtifacts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	approvedHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	openHash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	report := inboxTestReport("run-inbox-partial", VerdictPrompt, LaneRisky, "approvedpkg", approvedHash)
	report.Artifacts = append(report.Artifacts, Artifact{
		Ecosystem: "npm",
		Name:      "openpkg",
		Version:   "1.0.0",
		SHA256:    openHash,
		Kind:      "tar",
	})
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	if err := store.AddApproval(Approval{Ecosystem: "npm", Name: "approvedpkg", Version: "1.0.0", Hash: approvedHash, Reason: "reviewed"}); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"inbox"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	if !strings.Contains(out, "run-inbox-partial") || !strings.Contains(out, "openpkg@1.0.0") {
		t.Fatalf("inbox output = %q, want run with unapproved artifact", out)
	}
	if strings.Contains(out, "approvedpkg@1.0.0") {
		t.Fatalf("inbox output = %q, want approved artifact omitted from summary", out)
	}
}

func TestInboxApproveOnceRefusesNoAndMalformedArtifacts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	noArtifacts := inboxTestReport("run-inbox-no-artifacts", VerdictPrompt, LaneRisky, "empty", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	noArtifacts.Artifacts = nil
	malformed := inboxTestReport("run-inbox-malformed-artifact", VerdictPrompt, LaneRisky, "badpkg", "not-a-sha")
	for _, report := range []RunReport{noArtifacts, malformed} {
		if err := store.AppendEvent("preflight", report); err != nil {
			t.Fatal(err)
		}
	}

	err = Run([]string{"inbox", "approve-once", "run-inbox-no-artifacts"}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no exact approvable artifacts") {
		t.Fatalf("no-artifacts approve-once error = %v, want refusal", err)
	}
	err = Run([]string{"inbox", "approve-once", "run-inbox-malformed-artifact"}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "malformed artifact identity") {
		t.Fatalf("malformed approve-once error = %v, want refusal", err)
	}
	approvals, err := store.LoadApprovals()
	if err != nil {
		t.Fatal(err)
	}
	if len(approvals) != 0 {
		t.Fatalf("approvals = %#v, want none after refusals", approvals)
	}
}

func TestInboxReviewLLMCallsOllamaCachesAndPrintsEffectiveDecision(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := inboxTestReport("run-inbox-llm", VerdictPrompt, LaneRisky, "llmpkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/generate" {
			t.Fatalf("path = %q, want /api/generate", r.URL.Path)
		}
		bundle := BuildEvidenceBundle(report)
		review := inboxTestLLMReview(bundle.EvidenceSHA256, VerdictBlock)
		body, err := json.Marshal(review)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"response": string(body)})
	}))
	defer server.Close()

	var stdout strings.Builder
	if err := Run([]string{"inbox", "review-llm", "run-inbox-llm", "--model", "test-model", "--base-url", server.URL}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("ollama calls = %d, want 1", calls)
	}
	var out struct {
		RunID             string    `json:"run_id"`
		Cached            bool      `json:"cached"`
		Review            LLMReview `json:"review"`
		EffectiveDecision Decision  `json:"effective_decision"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &out); err != nil {
		t.Fatalf("output is not JSON: %q err=%v", stdout.String(), err)
	}
	if out.RunID != "run-inbox-llm" || out.Cached || out.Review.Verdict != VerdictBlock || out.EffectiveDecision.Verdict != VerdictBlock {
		t.Fatalf("output = %#v, want uncached block review and effective block", out)
	}
}

func TestInboxReviewLLMCacheHitAvoidsHTTP(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := inboxTestReport("run-inbox-llm-cache", VerdictPrompt, LaneRisky, "cachepkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	bundle := BuildEvidenceBundle(report)
	cache, err := DefaultLLMReviewCache()
	if err != nil {
		t.Fatal(err)
	}
	key := LLMCacheKey{Provider: "ollama", Model: "cached-model", Schema: LLMReviewSchema, EvidenceSHA256: bundle.EvidenceSHA256}
	if err := cache.Store(key, inboxTestLLMReview(bundle.EvidenceSHA256, VerdictPrompt)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unexpected HTTP call on cache hit")
	}))
	defer server.Close()

	var stdout strings.Builder
	if err := Run([]string{"inbox", "review-llm", "run-inbox-llm-cache", "--model", "cached-model", "--base-url", server.URL}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"cached": true`) {
		t.Fatalf("output = %q, want cached true", stdout.String())
	}
}

func TestInboxApproveOnceRefusesLatestBlockingLLMReview(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := inboxTestReport("run-inbox-llm-blocks-approve", VerdictPrompt, LaneRisky, "blockpkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	bundle := BuildEvidenceBundle(report)
	if err := store.AppendEvent("llm_review", inboxLLMReviewEvent{
		RunID:             report.RunID,
		Review:            inboxTestLLMReview(bundle.EvidenceSHA256, VerdictBlock),
		EvidenceSHA256:    bundle.EvidenceSHA256,
		Provider:          "ollama",
		Model:             "test-model",
		EffectiveDecision: ApplyLLMReview(report.Decision, inboxTestLLMReview(bundle.EvidenceSHA256, VerdictBlock)),
	}); err != nil {
		t.Fatal(err)
	}

	err = Run([]string{"inbox", "approve-once", report.RunID}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "LLM review blocked") {
		t.Fatalf("approve-once error = %v, want LLM block refusal", err)
	}
}

func TestInboxApproveOnceIgnoresStaleBlockingLLMReviewForChangedEvidence(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := inboxTestReport("run-inbox-llm-stale-review", VerdictPrompt, LaneRisky, "staleoldpkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	oldReview := inboxTestLLMReview(strings.Repeat("a", 64), VerdictBlock)
	if err := store.AppendEvent("llm_review", inboxLLMReviewEvent{
		RunID:             report.RunID,
		Review:            oldReview,
		EvidenceSHA256:    oldReview.EvidenceSHA256,
		Provider:          "ollama",
		Model:             "test-model",
		EffectiveDecision: ApplyLLMReview(report.Decision, oldReview),
	}); err != nil {
		t.Fatal(err)
	}

	err = Run([]string{"inbox", "approve-once", report.RunID}, strings.NewReader(""), io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("approve-once stale LLM review error = %v, want approval", err)
	}
	approvals, err := store.LoadApprovals()
	if err != nil {
		t.Fatal(err)
	}
	if !ArtifactsApproved(approvals, report.Artifacts) {
		t.Fatalf("approvals = %#v, want current artifacts approved", approvals)
	}
}

func TestInboxReviewLLMEventStoresNoRawSplitSecret(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := inboxTestReport("run-inbox-llm-secret", VerdictPrompt, LaneRisky, "secretpkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	report.Analysis.Raw = []string{"npm", "install", "secretpkg", "--token", "sk-abcdefghijklmnopqrstuvwxyz"}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	bundle := BuildEvidenceBundle(report)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		review := inboxTestLLMReview(bundle.EvidenceSHA256, VerdictPrompt)
		body, err := json.Marshal(review)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"response": string(body)})
	}))
	defer server.Close()

	if err := Run([]string{"inbox", "review-llm", report.RunID, "--model", "test-model", "--base-url", server.URL}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(paths.Events)
	if err != nil {
		t.Fatal(err)
	}
	log := string(body)
	if strings.Contains(log, "sk-abcdefghijklmnopqrstuvwxyz") || strings.Contains(log, "Prompt") || strings.Contains(log, "response") {
		t.Fatalf("event log contains raw secret, prompt, or response: %s", log)
	}
	if !strings.Contains(log, "llm_review") || !strings.Contains(log, "[redacted-secret]") {
		t.Fatalf("event log = %q, want sanitized llm_review event", log)
	}
}

func TestLLMReviewEventPersistenceBoundarySanitizesReview(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	review := inboxTestLLMReview(hash, VerdictPrompt)
	review.Reasons = []string{"found /Users/alice/.npmrc ghp_abcdefghijklmnopqrstuvwxyz123456"}
	review.Signals = []string{"sent sk-abcdefghijklmnopqrstuvwxyz lsec-canary-openai-api-key"}
	if err := store.AppendEvent("llm_review", inboxLLMReviewEvent{
		RunID:             "run-boundary-llm-review",
		Review:            review,
		EvidenceSHA256:    hash,
		Provider:          "ollama",
		Model:             "test-model",
		EffectiveDecision: Decision{Verdict: VerdictPrompt, Reasons: review.Reasons},
	}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(paths.Events)
	if err != nil {
		t.Fatal(err)
	}
	log := string(body)
	for _, forbidden := range []string{"/Users/alice", "ghp_", "sk-", "lsec-canary-"} {
		if strings.Contains(log, forbidden) {
			t.Fatalf("event log contains %q: %s", forbidden, log)
		}
	}
	if !strings.Contains(log, "[redacted-secret]") || !strings.Contains(log, "npmrc") {
		t.Fatalf("event log = %s, want redacted LLM review text", log)
	}
}

func TestInboxReviewLLMSanitizesReviewBeforeEventAndCachePersistence(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", filepath.Join(root, ".local-sec"))
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := inboxTestReport("run-inbox-llm-review-secret", VerdictPrompt, LaneRisky, "secretllmpkg", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	bundle := BuildEvidenceBundle(report)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		review := inboxTestLLMReview(bundle.EvidenceSHA256, VerdictPrompt)
		review.Reasons = []string{"saw /Users/alice/.npmrc ghp_abcdefghijklmnopqrstuvwxyz123456"}
		review.Signals = []string{"posted sk-abcdefghijklmnopqrstuvwxyz and lsec-canary-openai-api-key"}
		body, err := json.Marshal(review)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"response": string(body)})
	}))
	defer server.Close()

	if err := Run([]string{"inbox", "review-llm", report.RunID, "--model", "test-model", "--base-url", server.URL}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	eventBody, err := os.ReadFile(paths.Events)
	if err != nil {
		t.Fatal(err)
	}
	cacheBody := readOnlyLLMCacheFile(t, filepath.Join(paths.Root, "cache", "llm-reviews"))
	combined := string(eventBody) + "\n" + string(cacheBody)
	for _, forbidden := range []string{"/Users/alice", "ghp_", "sk-", "lsec-canary-"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("persistent LLM review data contains %q: %s", forbidden, combined)
		}
	}
	if strings.Contains(combined, "prompt") && (strings.Contains(combined, "raw_response") || strings.Contains(combined, `"response"`)) {
		t.Fatalf("persistent LLM review data contains raw prompt or response fields: %s", combined)
	}
	if !strings.Contains(combined, "[redacted-secret]") || !strings.Contains(combined, "npmrc") {
		t.Fatalf("persistent LLM review data = %s, want redacted secret and safe path text", combined)
	}

	cache, err := DefaultLLMReviewCache()
	if err != nil {
		t.Fatal(err)
	}
	key := LLMCacheKey{Provider: "ollama", Model: "test-model", Schema: LLMReviewSchema, EvidenceSHA256: bundle.EvidenceSHA256}
	review, ok, err := cache.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("cache miss, want sanitized cached review")
	}
	if strings.Contains(strings.Join(append(review.Reasons, review.Signals...), "\n"), "/Users/alice") {
		t.Fatalf("cached review = %#v, want sanitized review", review)
	}
}

func TestInboxReviewLLMRejectsNonPositiveTimeout(t *testing.T) {
	for _, timeout := range []string{"0", "-1s"} {
		t.Run(timeout, func(t *testing.T) {
			_, err := parseInboxLLMReviewOptions([]string{"run-id", "--model", "test-model", "--timeout", timeout})
			if err == nil || !strings.Contains(err.Error(), "positive") {
				t.Fatalf("parse timeout error = %v, want positive timeout refusal", err)
			}
		})
	}
}

func readOnlyLLMCacheFile(t *testing.T, root string) []byte {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("cache entries = %d, want 1", len(entries))
	}
	body, err := os.ReadFile(filepath.Join(root, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func inboxTestReport(runID string, verdict Verdict, lane RiskLane, name, hash string) RunReport {
	return RunReport{
		RunID: runID,
		Analysis: CommandAnalysis{
			Raw: []string{"npm", "install", name},
		},
		Decision: Decision{Verdict: verdict, Lane: lane},
		Artifacts: []Artifact{{
			Ecosystem: "npm",
			Name:      name,
			Version:   "1.0.0",
			SHA256:    hash,
			Kind:      "tar",
		}},
	}
}

func inboxTestLLMReview(evidenceSHA256 string, verdict Verdict) LLMReview {
	return LLMReview{
		Schema:         LLMReviewSchema,
		Version:        LLMReviewSchemaVersion,
		EvidenceSHA256: evidenceSHA256,
		Verdict:        verdict,
		Confidence:     "high",
		Reasons:        []string{"review reason"},
		Signals:        []string{"review signal"},
	}
}
