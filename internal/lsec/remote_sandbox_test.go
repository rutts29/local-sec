package lsec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRemoteSandboxPrepareStdoutJSONRedactsEvidence(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	seedRawRunEvent(t, pathsFromRoot(root), rawSecretRunReport())

	var stdout bytes.Buffer
	err := Run([]string{"remote-sandbox", "prepare", "run-remote-1"}, strings.NewReader(""), &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	body := stdout.String()
	assertNoRemoteSandboxSecrets(t, body)
	var request RemoteSandboxPrepareRequest
	if err := json.Unmarshal(stdout.Bytes(), &request); err != nil {
		t.Fatalf("stdout is not request JSON: %q err=%v", body, err)
	}
	if request.Schema != remoteSandboxPrepareSchema || request.Version != 1 || !request.Redacted {
		t.Fatalf("request metadata = %#v, want schema/version/redacted", request)
	}
	if request.RunID != "run-remote-1" {
		t.Fatalf("run id = %q, want run-remote-1", request.RunID)
	}
	if request.EvidenceSHA256 == "" || request.EvidenceSHA256 != request.Evidence.EvidenceSHA256 {
		t.Fatalf("evidence hash mismatch: request=%q evidence=%q", request.EvidenceSHA256, request.Evidence.EvidenceSHA256)
	}
	if request.CreatedAt.IsZero() {
		t.Fatal("created_at is zero")
	}
}

func TestRemoteSandboxPrepareMissingRunReturnsError(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)

	err := Run([]string{"remote-sandbox", "prepare", "missing-run"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "run missing-run not found") {
		t.Fatalf("err = %v, want missing run error", err)
	}
}

func TestRemoteSandboxPrepareOutWritesPrivateFile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	seedRawRunEvent(t, pathsFromRoot(root), rawSecretRunReport())
	out := filepath.Join(t.TempDir(), "nested", "request.json")

	var stdout bytes.Buffer
	err := Run([]string{"remote-sandbox", "prepare", "run-remote-1", "--out", out}, strings.NewReader(""), &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty when --out is used", stdout.String())
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 0600", got)
	}
	parent, err := os.Stat(filepath.Dir(out))
	if err != nil {
		t.Fatal(err)
	}
	if got := parent.Mode().Perm(); got != 0o700 {
		t.Fatalf("parent mode = %o, want 0700", got)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertNoRemoteSandboxSecrets(t, string(body))
}

func TestRemoteSandboxPrepareOutRejectsPathWithoutParent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	seedRawRunEvent(t, pathsFromRoot(root), rawSecretRunReport())
	cwd := filepath.Join(t.TempDir(), "cwd")
	if err := os.Mkdir(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalWD); err != nil {
			t.Fatal(err)
		}
	})
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}

	err = Run([]string{"remote-sandbox", "prepare", "run-remote-1", "--out", "request.json"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "directory component") {
		t.Fatalf("err = %v, want directory component error", err)
	}
	info, err := os.Stat(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("cwd mode = %o, want unchanged 0755", got)
	}
}

func TestRemoteSandboxPrepareOutRejectsSharedAbsoluteParent(t *testing.T) {
	for _, parent := range []string{
		filepath.Join(string(filepath.Separator), "tmp"),
		filepath.Join(string(filepath.Separator), "var"),
		filepath.Join(string(filepath.Separator), "private", "tmp"),
		filepath.Join(string(filepath.Separator), "private", "var"),
	} {
		err := validateRemoteSandboxOutputPath("--out", filepath.Join(parent, "request.json"))
		if err == nil || !strings.Contains(err.Error(), "private directory") {
			t.Fatalf("parent %q err = %v, want shared absolute parent error", parent, err)
		}
	}
}

func TestRemoteSandboxPrepareOutRejectsParentTraversalAndLeavesParentModeUnchanged(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	seedRawRunEvent(t, pathsFromRoot(root), rawSecretRunReport())
	parent := filepath.Join(t.TempDir(), "parent")
	cwd := filepath.Join(parent, "cwd")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalWD); err != nil {
			t.Fatal(err)
		}
	})
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}

	err = Run([]string{"remote-sandbox", "prepare", "run-remote-1", "--out", "../request.json"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "directory component without traversal") {
		t.Fatalf("err = %v, want parent traversal error", err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("parent mode = %o, want unchanged 0755", got)
	}
	if _, err := os.Stat(filepath.Join(parent, "request.json")); !os.IsNotExist(err) {
		t.Fatalf("traversal output stat err = %v, want not exist", err)
	}
}

func TestRemoteSandboxPrepareOutRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	seedRawRunEvent(t, pathsFromRoot(root), rawSecretRunReport())
	base := t.TempDir()
	target := filepath.Join(base, "target")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := Run([]string{"remote-sandbox", "prepare", "run-remote-1", "--out", filepath.Join(link, "request.json")}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "path parent must not be a symlink") {
		t.Fatalf("err = %v, want symlink parent error", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("target mode = %o, want unchanged 0755", got)
	}
	if _, err := os.Stat(filepath.Join(target, "request.json")); !os.IsNotExist(err) {
		t.Fatalf("symlink output stat err = %v, want not exist", err)
	}
}

func TestRemoteSandboxPrepareOutRejectsTMPDIRSymlinkParent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	seedRawRunEvent(t, pathsFromRoot(root), rawSecretRunReport())
	base := t.TempDir()
	target := filepath.Join(base, "target")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", filepath.Join(link, "tmp"))
	out := filepath.Join(os.TempDir(), "nested", "request.json")

	err := Run([]string{"remote-sandbox", "prepare", "run-remote-1", "--out", out}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "path parent must not be a symlink") {
		t.Fatalf("err = %v, want TMPDIR symlink parent error", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("target mode = %o, want unchanged 0755", got)
	}
	if _, err := os.Stat(filepath.Join(target, "tmp", "nested", "request.json")); !os.IsNotExist(err) {
		t.Fatalf("TMPDIR symlink output stat err = %v, want not exist", err)
	}
}

func TestRemoteSandboxPrepareOutTightensExistingParent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	seedRawRunEvent(t, pathsFromRoot(root), rawSecretRunReport())
	parent := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(parent, "request.json")

	err := Run([]string{"remote-sandbox", "prepare", "run-remote-1", "--out", out}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("parent mode = %o, want 0700", got)
	}
}

func TestRemoteSandboxSubmitFakeWritesResultAndAppendsSanitizedEvent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	paths := pathsFromRoot(root)
	seedRawRunEvent(t, paths, rawSecretRunReport())
	resultPath := filepath.Join(t.TempDir(), "result.json")

	err := Run([]string{"remote-sandbox", "submit-fake", "run-remote-1", "--result", resultPath}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	resultBody, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	assertNoRemoteSandboxSecrets(t, string(resultBody))
	var result RemoteSandboxResult
	if err := json.Unmarshal(resultBody, &result); err != nil {
		t.Fatalf("result is not JSON: %q err=%v", resultBody, err)
	}
	if result.Schema != remoteSandboxResultSchema || result.Version != 1 || result.Status != RemoteSandboxStatusComplete {
		t.Fatalf("result metadata = %#v, want completed fake result", result)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("fake findings = %#v, want empty by default", result.Findings)
	}

	eventsBody, err := os.ReadFile(paths.Events)
	if err != nil {
		t.Fatal(err)
	}
	events := string(eventsBody)
	remoteEvent := remoteSandboxEventRow(t, events)
	assertNoRemoteSandboxSecrets(t, remoteEvent)
	if !strings.Contains(events, `"kind":"remote_sandbox"`) {
		t.Fatalf("events = %s, want remote_sandbox event", events)
	}
	if strings.Contains(remoteEvent, remoteSandboxPrepareSchema) || strings.Contains(remoteEvent, `"evidence":`) {
		t.Fatalf("event contains raw request/evidence: %s", remoteEvent)
	}
}

func TestRemoteSandboxResultCanRepresentBlockingFinding(t *testing.T) {
	result := RemoteSandboxResult{
		Schema:         remoteSandboxResultSchema,
		Version:        1,
		RunID:          "run-remote-1",
		EvidenceSHA256: strings.Repeat("a", 64),
		Status:         RemoteSandboxStatusComplete,
		Findings: []Finding{{
			Code:     "remote_behavior",
			Severity: "block",
			Message:  "blocked by remote sandbox behavior",
		}},
		CreatedAt: time.Date(2026, 7, 2, 1, 2, 3, 0, time.UTC),
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"severity":"block"`) {
		t.Fatalf("result JSON = %s, want block severity finding", body)
	}
}

func seedRawRunEvent(t *testing.T, paths Paths, report RunReport) {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.Events), 0o700); err != nil {
		t.Fatal(err)
	}
	row := `{"kind":"preflight","json":` + string(body) + `,"created_at":"2026-07-02T01:02:03Z"}` + "\n"
	if err := os.WriteFile(paths.Events, []byte(row), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rawSecretRunReport() RunReport {
	return RunReport{
		RunID: "run-remote-1",
		Analysis: CommandAnalysis{
			Raw: []string{
				"npm", "install", "/Users/alice/project/pkg",
				"--token", "ghp_abcdefghijklmnopqrstuvwxyz123456",
				"--api-key", "sk-abcdefghijklmnopqrstuvwxyz",
				"--canary", "lsec-canary-openai-api-key",
			},
			Manager: "npm",
			Action:  "install",
			PackageSpecs: []PackageSpec{{
				Raw:  "/Users/alice/project/pkg",
				Name: "pkg",
			}},
			RiskFlags: []RiskFlag{{
				Code:     "llm_signal",
				Severity: "prompt",
				Message:  "raw prompt: explain /Users/alice/.npmrc",
				Evidence: "raw response: use ghp_abcdefghijklmnopqrstuvwxyz123456",
			}},
		},
		Artifacts: []Artifact{{
			Path:      "/Users/alice/.local-sec/staging/run-remote-1/pkg.tgz",
			SHA256:    strings.Repeat("b", 64),
			Kind:      "tar",
			Ecosystem: "npm",
			Name:      "pkg",
			Version:   "1.0.0",
		}},
		Findings: []Finding{{
			Code:     "secret_leak",
			Severity: "prompt",
			File:     "/Users/alice/project/pkg/index.js",
			Message:  "raw prompt string",
			Evidence: "raw response string and lsec-canary-npm-token",
		}},
		Sandbox: SandboxEvidence{
			Enabled: true,
			Mode:    "fake-canary",
			FileEvents: []FileEvent{{
				Operation: "read",
				Path:      "/Users/alice/.ssh/id_rsa",
			}},
			CanaryEvents: []CanaryEvent{{
				Kind:   "env",
				Marker: "lsec-canary-github-token",
			}},
			FakeEnvironment: map[string]string{
				"OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz",
			},
		},
		Decision:  Decision{Verdict: VerdictPrompt, Lane: LaneRisky, Reasons: []string{"review /Users/alice/.npmrc"}},
		CreatedAt: time.Date(2026, 7, 2, 1, 2, 3, 0, time.UTC),
	}
}

func assertNoRemoteSandboxSecrets(t *testing.T, body string) {
	t.Helper()
	for _, forbidden := range []string{
		"/Users/alice",
		"ghp_",
		"sk-",
		"lsec-canary-",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz",
		"raw prompt string",
		"raw response string",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("body contains forbidden value %q: %s", forbidden, body)
		}
	}
}

func remoteSandboxEventRow(t *testing.T, events string) string {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(events), "\n") {
		if strings.Contains(line, `"kind":"remote_sandbox"`) {
			return line
		}
	}
	t.Fatalf("events = %s, want remote_sandbox row", events)
	return ""
}

func TestSubmitRemoteSandboxResultRequiresMatchingEvidenceHash(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	paths := pathsFromRoot(root)
	seedRawRunEvent(t, paths, rawSecretRunReport())
	request, err := PrepareRemoteSandboxRequest(NewStore(paths), "run-remote-1", time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	bad := RemoteSandboxResult{
		Schema:         remoteSandboxResultSchema,
		Version:        1,
		RunID:          request.RunID,
		EvidenceSHA256: strings.Repeat("b", 64),
		Status:         RemoteSandboxStatusComplete,
		Findings:       []Finding{{Code: "remote_behavior", Severity: "block", Message: "blocked"}},
		CreatedAt:      time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC),
	}
	body, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(t.TempDir(), "bad-result.json")
	if err := os.WriteFile(resultPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitRemoteSandboxResult(NewStore(paths), "run-remote-1", resultPath, time.Now().UTC()); err == nil {
		t.Fatal("expected evidence hash mismatch error")
	}

	good := bad
	good.EvidenceSHA256 = request.EvidenceSHA256
	body, err = json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	goodPath := filepath.Join(t.TempDir(), "good-result.json")
	if err := os.WriteFile(goodPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := SubmitRemoteSandboxResult(NewStore(paths), "run-remote-1", goodPath, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Severity != "block" {
		t.Fatalf("result = %#v, want sanitized block finding", got)
	}
	report := rawSecretRunReport()
	report.Decision.Verdict = VerdictAllow
	report.Decision.Lane = LaneTrusted
	merged := ApplyRemoteSandboxResult(report, got)
	if merged.Decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %s, want block after remote escalation", merged.Decision.Verdict)
	}
}

func TestApplyRemoteSandboxResultCannotClearLocalBlock(t *testing.T) {
	report := RunReport{
		Analysis: CommandAnalysis{RemoteShell: true, Manager: "curl"},
		Decision: Decision{Verdict: VerdictBlock, Lane: LaneBlock, Reasons: []string{"local block"}},
	}
	result := RemoteSandboxResult{Findings: []Finding{{Code: "remote_ok", Severity: "prompt", Message: "only prompt"}}}
	// Evaluate first so decision is block from policy
	report.Decision = DefaultPolicy().Evaluate(report.Analysis, report.Version, report.Findings, report.Advisories)
	if report.Decision.Verdict != VerdictBlock {
		t.Fatalf("setup verdict = %s, want block", report.Decision.Verdict)
	}
	merged := ApplyRemoteSandboxResult(report, result)
	if merged.Decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %s, want retained local block", merged.Decision.Verdict)
	}
}

func TestNormalizeRemoteSandboxSeverityMapsCriticalToBlock(t *testing.T) {
	got, err := normalizeRemoteSandboxSeverity("critical")
	if err != nil || got != "block" {
		t.Fatalf("critical -> %q err=%v, want block", got, err)
	}
	got, err = normalizeRemoteSandboxSeverity("HIGH")
	if err != nil || got != "block" {
		t.Fatalf("HIGH -> %q err=%v, want block", got, err)
	}
	if _, err := normalizeRemoteSandboxSeverity("allow"); err == nil {
		t.Fatal("expected allow to be rejected")
	}
	if _, err := normalizeRemoteSandboxSeverity("weird"); err == nil {
		t.Fatal("expected unknown severity to be rejected")
	}
}

func TestSanitizeRemoteSandboxFindingsMapsCriticalToBlock(t *testing.T) {
	out := sanitizeRemoteSandboxFindings([]Finding{{Code: "x", Severity: "critical", Message: "bad"}})
	if len(out) != 1 || out[0].Severity != "block" {
		t.Fatalf("out = %#v, want block", out)
	}
}

func TestValidateRemoteSandboxResultRequiresRunID(t *testing.T) {
	req := RemoteSandboxPrepareRequest{RunID: "run-1", EvidenceSHA256: strings.Repeat("a", 64)}
	err := validateRemoteSandboxResult(req, RemoteSandboxResult{
		EvidenceSHA256: req.EvidenceSHA256,
		Findings:       []Finding{{Severity: "block", Message: "x"}},
	})
	if err == nil {
		t.Fatal("expected missing run_id error")
	}
}
