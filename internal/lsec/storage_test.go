package lsec

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppendEventConcurrentWritesValidJSONL(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report := RunReport{RunID: NewRunID(time.Now().UTC())}
			if err := store.AppendEvent("test", report); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	f, err := os.Open(store.paths.Events)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var row map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatalf("invalid JSONL row %d: %v", count, err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 20 {
		t.Fatalf("event rows = %d, want 20", count)
	}
}

func TestLoadEventSummariesIncludesScanEvents(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 7, 1, 1, 2, 3, 0, time.UTC)
	summary := ScanSummary{
		Type:            "scan_summary",
		RunID:           "scan-run-1",
		Profile:         "project",
		Backend:         "builtin",
		NetworkMode:     "off",
		Status:          "complete",
		InventoryCount:  2,
		FindingCount:    1,
		DiagnosticCount: 0,
		StartedAt:       started,
		FinishedAt:      started.Add(time.Second),
	}
	if err := store.AppendEvent("scan", summary); err != nil {
		t.Fatal(err)
	}

	events, err := store.LoadEventSummaries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	if events[0].Kind != "scan" || events[0].RunID != "scan-run-1" {
		t.Fatalf("event = %#v, want scan summary event", events[0])
	}
	if !strings.Contains(events[0].Command, "scan --profile project") || !strings.Contains(events[0].Command, "status=complete") {
		t.Fatalf("event command = %q, want scan details", events[0].Command)
	}
}

func TestLoadStatusAggregatesUniqueStructuredScanSummaries(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("preflight", RunReport{
		RunID:    "preflight-run-1",
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("scan", ScanSummary{
		Type:            "scan_summary",
		RunID:           "scan-run-complete",
		Status:          "complete",
		FindingCount:    3,
		DiagnosticCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("scan", ScanSummary{
		Type:            "scan_summary",
		RunID:           "scan-run-complete",
		Status:          "partial",
		FindingCount:    5,
		DiagnosticCount: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("scan", ScanSummary{
		Type:            "scan_summary",
		RunID:           "scan-run-partial",
		Status:          "partial",
		FindingCount:    4,
		DiagnosticCount: 2,
	}); err != nil {
		t.Fatal(err)
	}

	status, err := store.LoadStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Runs != 3 || status.ScanRuns != 2 || status.PartialScanRuns != 2 {
		t.Fatalf("run counts = %#v, want 3 total, 2 scans, 2 partial scans", status)
	}
	if status.ScanFindings != 9 || status.ScanDiagnostics != 4 {
		t.Fatalf("scan counts = %#v, want latest records totaling 9 findings and 4 diagnostics", status)
	}
	if status.Verdicts[VerdictPrompt] != 1 || status.Lanes[LaneRisky] != 1 {
		t.Fatalf("preflight counts = %#v, want prompt/risky unchanged", status)
	}
}

func TestLoadStatusIgnoresInvalidStructuredScanSummaries(t *testing.T) {
	tests := []struct {
		name    string
		invalid ScanSummary
	}{
		{name: "missing type", invalid: ScanSummary{RunID: "scan-run-valid"}},
		{name: "wrong type", invalid: ScanSummary{Type: "legacy_scan", RunID: "scan-run-valid"}},
		{name: "missing run ID", invalid: ScanSummary{Type: "scan_summary"}},
		{name: "negative inventory count", invalid: ScanSummary{Type: "scan_summary", RunID: "scan-run-valid", InventoryCount: -1}},
		{name: "negative finding count", invalid: ScanSummary{Type: "scan_summary", RunID: "scan-run-valid", FindingCount: -1}},
		{name: "negative diagnostic count", invalid: ScanSummary{Type: "scan_summary", RunID: "scan-run-valid", DiagnosticCount: -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewStore(pathsFromRoot(t.TempDir()))
			if err := store.Init(); err != nil {
				t.Fatal(err)
			}
			if err := store.AppendEvent("scan", ScanSummary{
				Type:            "scan_summary",
				RunID:           "scan-run-valid",
				Status:          "complete",
				InventoryCount:  2,
				FindingCount:    3,
				DiagnosticCount: 1,
			}); err != nil {
				t.Fatal(err)
			}
			tt.invalid.Status = "partial"
			if tt.invalid.FindingCount == 0 {
				tt.invalid.FindingCount = 100
			}
			if tt.invalid.DiagnosticCount == 0 {
				tt.invalid.DiagnosticCount = 100
			}
			if err := store.AppendEvent("scan", tt.invalid); err != nil {
				t.Fatal(err)
			}

			status, err := store.LoadStatus()
			if err != nil {
				t.Fatal(err)
			}
			if status.ScanRuns != 1 || status.PartialScanRuns != 0 || status.ScanFindings != 3 || status.ScanDiagnostics != 1 {
				t.Fatalf("scan status = %#v, want only the latest valid summary counted", status)
			}
		})
	}
}

func TestLoadStatusEventSnapshotAggregatesEventsAndScansTogether(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("preflight", RunReport{
		RunID:    "preflight-run-1",
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky},
	}); err != nil {
		t.Fatal(err)
	}
	for _, summary := range []ScanSummary{
		{Type: "scan_summary", RunID: "scan-run-1", Status: "complete", FindingCount: 3, DiagnosticCount: 1},
		{Type: "scan_summary", RunID: "scan-run-1", Status: "partial", FindingCount: 5, DiagnosticCount: 2},
	} {
		if err := store.AppendEvent("scan", summary); err != nil {
			t.Fatal(err)
		}
	}

	snapshot, err := store.loadStatusEventSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(latestEventByRunID(snapshot.events)); got != 2 {
		t.Fatalf("unique event count = %d, want 2", got)
	}
	if snapshot.scans.Runs != 1 || snapshot.scans.PartialRuns != 1 || snapshot.scans.Findings != 5 || snapshot.scans.Diagnostics != 2 {
		t.Fatalf("scan counts = %#v, want latest scan summary from the same snapshot", snapshot.scans)
	}
}

func TestLoadEventSummariesIncludesRemoteSandboxEvents(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	event := remoteSandboxEvent{
		Schema:       remoteSandboxResultSchema,
		Version:      1,
		RunID:        "remote-run-1",
		Status:       RemoteSandboxStatusComplete,
		FindingCount: 2,
		CreatedAt:    time.Date(2026, 7, 2, 1, 2, 3, 0, time.UTC),
		Redacted:     true,
	}
	if err := store.AppendEvent("remote_sandbox", event); err != nil {
		t.Fatal(err)
	}

	events, err := store.LoadEventSummaries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	if events[0].Kind != "remote_sandbox" || events[0].RunID != "remote-run-1" {
		t.Fatalf("event = %#v, want remote_sandbox summary event", events[0])
	}
	if events[0].Command != "remote-sandbox status=complete findings=2" {
		t.Fatalf("event command = %q, want remote sandbox details", events[0].Command)
	}
}

func TestAppendEventPersistsRemoteSandboxRunIDToSQLite(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", fakeSQLiteLogScript(logPath))
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	if err := store.AppendEvent("remote_sandbox", remoteSandboxEvent{RunID: "remote-run-1"}); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "VALUES(@run_id,@kind,@json,@created_at)") || !strings.Contains(string(body), ".parameter set @run_id 'remote-run-1'") {
		t.Fatalf("sqlite log missing remote_sandbox run_id:\n%s", string(body))
	}
}

func TestEventRunIDIncludesNotificationEvents(t *testing.T) {
	planned := NotificationPayload{RunID: "run-planned"}
	if got := eventRunID(planned); got != "run-planned" {
		t.Fatalf("planned notification run id = %q, want run-planned", got)
	}
	sent := NotificationSentEvent{RunID: "run-sent"}
	if got := eventRunID(sent); got != "run-sent" {
		t.Fatalf("sent notification run id = %q, want run-sent", got)
	}
}

func TestLoadRunReportIgnoresScanEvents(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	summary := ScanSummary{
		Type:        "scan_summary",
		RunID:       "scan-run-1",
		Profile:     "project",
		Backend:     "builtin",
		NetworkMode: "off",
		Status:      "complete",
	}
	if err := store.AppendEvent("scan", summary); err != nil {
		t.Fatal(err)
	}

	report, ok, err := store.LoadRunReport("scan-run-1")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("report = %#v, want scan event ignored", report)
	}
}

func TestLoadRunReportIgnoresRemoteSandboxEvents(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	event := remoteSandboxEvent{
		Schema:       remoteSandboxResultSchema,
		Version:      1,
		RunID:        "remote-run-1",
		Status:       RemoteSandboxStatusComplete,
		FindingCount: 1,
		CreatedAt:    time.Date(2026, 7, 2, 1, 2, 3, 0, time.UTC),
		Redacted:     true,
	}
	if err := store.AppendEvent("remote_sandbox", event); err != nil {
		t.Fatal(err)
	}

	report, ok, err := store.LoadRunReport("remote-run-1")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("report = %#v, want remote_sandbox event ignored", report)
	}
}

func TestLoadRunReportLoadsSandboxRunEvents(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	want := RunReport{
		RunID: "sandbox-run-1",
		Analysis: CommandAnalysis{
			Raw: []string{"npm", "install", "example"},
		},
		Decision: Decision{Verdict: VerdictBlock, Lane: LaneBlock, Reasons: []string{"sandbox finding"}},
		Sandbox:  SandboxEvidence{Enabled: true, Mode: "docker"},
	}
	if err := store.AppendEvent("sandbox_run", BuildEvidenceBundle(want)); err != nil {
		t.Fatal(err)
	}

	got, ok, err := store.LoadRunReport("sandbox-run-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("sandbox_run report was not loaded")
	}
	if got.RunID != want.RunID || got.Decision.Verdict != VerdictBlock || got.Sandbox.Mode != "docker" {
		t.Fatalf("report = %#v, want sandbox_run report", got)
	}
}

func TestAdvisoryCacheConcurrentWritesPreserveEntries(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			entry := AdvisoryCacheEntry{
				Ecosystem: "npm",
				Name:      "pkg",
				Version:   string(rune('a' + i)),
				CheckedAt: time.Now().UTC(),
			}
			if err := store.PutAdvisoryCache(entry); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	entries, err := store.LoadAdvisoryCache()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 20 {
		t.Fatalf("cache entries = %d, want 20", len(entries))
	}
}

func TestAppendEventPersistsRunEvidenceToSQLite(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", fakeSQLiteLogScript(logPath))
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report := RunReport{
		RunID: "run-1",
		Analysis: CommandAnalysis{
			Raw:          []string{"pip", "install", "example"},
			PackageSpecs: []PackageSpec{{Raw: "example", Name: "example"}},
		},
		Version: VersionInfo{
			Selected: RegistryVersion{Version: "1.0.0", PublishedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			Latest:   RegistryVersion{Version: "1.0.1"},
			Found:    true,
		},
		Artifacts: []Artifact{{
			Path:      "/tmp/example-1.0.0.whl",
			SHA256:    "sha256-test",
			Kind:      "wheel",
			Ecosystem: "PyPI",
			Name:      "example",
			Version:   "1.0.0",
		}},
		Findings:  []Finding{{Code: "network_api", Severity: "prompt", File: "example.py", Message: "network"}},
		Decision:  Decision{Verdict: VerdictPrompt, Reasons: []string{"needs review"}},
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(body)
	for _, want := range []string{
		"INSERT INTO events",
		"INSERT OR REPLACE INTO artifacts",
		"INSERT OR REPLACE INTO package_versions",
		"INSERT INTO static_findings",
		"INSERT OR REPLACE INTO resolution_decisions",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("sqlite log missing %q:\n%s", want, log)
		}
	}
}

func TestStoreInitCreatesPhase25ScanTables(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", fakeSQLiteLogScript(logPath))
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(body)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS scan_runs",
		"CREATE TABLE IF NOT EXISTS scan_roots",
		"CREATE TABLE IF NOT EXISTS component_observations",
		"CREATE TABLE IF NOT EXISTS scan_findings",
		"CREATE TABLE IF NOT EXISTS finding_evidence",
		"CREATE TABLE IF NOT EXISTS catalog_snapshots",
		"CREATE TABLE IF NOT EXISTS provider_snapshots",
		"CREATE TABLE IF NOT EXISTS remediation_candidates",
		"CREATE TABLE IF NOT EXISTS finding_state",
		"CREATE TABLE IF NOT EXISTS scan_diagnostics",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("sqlite init log missing %q:\n%s", want, log)
		}
	}
}

func TestAppendEventPersistsTopLevelPackageVersionEcosystem(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", fakeSQLiteLogScript(logPath))
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report := RunReport{
		RunID: "run-ecosystem",
		Analysis: CommandAnalysis{
			Manager:      "pip",
			Raw:          []string{"pip", "install", "example"},
			PackageSpecs: []PackageSpec{{Raw: "example", Name: "example"}},
		},
		Version: VersionInfo{
			Selected: RegistryVersion{Version: "1.0.0", PublishedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			Found:    true,
		},
		Decision:  Decision{Verdict: VerdictAllow},
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "INSERT OR REPLACE INTO package_versions") ||
		!strings.Contains(string(body), ".parameter set @ecosystem 'PyPI'") ||
		!strings.Contains(string(body), ".parameter set @name 'example'") ||
		!strings.Contains(string(body), ".parameter set @version '1.0.0'") {
		t.Fatalf("sqlite log missing top-level ecosystem:\n%s", string(body))
	}
}

func TestAppendEventPersistsReportAdvisoriesToSQLite(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", fakeSQLiteLogScript(logPath))
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report := RunReport{
		RunID: "run-advisory",
		Advisories: []Advisory{{
			Source:    "socket",
			ID:        "socket-malware",
			Ecosystem: "npm",
			Name:      "left-pad",
			Version:   "1.3.0",
			Severity:  "critical",
			Type:      "malware",
		}},
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "INSERT INTO advisory_checks") || !strings.Contains(string(body), "socket-malware") {
		t.Fatalf("sqlite log missing report advisory:\n%s", string(body))
	}
}

func TestAppendEventPersistsEvidenceBundleRunIDToSQLite(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", fakeSQLiteLogScript(logPath))
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	bundle := EvidenceBundle{RunID: "run-evidence-1"}
	if err := store.AppendEvent("evidence", bundle); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "VALUES(@run_id,@kind,@json,@created_at)") ||
		!strings.Contains(string(body), ".parameter set @run_id 'run-evidence-1'") ||
		!strings.Contains(string(body), ".parameter set @kind 'evidence'") {
		t.Fatalf("sqlite log missing evidence run_id:\n%s", string(body))
	}
}

func TestAppendEventPersistsEvidenceBundleDetailsToSQLite(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", fakeSQLiteLogScript(logPath))
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	bundle := EvidenceBundle{
		RunID: "run-evidence-2",
		Analysis: CommandAnalysis{
			Raw:          []string{"pip", "install", "example"},
			PackageSpecs: []PackageSpec{{Raw: "example", Name: "example"}},
		},
		Version: VersionInfo{
			Selected: RegistryVersion{Version: "1.0.0", PublishedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			Latest:   RegistryVersion{Version: "1.0.1"},
			Found:    true,
		},
		Artifacts: []Artifact{{
			Path:      "/tmp/example-1.0.0.whl",
			SHA256:    "sha256-test",
			Kind:      "wheel",
			Ecosystem: "PyPI",
			Name:      "example",
			Version:   "1.0.0",
		}},
		Findings: []Finding{{Code: "network_api", Severity: "prompt", File: "example.py", Message: "network"}},
		Decision: Decision{Verdict: VerdictPrompt, Reasons: []string{"needs review"}},
	}
	if err := store.AppendEvent("evidence", bundle); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(body)
	for _, want := range []string{
		"INSERT OR REPLACE INTO artifacts",
		"INSERT INTO static_findings",
		"INSERT OR REPLACE INTO resolution_decisions",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("sqlite log missing %q:\n%s", want, log)
		}
	}
}

func TestAppendEventMirrorsOnlyRedactedEvidenceToSQLite(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", fakeSQLiteLogScript(logPath))
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report := RunReport{
		RunID: "run-redacted-persist",
		Analysis: CommandAnalysis{
			Raw:          []string{"pip", "install", "/Users/alice/project/example", "--token", "ghp_1234567890abcdef1234567890abcdef1234"},
			PackageSpecs: []PackageSpec{{Raw: "/Users/alice/project/example", Name: "example"}},
		},
		Artifacts: []Artifact{{
			Path:      "/Users/alice/.local-sec/staging/run-redacted-persist/example-1.0.0.whl",
			SHA256:    "sha256-redacted",
			Kind:      "wheel",
			Ecosystem: "PyPI",
			Name:      "example",
			Version:   "1.0.0",
		}},
		Findings: []Finding{{
			Code:     "credential_exfil_pattern",
			Severity: "block",
			File:     "/Users/alice/project/example/setup.py",
			Message:  "credential exfiltration",
			Evidence: "posting ghp_1234567890abcdef1234567890abcdef1234 from /Users/alice/.npmrc",
		}},
	}

	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(body)
	for _, forbidden := range []string{
		"/Users/alice",
		"ghp_1234567890abcdef1234567890abcdef1234",
	} {
		if strings.Contains(log, forbidden) {
			t.Fatalf("sqlite log contains unredacted persistence value %q:\n%s", forbidden, log)
		}
	}
	for _, want := range []string{"example-1.0.0.whl", "setup.py", "[redacted-secret]"} {
		if !strings.Contains(log, want) {
			t.Fatalf("sqlite log missing redacted value %q:\n%s", want, log)
		}
	}
}

func TestAddApprovalReplacesExactSQLiteMirror(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", fakeSQLiteLogScript(logPath))
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	approval := Approval{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		Hash:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Reason:    "reviewed",
	}
	if err := store.AddApproval(approval); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(body)
	if !strings.Contains(log, "DELETE FROM approvals") {
		t.Fatalf("sqlite log missing approval replacement delete:\n%s", log)
	}
	if !strings.Contains(log, "INSERT INTO approvals") {
		t.Fatalf("sqlite log missing approval insert:\n%s", log)
	}
}

func TestRevokeApprovalMirrorsSQLiteDeleteWithHash(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", fakeSQLiteLogScript(logPath))
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	if err := store.RevokeApproval("npm", "left-pad", "1.3.0", hash); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(body)
	if !strings.Contains(log, "DELETE FROM approvals") || !strings.Contains(log, ".parameter set @hash '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'") {
		t.Fatalf("sqlite log missing exact-hash approval delete:\n%s", log)
	}
}

func fakeSQLiteLogScript(logPath string) string {
	return "#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + shellQuote(logPath) + "\nif [ -x /bin/cat ]; then\n  /bin/cat >> " + shellQuote(logPath) + "\nelif [ -x /usr/bin/cat ]; then\n  /usr/bin/cat >> " + shellQuote(logPath) + "\nelse\n  while IFS= read -r line; do\n    printf '%s\\n' \"$line\"\n  done >> " + shellQuote(logPath) + "\nfi\n"
}
