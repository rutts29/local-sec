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
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nprintf '%s\\n' \"$@\" >> "+shellQuote(logPath)+"\n")
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
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nprintf '%s\\n' \"$@\" >> "+shellQuote(logPath)+"\n")
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
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nprintf '%s\\n' \"$@\" >> "+shellQuote(logPath)+"\n")
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
	if !strings.Contains(string(body), "VALUES('PyPI','example','1.0.0'") {
		t.Fatalf("sqlite log missing top-level ecosystem:\n%s", string(body))
	}
}

func TestAppendEventPersistsReportAdvisoriesToSQLite(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nprintf '%s\\n' \"$@\" >> "+shellQuote(logPath)+"\n")
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
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nprintf '%s\\n' \"$@\" >> "+shellQuote(logPath)+"\n")
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
	if !strings.Contains(string(body), "VALUES('run-evidence-1','evidence'") {
		t.Fatalf("sqlite log missing evidence run_id:\n%s", string(body))
	}
}

func TestAppendEventPersistsEvidenceBundleDetailsToSQLite(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nprintf '%s\\n' \"$@\" >> "+shellQuote(logPath)+"\n")
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

func TestAddApprovalReplacesExactSQLiteMirror(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nprintf '%s\\n' \"$@\" >> "+shellQuote(logPath)+"\n")
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
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nprintf '%s\\n' \"$@\" >> "+shellQuote(logPath)+"\n")
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
	if !strings.Contains(log, "DELETE FROM approvals") || !strings.Contains(log, "hash='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'") {
		t.Fatalf("sqlite log missing exact-hash approval delete:\n%s", log)
	}
}
