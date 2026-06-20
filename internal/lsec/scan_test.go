package lsec

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunScanProjectInventoriesMetadataAndWritesBundle(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "demo", "version": "0.1.0"},
			"node_modules/left-pad": {
				"version": "1.3.0",
				"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
				"integrity": "sha512-test",
				"dev": true
			}
		}
	}`)
	writeFile(t, filepath.Join(project, ".venv", "lib", "python3.13", "site-packages", "requests-2.32.5.dist-info", "METADATA"), "Metadata-Version: 2.3\nName: requests\nVersion: 2.32.5\n")
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasScanObservation(records, "npm", "left-pad", "1.3.0", "declared") {
		t.Fatalf("records = %#v, want declared npm left-pad observation", records)
	}
	if !hasScanObservation(records, "PyPI", "requests", "2.32.5", "installed") {
		t.Fatalf("records = %#v, want installed PyPI requests observation", records)
	}
	summary := scanSummaryRecord(t, records)
	if summary["status"] != "complete" {
		t.Fatalf("summary status = %v, want complete", summary["status"])
	}
	runID, _ := summary["run_id"].(string)
	if runID == "" {
		t.Fatalf("summary = %#v, want run_id", summary)
	}
	for _, name := range []string{"inventory.ndjson", "findings.ndjson", "diagnostics.ndjson", "summary.json", "provider-snapshots.json", "catalog-snapshots.json", "report.txt"} {
		if _, err := os.Stat(filepath.Join(lsecHome, "scans", runID, name)); err != nil {
			t.Fatalf("scan bundle missing %s: %v", name, err)
		}
	}
}

func TestRunScanDoesNotEmitMCPSecrets(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, ".mcp.json"), `{
		"mcpServers": {
			"danger": {
				"command": "npx",
				"args": ["-y", "@example/server@1.2.3", "--token", "SECRET_TOKEN"],
				"env": {"GITHUB_TOKEN": "SECRET_TOKEN"}
			}
		}
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	if strings.Contains(out, "SECRET_TOKEN") || strings.Contains(out, "GITHUB_TOKEN") {
		t.Fatalf("scan output leaked MCP secret material: %s", out)
	}
	if !strings.Contains(out, `"presence":"configured"`) || !strings.Contains(out, `"@example/server"`) {
		t.Fatalf("scan output = %s, want sanitized configured MCP package observation", out)
	}
	records := parseNDJSONRecords(t, out)
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	for _, name := range []string{"inventory.ndjson", "diagnostics.ndjson", "findings.ndjson", "summary.json"} {
		body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "SECRET_TOKEN") || strings.Contains(string(body), "GITHUB_TOKEN") {
			t.Fatalf("%s leaked MCP secret material: %s", name, string(body))
		}
	}
}

func TestRunScanInventoriesHomebrewAndEditorExtensions(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "Cellar", "wget", "1.25.0", "INSTALL_RECEIPT.json"), `{"source":{"tap":"homebrew/core"}}`)
	writeFile(t, filepath.Join(project, ".vscode", "extensions", "publisher.tool-1.2.3", "package.json"), `{
		"publisher":"publisher",
		"name":"tool",
		"version":"1.2.3"
	}`)
	writeFile(t, filepath.Join(project, ".cursor", "extensions", "cursor.publisher-2.0.0", "package.json"), `{
		"publisher":"cursor",
		"name":"publisher",
		"version":"2.0.0"
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasScanObservation(records, "Homebrew", "wget", "1.25.0", "installed") {
		t.Fatalf("records = %#v, want Homebrew formula observation", records)
	}
	if !hasScanObservation(records, "vscode-extension", "publisher.tool", "1.2.3", "configured") {
		t.Fatalf("records = %#v, want editor extension observation", records)
	}
	if !hasScanObservation(records, "vscode-extension", "cursor.publisher", "2.0.0", "configured") {
		t.Fatalf("records = %#v, want Cursor extension observation", records)
	}
}

func TestRunScanFindingsOnlyOmitsObservationsFromOutput(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, ".claude", "setup.mjs"), "placeholder")
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson", "--findings-only"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if hasRecordType(records, "observation") {
		t.Fatalf("records = %#v, findings-only output should omit observations", records)
	}
	if !hasScanFinding(records, "BUILTIN-AGENT-SETUP-MJS", "host_ioc", "critical-immediate") {
		t.Fatalf("records = %#v, want host IOC finding", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "inventory.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(body))) != 0 {
		t.Fatalf("inventory bundle = %s, expected no observations for host-only IOC", string(body))
	}
}

func TestRunScanRedactsHomePathsInOutputOnly(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	sourcePath := filepath.Join(project, "package-lock.json")
	writeFile(t, sourcePath, `{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/left-pad": {"version": "1.3.0"}
		}
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson", "--redact-paths", "home"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), sourcePath) {
		t.Fatalf("scan output leaked full home path: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "~/project/package-lock.json") {
		t.Fatalf("scan output = %s, want home-relative redacted path", stdout.String())
	}
	records := parseNDJSONRecords(t, stdout.String())
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "inventory.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), sourcePath) {
		t.Fatalf("canonical inventory bundle should retain local path, got %s", string(body))
	}
}

func TestRunScanMatchesLocalExposureCatalog(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	catalog := filepath.Join(root, "catalog.json")
	writeFile(t, filepath.Join(project, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/evil": {"version": "9.9.9"}
		}
	}`)
	writeFile(t, catalog, `{
		"entries": [{
			"id": "CAMPAIGN-2026-X",
			"ecosystem": "npm",
			"name": "evil",
			"version": "9.9.9",
			"class": "malicious_package",
			"severity": "critical",
			"urgency": "critical-immediate",
			"title": "known malicious test package"
		}]
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--catalog", catalog, "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasScanFinding(records, "CAMPAIGN-2026-X", "malicious_package", "critical-immediate") {
		t.Fatalf("records = %#v, want catalog malware finding", records)
	}
	summary := scanSummaryRecord(t, records)
	if summary["finding_count"].(float64) != 1 {
		t.Fatalf("summary = %#v, want one finding", summary)
	}
	runID, _ := summary["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "catalog-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasSnapshot(body, "source", catalog, "signature_status", "unsigned-explicit") {
		t.Fatalf("catalog snapshots = %s, want explicit unsigned catalog snapshot", string(body))
	}
}

func TestRunScanMatchesHostIOCCatalogPath(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	iocPath := filepath.Join(project, ".claude", "setup.mjs")
	catalog := filepath.Join(root, "catalog.json")
	writeFile(t, iocPath, "placeholder")
	writeFile(t, catalog, `{
		"entries": [{
			"id": "HOST-IOC-SETUP-MJS",
			"known_file_path": ".claude/setup.mjs",
			"class": "host_ioc",
			"severity": "critical",
			"urgency": "critical-immediate",
			"title": "known agent persistence file"
		}]
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--catalog", catalog, "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasScanFinding(records, "HOST-IOC-SETUP-MJS", "host_ioc", "critical-immediate") {
		t.Fatalf("records = %#v, want host IOC finding", records)
	}
}

func TestBuiltinScanCatalogHasNarrowHostIOCsOnly(t *testing.T) {
	entries := builtinScanCatalogEntries()
	if len(entries) == 0 {
		t.Fatal("expected built-in host IOC entries")
	}
	for _, entry := range entries {
		if entry.KnownFilePath == "" {
			t.Fatalf("entry = %#v, want known_file_path", entry)
		}
		for _, forbidden := range []string{".env", ".zsh_history", ".bash_history", ".ssh", ".aws", "Keychain", "Cookies", "History"} {
			if strings.Contains(entry.KnownFilePath, forbidden) {
				t.Fatalf("entry = %#v, built-in catalog must not target secret-bearing paths", entry)
			}
		}
	}
}

func TestRunScanMatchesBuiltinHostIOCCatalog(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, ".claude", "setup.mjs"), "placeholder")
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasScanFinding(records, "BUILTIN-AGENT-SETUP-MJS", "host_ioc", "critical-immediate") {
		t.Fatalf("records = %#v, want built-in agent setup.mjs IOC finding", records)
	}
}

func TestRunScanUsesOSVQueryBatchForAdvisoryFindings(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/vuln": {"version": "1.0.0"}
		}
	}`)
	withFakeOSVBatch(t, `{"results":[{"vulns":[{"id":"GHSA-test","summary":"bad","database_specific":{"severity":"CRITICAL"}}]}]}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasScanFinding(records, "GHSA-test", "vulnerability", "high") {
		t.Fatalf("records = %#v, want OSV vulnerability finding", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasSnapshot(body, "provider", "osv", "status", "ok") || !strings.Contains(string(body), `"queried_count": 1`) {
		t.Fatalf("provider snapshots = %s, want OSV ok snapshot", string(body))
	}
}

func TestRunScanProviderFailureMakesScanPartial(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/left-pad": {"version": "1.3.0"}
		}
	}`)
	withFakeOSVBatchStatus(t, http.StatusInternalServerError, `{"error":"down"}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	summary := scanSummaryRecord(t, records)
	if summary["status"] != "partial" {
		t.Fatalf("summary = %#v, want partial scan on provider failure", summary)
	}
	if !hasDiagnostic(records, "provider_unavailable") {
		t.Fatalf("records = %#v, want provider_unavailable diagnostic", records)
	}
}

func TestRunScanUsesFreshOSVCacheWhenProviderUnavailable(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/cached-vuln": {"version": "1.0.0"}
		}
	}`)
	t.Setenv("LSEC_HOME", lsecHome)
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.PutAdvisoryCache(AdvisoryCacheEntry{
		Ecosystem: "npm",
		Name:      "cached-vuln",
		Version:   "1.0.0",
		CheckedAt: time.Now().UTC(),
		Advisories: []Advisory{{
			Source: "osv", ID: "GHSA-cached", Ecosystem: "npm", Name: "cached-vuln", Version: "1.0.0", Severity: "critical", Summary: "cached advisory",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	withFakeOSVBatchStatus(t, http.StatusInternalServerError, `{"error":"down"}`)

	var stdout strings.Builder
	err = Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasScanFinding(records, "GHSA-cached", "vulnerability", "high") {
		t.Fatalf("records = %#v, want cached advisory finding", records)
	}
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, cached advisory should avoid partial provider failure", records)
	}
}

func parseNDJSONRecords(t *testing.T, body string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("bad ndjson line %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

func hasScanObservation(records []map[string]any, ecosystem, name, version, presence string) bool {
	for _, record := range records {
		if record["type"] == "observation" &&
			record["ecosystem"] == ecosystem &&
			record["name"] == name &&
			record["version"] == version &&
			record["presence"] == presence {
			return true
		}
	}
	return false
}

func hasScanFinding(records []map[string]any, id, class, urgency string) bool {
	for _, record := range records {
		if record["type"] == "finding" &&
			record["provider_record_id"] == id &&
			record["class"] == class &&
			record["urgency"] == urgency {
			return true
		}
	}
	return false
}

func hasDiagnostic(records []map[string]any, code string) bool {
	for _, record := range records {
		if record["type"] == "diagnostic" && record["code"] == code {
			return true
		}
	}
	return false
}

func hasRecordType(records []map[string]any, recordType string) bool {
	for _, record := range records {
		if record["type"] == recordType {
			return true
		}
	}
	return false
}

func scanSummaryRecord(t *testing.T, records []map[string]any) map[string]any {
	t.Helper()
	if len(records) == 0 || records[len(records)-1]["type"] != "scan_summary" {
		t.Fatalf("records = %#v, want final scan_summary", records)
	}
	return records[len(records)-1]
}

func hasSnapshot(body []byte, key, value, secondKey, secondValue string) bool {
	var records []map[string]any
	if err := json.Unmarshal(body, &records); err != nil {
		return false
	}
	for _, record := range records {
		if record[key] == value && record[secondKey] == secondValue {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func withFakeOSVBatch(t *testing.T, body string) {
	t.Helper()
	withFakeOSVBatchStatus(t, http.StatusOK, body)
}

func withFakeOSVBatchStatus(t *testing.T, status int, body string) {
	t.Helper()
	previousEndpoint := osvBatchEndpoint
	previousClient := osvHTTPClient
	osvBatchEndpoint = "https://osv.test/querybatch"
	osvHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() {
		osvBatchEndpoint = previousEndpoint
		osvHTTPClient = previousClient
	})
}
