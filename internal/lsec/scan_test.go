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

func TestRunScanAppearsInHistoryAndStatus(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "demo", "version": "0.1.0"},
			"node_modules/left-pad": {"version": "1.3.0"}
		}
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var scanOut strings.Builder
	if err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &scanOut, io.Discard); err != nil {
		t.Fatal(err)
	}
	runID, _ := scanSummaryRecord(t, parseNDJSONRecords(t, scanOut.String()))["run_id"].(string)

	var history strings.Builder
	if err := Run([]string{"history"}, strings.NewReader(""), &history, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(history.String(), "scan\t"+runID) || !strings.Contains(history.String(), "scan --profile project") {
		t.Fatalf("history output = %q, want scan event", history.String())
	}

	var status strings.Builder
	if err := Run([]string{"status"}, strings.NewReader(""), &status, io.Discard); err != nil {
		t.Fatal(err)
	}
	wantStatus := "runs: 1\n" +
		"packages: 0\n" +
		"approvals: 0\n" +
		"approved_packages: 0\n" +
		"scan_runs: 1\n" +
		"partial_scan_runs: 0\n" +
		"scan_findings: 0\n" +
		"scan_diagnostics: 0\n" +
		"verdict[allow]: 0\n" +
		"verdict[prompt]: 0\n" +
		"verdict[block]: 0\n" +
		"lane[trusted]: 0\n" +
		"lane[risky]: 0\n" +
		"lane[block]: 0\n"
	if status.String() != wantStatus {
		t.Fatalf("status output = %q, want %q", status.String(), wantStatus)
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
				"args": ["-y", "@example/server@1.2.3", "--token", "lsec-test-placeholder-token"],
				"env": {"GITHUB_TOKEN": "lsec-test-placeholder-token"}
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
	if strings.Contains(out, "lsec-test-placeholder-token") {
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
		if strings.Contains(string(body), "lsec-test-placeholder-token") {
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

func TestRunScanInventoriesCycloneDXSBOMComponents(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "sbom.json"), `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{"type":"library","name":"ignored-name","version":"0.0.0","purl":"pkg:npm/%40scope/left-pad@1.3.0"},
			{"type":"library","name":"Requests","version":"2.32.5","purl":"pkg:pypi/requests@2.32.5"}
		]
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasScanObservationWithSource(records, "npm", "@scope/left-pad", "1.3.0", "configured", "cyclonedx_sbom") {
		t.Fatalf("records = %#v, want CycloneDX npm observation from purl", records)
	}
	if !hasScanObservationWithSource(records, "PyPI", "requests", "2.32.5", "configured", "cyclonedx_sbom") {
		t.Fatalf("records = %#v, want CycloneDX PyPI observation from purl", records)
	}
}

func TestRunScanCycloneDXIgnoresUnsupportedIncompleteComponents(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "deps.cdx.json"), `{
		"bomFormat": "CycloneDX",
		"components": [
			{"type":"library","name":"left-pad","version":"1.3.0"},
			{"type":"library","name":"noversion","purl":"pkg:npm/noversion"},
			{"type":"library","name":"crate","version":"1.0.0","purl":"pkg:cargo/crate@1.0.0"}
		]
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if hasRecordType(records, "observation") {
		t.Fatalf("records = %#v, unsupported and incomplete SBOM components should be ignored", records)
	}
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, ignored SBOM components should not make scan partial", records)
	}
}

func TestRunScanMalformedCycloneDXSBOMDiagnosticContinues(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "bom.json"), `{"bomFormat":"CycloneDX","components":[`)
	writeFile(t, filepath.Join(project, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {"node_modules/left-pad": {"version": "1.3.0"}}
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasDiagnostic(records, "parse_error") {
		t.Fatalf("records = %#v, want malformed SBOM parse diagnostic", records)
	}
	if !hasScanObservation(records, "npm", "left-pad", "1.3.0", "declared") {
		t.Fatalf("records = %#v, scan should continue after malformed SBOM", records)
	}
	if scanSummaryRecord(t, records)["status"] != "partial" {
		t.Fatalf("records = %#v, malformed SBOM diagnostic should make scan partial", records)
	}
}

func TestRunScanCycloneDXNetworkOffDoesNotUseProviders(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "sbom.json"), `{
		"bomFormat": "CycloneDX",
		"components": [{"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]
	}`)
	t.Setenv("LSEC_HOME", lsecHome)
	t.Setenv("PATH", t.TempDir())
	oldClient := osvHTTPClient
	t.Cleanup(func() { osvHTTPClient = oldClient })
	osvHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("OSV provider should not be invoked with --network off")
		return nil, nil
	})}

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if !hasScanObservation(parseNDJSONRecords(t, stdout.String()), "npm", "left-pad", "1.3.0", "configured") {
		t.Fatalf("scan output = %s, want SBOM observation", stdout.String())
	}
}

func TestRunScanCycloneDXFeedsOSVAdvisoryFlow(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "bom.json"), `{
		"bomFormat": "CycloneDX",
		"components": [{"type":"library","name":"vuln","version":"1.0.0","purl":"pkg:npm/vuln@1.0.0"}]
	}`)
	withFakeOSVBatch(t, `{"results":[{"vulns":[{"id":"GHSA-sbom","summary":"bad sbom vuln","database_specific":{"severity":"CRITICAL"}}]}]}`)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasProviderScanFinding(records, "osv", "GHSA-sbom", "vulnerability", "high") {
		t.Fatalf("records = %#v, want OSV finding for SBOM observation", records)
	}
}

func TestRunScanCycloneDXRedactsSourcePath(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	sbom := filepath.Join(project, "sbom.json")
	writeFile(t, sbom, `{
		"bomFormat": "CycloneDX",
		"components": [{"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson", "--redact-paths", "all"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	out := stdout.String()
	if strings.Contains(out, sbom) || strings.Contains(out, project) {
		t.Fatalf("scan output leaked SBOM source path: %s", out)
	}
	if !strings.Contains(out, `"source_path":"[redacted]"`) {
		t.Fatalf("scan output = %s, want redacted SBOM source path", out)
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

func TestRunScanRedactsHomePathsInOutputAndBundle(t *testing.T) {
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
	if strings.Contains(string(body), sourcePath) {
		t.Fatalf("inventory bundle leaked full home path: %s", string(body))
	}
	if !strings.Contains(string(body), "~/project/package-lock.json") {
		t.Fatalf("inventory bundle = %s, want home-relative redacted path", string(body))
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

func hasScanObservationWithSource(records []map[string]any, ecosystem, name, version, presence, sourceType string) bool {
	for _, record := range records {
		if record["type"] == "observation" &&
			record["ecosystem"] == ecosystem &&
			record["name"] == name &&
			record["version"] == version &&
			record["presence"] == presence &&
			record["source_type"] == sourceType {
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

func hasProviderScanFinding(records []map[string]any, provider, id, class, urgency string) bool {
	for _, record := range records {
		if record["type"] == "finding" &&
			record["provider"] == provider &&
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

func diagnosticMessage(records []map[string]any, code string) string {
	for _, record := range records {
		if record["type"] == "diagnostic" && record["code"] == code {
			message, _ := record["message"].(string)
			return message
		}
	}
	return ""
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
