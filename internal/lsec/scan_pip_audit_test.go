package lsec

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const safeRequirementLine = "requests==2.32.5 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"

func TestPipAuditMissingIsNonFatalWhenSafeRequirementsExist(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "requirements.txt"), safeRequirementLine)
	withFakeOSVBatch(t, `{"results":[{}]}`)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, missing pip-audit should not make scan partial", records)
	}
	if hasDiagnostic(records, "provider_unavailable") || hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, missing pip-audit should not emit provider diagnostic", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasSnapshot(body, "provider", "pip-audit", "status", "not_available") {
		t.Fatalf("provider snapshots = %s, want missing pip-audit snapshot", string(body))
	}
	snapshot := readProviderSnapshot(t, lsecHome, runID, "pip-audit")
	if snapshot.CandidateCount != 1 || snapshot.AcceptedCount != 1 || snapshot.SkippedCount != 0 || snapshot.QueriedCount != 0 || snapshot.FailedCount != 0 {
		t.Fatalf("snapshot = %#v, want one accepted candidate and no query for missing provider", snapshot)
	}
}

func TestPipAuditNetworkOffDoesNotInvokeProvider(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	marker := filepath.Join(root, "pip-audit-called")
	writeFile(t, filepath.Join(project, "requirements.txt"), safeRequirementLine)
	writeFakeTool(t, root, "pip-audit", "#!/bin/sh\nprintf called > "+shellQuote(marker)+"\n")
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("pip-audit marker stat err = %v, want not invoked", err)
	}
}

func TestPipAuditReceivesOnlySafeRequirementsFiles(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	argsPath := filepath.Join(root, "args.txt")
	safe := filepath.Join(project, "requirements.txt")
	writeFile(t, safe, safeRequirementLine)
	writeFile(t, filepath.Join(project, "nested", "requirements.txt"), "flask==3.0.0 --hash sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n")
	writeFile(t, filepath.Join(project, "unsafe", "requirements.txt"), "requests>=2\n")
	writeFile(t, filepath.Join(project, "src", "app.py"), "print('nope')\n")
	writeFile(t, filepath.Join(project, ".venv", "requirements.txt"), safeRequirementLine)
	writeFile(t, filepath.Join(project, ".env", "requirements.txt"), safeRequirementLine)
	writeFile(t, filepath.Join(project, "venv", "requirements.txt"), safeRequirementLine)
	writeFile(t, filepath.Join(project, "env", "requirements.txt"), safeRequirementLine)
	writeFile(t, filepath.Join(project, "lib", "site-packages", "requirements.txt"), safeRequirementLine)
	writeFile(t, filepath.Join(project, "node_modules", "pkg", "requirements.txt"), safeRequirementLine)
	writeFakeTool(t, root, "pip-audit", "#!/bin/sh\nprintf '%s\\n' \"$@\" >> "+shellQuote(argsPath)+"\necho '{\"dependencies\":[]}'\n")
	withFakeOSVBatch(t, `{"results":[{},{}]}`)
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(args)
	gotArgs := strings.Fields(got)
	wantArgs := []string{
		"--format", "json", "--progress-spinner", "off", "--requirement", filepath.Join(project, "nested", "requirements.txt"),
		"--format", "json", "--progress-spinner", "off", "--requirement", safe,
	}
	if strings.Join(gotArgs, "\n") != strings.Join(wantArgs, "\n") {
		t.Fatalf("pip-audit args = %#v, want %#v", gotArgs, wantArgs)
	}
	for _, unwanted := range []string{
		project,
		filepath.Join(project, "unsafe", "requirements.txt"),
		filepath.Join(project, "src", "app.py"),
		filepath.Join(project, ".venv", "requirements.txt"),
		filepath.Join(project, ".env", "requirements.txt"),
		filepath.Join(project, "venv", "requirements.txt"),
		filepath.Join(project, "env", "requirements.txt"),
		filepath.Join(project, "lib", "site-packages", "requirements.txt"),
		filepath.Join(project, "node_modules", "pkg", "requirements.txt"),
	} {
		if strings.Contains(got, unwanted+"\n") {
			t.Fatalf("pip-audit args = %q, should not include %s", got, unwanted)
		}
	}
}

func TestPipAuditJSONOutputMapsFinding(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	requirements := filepath.Join(project, "requirements.txt")
	writeFile(t, requirements, safeRequirementLine)
	writeFakeTool(t, root, "pip-audit", `#!/bin/sh
echo '{"dependencies":[{"name":"requests","version":"2.32.5","vulns":[{"id":"PYSEC-2026-1","description":"bad requests vuln","fix_versions":["2.32.6"]}]}]}'
`)
	withFakeOSVBatch(t, `{"results":[{}]}`)
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasProviderScanFinding(records, "pip-audit", "PYSEC-2026-1", "vulnerability", "review") {
		t.Fatalf("records = %#v, want pip-audit vulnerability finding", records)
	}
}

func TestPipAuditJSONOutputIgnoresStderrNoise(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	requirements := filepath.Join(project, "requirements.txt")
	writeFile(t, requirements, safeRequirementLine)
	writeFakeTool(t, root, "pip-audit", `#!/bin/sh
echo 'warning: noisy stderr' >&2
echo '{"dependencies":[{"name":"requests","version":"2.32.5","vulns":[{"id":"PYSEC-stderr-noise","description":"bad requests vuln","fix_versions":["2.32.6"]}]}]}'
`)
	withFakeOSVBatch(t, `{"results":[{}]}`)
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasProviderScanFinding(records, "pip-audit", "PYSEC-stderr-noise", "vulnerability", "review") {
		t.Fatalf("records = %#v, want pip-audit finding despite stderr noise", records)
	}
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, want complete scan when pip-audit emits stderr noise with valid json", records)
	}
	if hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, valid pip-audit json with stderr noise should not emit provider_failed", records)
	}
}

func TestPipAuditProviderRunsWithIsolatedEnvAndWorkingDir(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	observed := filepath.Join(root, "observed")
	writeFile(t, filepath.Join(project, "requirements.txt"), safeRequirementLine)
	if err := os.MkdirAll(observed, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFakeTool(t, root, "pip-audit", `#!/bin/sh
printf '%s' "$GITHUB_TOKEN" > `+shellQuote(filepath.Join(observed, "github_token"))+`
printf '%s' "$AWS_SECRET_ACCESS_KEY" > `+shellQuote(filepath.Join(observed, "aws_secret"))+`
printf '%s' "$OPENAI_API_KEY" > `+shellQuote(filepath.Join(observed, "openai_key"))+`
printf '%s' "$HOME" > `+shellQuote(filepath.Join(observed, "home"))+`
printf '%s' "$XDG_CACHE_HOME" > `+shellQuote(filepath.Join(observed, "cache_home"))+`
printf '%s' "$XDG_CONFIG_HOME" > `+shellQuote(filepath.Join(observed, "config_home"))+`
printf '%s' "$PWD" > `+shellQuote(filepath.Join(observed, "pwd"))+`
echo '{"dependencies":[]}'
`)
	withFakeOSVBatch(t, `{"results":[{}]}`)
	parentHome := filepath.Join(root, "real-home")
	t.Setenv("PATH", root)
	t.Setenv("HOME", parentHome)
	t.Setenv("GITHUB_TOKEN", "ghp_secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws_secret")
	t.Setenv("OPENAI_API_KEY", "openai_secret")
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"github_token", "aws_secret", "openai_key"} {
		if got := readTextFile(t, filepath.Join(observed, name)); got != "" {
			t.Fatalf("%s = %q, want secret env omitted", name, got)
		}
	}
	home := readTextFile(t, filepath.Join(observed, "home"))
	if home == "" || home == parentHome || !strings.Contains(home, "lsec-scan-provider-") {
		t.Fatalf("HOME = %q, want fake provider home under temp dir", home)
	}
	for _, name := range []string{"cache_home", "config_home"} {
		if got := readTextFile(t, filepath.Join(observed, name)); got == "" || !strings.HasPrefix(got, filepath.Dir(home)+string(os.PathSeparator)) {
			t.Fatalf("%s = %q, want XDG dir under provider temp dir %q", name, got, filepath.Dir(home))
		}
	}
	pwd := readTextFile(t, filepath.Join(observed, "pwd"))
	if pwd == "" || pwd == project || pwd == root || !strings.Contains(pwd, "lsec-scan-provider-") {
		t.Fatalf("PWD = %q, want isolated provider working directory outside project", pwd)
	}
}

func TestPipAuditProviderDropsCredentialedProxyEnv(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	observed := filepath.Join(root, "proxy.txt")
	writeFile(t, filepath.Join(project, "requirements.txt"), safeRequirementLine)
	writeFakeTool(t, root, "pip-audit", "#!/bin/sh\nprintf '%s\\n%s\\n%s' \"$HTTPS_PROXY\" \"$HTTP_PROXY\" \"$NO_PROXY\" > "+shellQuote(observed)+"\necho '{\"dependencies\":[]}'\n")
	withFakeOSVBatch(t, `{"results":[{}]}`)
	t.Setenv("PATH", root)
	t.Setenv("HTTPS_PROXY", "https://user:pass@proxy.local:8443")
	t.Setenv("HTTP_PROXY", "http://proxy.local:8080")
	t.Setenv("NO_PROXY", "localhost,127.0.0.1")
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	got := readTextFile(t, observed)
	if strings.Contains(got, "user:pass") {
		t.Fatalf("proxy env = %q, want credentialed proxy omitted", got)
	}
	if !strings.Contains(got, "http://proxy.local:8080") || !strings.Contains(got, "localhost,127.0.0.1") {
		t.Fatalf("proxy env = %q, want safe proxy values preserved", got)
	}
}

func TestPipAuditNonzeroExitWithJSONMapsFinding(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "requirements.txt"), safeRequirementLine)
	writeFakeTool(t, root, "pip-audit", `#!/bin/sh
echo '{"dependencies":[{"name":"requests","version":"2.32.5","vulns":[{"id":"GHSA-pip-audit","description":"nonzero vuln","severity":"high"}]}]}'
exit 1
`)
	withFakeOSVBatch(t, `{"results":[{}]}`)
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if !hasProviderScanFinding(records, "pip-audit", "GHSA-pip-audit", "vulnerability", "review") {
		t.Fatalf("records = %#v, want pip-audit finding despite nonzero exit", records)
	}
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, valid pip-audit JSON should keep scan complete", records)
	}
}

func TestPipAuditNonzeroExitWithoutFindingsMakesScanPartial(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "requirements.txt"), safeRequirementLine)
	writeFakeTool(t, root, "pip-audit", `#!/bin/sh
echo '{"dependencies":[{"name":"requests","version":"2.32.5","vulns":[]}]}'
exit 1
`)
	withFakeOSVBatch(t, `{"results":[{}]}`)
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if scanSummaryRecord(t, records)["status"] != "partial" {
		t.Fatalf("records = %#v, want partial scan on nonzero pip-audit output without findings", records)
	}
	if !hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, want provider_failed diagnostic", records)
	}
}

func TestPipAuditFailureOutputIsTruncated(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "requirements.txt"), safeRequirementLine)
	writeFakeTool(t, root, "pip-audit", `#!/bin/sh
i=0
while [ "$i" -lt 9000 ]; do
	printf 'x'
	i=$((i + 1))
done
printf 'TAIL_SECRET'
exit 2
`)
	withFakeOSVBatch(t, `{"results":[{}]}`)
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if scanSummaryRecord(t, records)["status"] != "partial" {
		t.Fatalf("records = %#v, want partial scan on pip-audit failure", records)
	}
	message := diagnosticMessage(records, "provider_failed")
	if !strings.Contains(message, "truncated") {
		t.Fatalf("provider_failed message = %q, want truncation marker", message)
	}
	if strings.Contains(stdout.String(), "TAIL_SECRET") || len(message) > 1200 {
		t.Fatalf("provider_failed message was not bounded: len=%d body=%q", len(message), message)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := readProviderSnapshot(t, lsecHome, runID, "pip-audit")
	if snapshot.Error != "execution_failed" || strings.Contains(string(body), "truncated") || strings.Contains(string(body), "TAIL_SECRET") {
		t.Fatalf("provider snapshots = %s, want categorical error without provider output", string(body))
	}
}

func TestPipAuditFailureRedactsOutputPaths(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	requirements := filepath.Join(project, "requirements.txt")
	writeFile(t, requirements, safeRequirementLine)
	writeFakeTool(t, root, "pip-audit", "#!/bin/sh\necho failed scanning "+shellQuote(requirements)+" >&2\nexit 2\n")
	withFakeOSVBatch(t, `{"results":[{}]}`)
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson", "--redact-paths", "all"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	out := stdout.String()
	if strings.Contains(out, requirements) || strings.Contains(out, project) {
		t.Fatalf("scan output leaked external provider path: %s", out)
	}
	records := parseNDJSONRecords(t, out)
	if scanSummaryRecord(t, records)["status"] != "partial" {
		t.Fatalf("records = %#v, want partial scan on pip-audit failure", records)
	}
	if !hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, want provider_failed diagnostic", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), requirements) || strings.Contains(string(body), project) {
		t.Fatalf("provider snapshots leaked external provider path: %s", string(body))
	}
	diagnostics, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "diagnostics.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(diagnostics), requirements) || strings.Contains(string(diagnostics), project) {
		t.Fatalf("diagnostics leaked external provider path: %s", string(diagnostics))
	}
}

func TestPipAuditUnsafeRequirementsSkippedWithoutLeakingContents(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	marker := filepath.Join(root, "pip-audit-called")
	unsafeLine := "secret-internal-package>=1.0\n"
	writeFile(t, filepath.Join(project, "requirements.txt"), unsafeLine)
	writeFakeTool(t, root, "pip-audit", "#!/bin/sh\nprintf called > "+shellQuote(marker)+"\n")
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("pip-audit marker stat err = %v, want not invoked", err)
	}
	if strings.Contains(stdout.String(), unsafeLine) || strings.Contains(stdout.String(), "secret-internal-package") {
		t.Fatalf("scan output leaked unsafe requirements contents: %s", stdout.String())
	}
	records := parseNDJSONRecords(t, stdout.String())
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, skipped unsafe requirements should not make scan partial", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	snapshot := readProviderSnapshot(t, lsecHome, runID, "pip-audit")
	if snapshot.Status != "not_applicable" || snapshot.CandidateCount != 1 || snapshot.AcceptedCount != 0 || snapshot.SkippedCount != 1 || snapshot.QueriedCount != 0 || snapshot.FailedCount != 0 {
		t.Fatalf("snapshot = %#v, want visible unsafe input skip", snapshot)
	}
	if snapshot.SkipReasons["unsafe_requirements"] != 1 {
		t.Fatalf("skip reasons = %#v, want categorical unsafe requirements count", snapshot.SkipReasons)
	}
	encoded, err := json.Marshal(snapshot.SkipReasons)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), project) || strings.Contains(string(encoded), "secret-internal-package") || strings.Contains(string(encoded), "requirements.txt") {
		t.Fatalf("skip reasons leaked path or content: %s", string(encoded))
	}
}

func TestPipAuditKeepsEarlierFindingsAndCountsFailedInput(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "a", "requirements.txt"), safeRequirementLine)
	writeFile(t, filepath.Join(project, "z", "requirements.txt"), safeRequirementLine)
	writeFakeTool(t, root, "pip-audit", `#!/bin/sh
case "$6" in
  */a/*) echo '{"dependencies":[{"name":"requests","version":"2.32.5","vulns":[{"id":"PYSEC-retained"}]}]}' ;;
  *) echo 'secret provider output from /private/project/requirements.txt' >&2; exit 2 ;;
esac
`)
	t.Setenv("PATH", root)

	findings, diagnostics, snapshot := runPipAuditProvider(t.Context(), "run", []string{project})

	if len(findings) != 1 || findings[0].ProviderRecordID != "PYSEC-retained" {
		t.Fatalf("findings = %#v, want earlier successful finding retained", findings)
	}
	if len(diagnostics) != 1 || snapshot.Status != "error" {
		t.Fatalf("diagnostics = %#v snapshot = %#v, want partial provider error", diagnostics, snapshot)
	}
	if snapshot.CandidateCount != 2 || snapshot.AcceptedCount != 2 || snapshot.SkippedCount != 0 || snapshot.QueriedCount != 2 || snapshot.FailedCount != 1 {
		t.Fatalf("snapshot = %#v, want actual query and failure counts", snapshot)
	}
	if snapshot.Error != "execution_failed" || strings.Contains(snapshot.Error, "secret") || strings.Contains(snapshot.Error, project) {
		t.Fatalf("snapshot error = %q, want redacted category", snapshot.Error)
	}
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
