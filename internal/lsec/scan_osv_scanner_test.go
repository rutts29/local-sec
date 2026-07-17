package lsec

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOSVScannerMissingIsNonFatal(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/left-pad": {"version": "1.3.0"}
		}
	}`)
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
		t.Fatalf("records = %#v, missing osv-scanner should not make scan partial", records)
	}
	if hasDiagnostic(records, "provider_unavailable") || hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, missing osv-scanner should not emit provider diagnostic", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasSnapshot(body, "provider", "osv-scanner", "status", "not_available") {
		t.Fatalf("provider snapshots = %s, want missing osv-scanner snapshot", string(body))
	}
	snapshot := readProviderSnapshot(t, lsecHome, runID, "osv-scanner")
	if snapshot.CandidateCount != 1 || snapshot.AcceptedCount != 1 || snapshot.SkippedCount != 0 || snapshot.QueriedCount != 0 || snapshot.FailedCount != 0 {
		t.Fatalf("snapshot = %#v, want one accepted candidate and no query for missing provider", snapshot)
	}
}

func TestOSVScannerSnapshotCountsSkippedUnsafeInputsWithoutPaths(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	accepted := filepath.Join(project, "package-lock.json")
	linked := filepath.Join(project, "linked", "npm-shrinkwrap.json")
	writeFile(t, accepted, `{"lockfileVersion":3,"packages":{}}`)
	if err := os.MkdirAll(filepath.Dir(linked), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(accepted, linked); err != nil {
		t.Fatal(err)
	}
	writeFakeTool(t, root, "osv-scanner", "#!/bin/sh\necho '{\"results\":[]}'\n")
	t.Setenv("PATH", root)

	_, _, snapshot := runOSVScannerProvider(t.Context(), "run", []string{project})

	if snapshot.CandidateCount != 2 || snapshot.AcceptedCount != 1 || snapshot.SkippedCount != 1 || snapshot.QueriedCount != 1 || snapshot.FailedCount != 0 {
		t.Fatalf("snapshot = %#v, want accepted and skipped input counts", snapshot)
	}
	if snapshot.SkipReasons["symlink"] != 1 {
		t.Fatalf("skip reasons = %#v, want categorical symlink count", snapshot.SkipReasons)
	}
	encoded, err := json.Marshal(snapshot.SkipReasons)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), project) || strings.Contains(string(encoded), linked) || strings.Contains(string(encoded), "npm-shrinkwrap.json") {
		t.Fatalf("skip reasons leaked input identity: %s", string(encoded))
	}
}

func TestOSVScannerReceivesOnlyNPMLockfiles(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	argsPath := filepath.Join(root, "args.txt")
	writeFile(t, filepath.Join(project, "package-lock.json"), `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`)
	writeFile(t, filepath.Join(project, "nested", "npm-shrinkwrap.json"), `{"lockfileVersion":3,"packages":{"node_modules/b":{"version":"2.0.0"}}}`)
	writeFile(t, filepath.Join(project, "package.json"), `{"name":"demo"}`)
	writeFile(t, filepath.Join(project, "src", "index.js"), `console.log("nope")`)
	writeFile(t, filepath.Join(project, "node_modules", ".package-lock.json"), `{"lockfileVersion":3,"packages":{"node_modules/c":{"version":"3.0.0"}}}`)
	writeFile(t, filepath.Join(project, "node_modules", "pkg", "package-lock.json"), `{"lockfileVersion":3,"packages":{"node_modules/d":{"version":"4.0.0"}}}`)
	writeFakeTool(t, root, "osv-scanner", "#!/bin/sh\nprintf '%s\\n' \"$@\" > "+argsPath+"\necho '{\"results\":[]}'\n")
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
	if len(gotArgs) != 7 || gotArgs[0] != "scan" || gotArgs[1] != "-L" || gotArgs[3] != "-L" || gotArgs[5] != "--format" || gotArgs[6] != "json" {
		t.Fatalf("osv-scanner args = %#v, want copied lockfile invocation", gotArgs)
	}
	for _, arg := range []string{gotArgs[2], gotArgs[4]} {
		if !strings.Contains(arg, "lsec-scan-provider-") || !filepath.IsAbs(arg) {
			t.Fatalf("osv-scanner lockfile arg = %q, want private provider copy", arg)
		}
	}
	for _, unwanted := range []string{project, filepath.Join(project, "package-lock.json"), filepath.Join(project, "nested", "npm-shrinkwrap.json"), filepath.Join(project, "package.json"), filepath.Join(project, "src", "index.js"), filepath.Join(project, "node_modules", ".package-lock.json"), filepath.Join(project, "node_modules", "pkg", "package-lock.json")} {
		for _, arg := range gotArgs {
			if arg == unwanted {
				t.Fatalf("osv-scanner args = %#v, should not include %s", gotArgs, unwanted)
			}
		}
		if strings.Contains(got, unwanted+"\n") {
			t.Fatalf("osv-scanner args = %q, should not include %s", got, unwanted)
		}
	}
}

func TestOSVScannerJSONOutputMapsFinding(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	lockfile := filepath.Join(project, "package-lock.json")
	writeFile(t, lockfile, `{"lockfileVersion":3,"packages":{"node_modules/vuln":{"version":"1.0.0"}}}`)
	writeFakeTool(t, root, "osv-scanner", `#!/bin/sh
echo '{"results":[{"source":{"path":"`+lockfile+`"},"packages":[{"package":{"name":"vuln","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":"GHSA-scanner","summary":"bad scanner vuln","database_specific":{"severity":"CRITICAL"}}]}]}]}'
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
	if !hasProviderScanFinding(records, "osv-scanner", "GHSA-scanner", "vulnerability", "high") {
		t.Fatalf("records = %#v, want osv-scanner vulnerability finding", records)
	}
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, want complete scan when osv-scanner exits 1 with findings", records)
	}
	if hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, valid osv-scanner JSON with findings should not emit provider_failed", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasSnapshot(body, "provider", "osv-scanner", "status", "ok") {
		t.Fatalf("provider snapshots = %s, want osv-scanner ok snapshot", string(body))
	}
}

func TestOSVScannerJSONOutputIgnoresStderrNoise(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	lockfile := filepath.Join(project, "package-lock.json")
	writeFile(t, lockfile, `{"lockfileVersion":3,"packages":{"node_modules/vuln":{"version":"1.0.0"}}}`)
	writeFakeTool(t, root, "osv-scanner", `#!/bin/sh
echo 'warning: noisy stderr' >&2
echo '{"results":[{"source":{"path":"`+lockfile+`"},"packages":[{"package":{"name":"vuln","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":"GHSA-stderr-noise","summary":"stderr noise vuln","database_specific":{"severity":"CRITICAL"}}]}]}]}'
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
	if !hasProviderScanFinding(records, "osv-scanner", "GHSA-stderr-noise", "vulnerability", "high") {
		t.Fatalf("records = %#v, want osv-scanner finding despite stderr noise", records)
	}
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, want complete scan when osv-scanner emits stderr noise with valid json", records)
	}
	if hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, valid osv-scanner json with stderr noise should not emit provider_failed", records)
	}
}

func TestOSVScannerExitTwoWithFindingsMakesScanPartial(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	lockfile := filepath.Join(project, "package-lock.json")
	writeFile(t, lockfile, `{"lockfileVersion":3,"packages":{"node_modules/vuln":{"version":"1.0.0"}}}`)
	writeFakeTool(t, root, "osv-scanner", `#!/bin/sh
echo '{"results":[{"source":{"path":"`+lockfile+`"},"packages":[{"package":{"name":"vuln","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":"GHSA-exit-two","summary":"bad scanner vuln","database_specific":{"severity":"CRITICAL"}}]}]}]}'
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
		t.Fatalf("records = %#v, want partial scan when osv-scanner exits 2", records)
	}
	if !hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, want provider_failed diagnostic", records)
	}
	if hasProviderScanFinding(records, "osv-scanner", "GHSA-exit-two", "vulnerability", "high") {
		t.Fatalf("records = %#v, exit 2 should not be accepted as successful osv-scanner findings", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if hasSnapshot(body, "provider", "osv-scanner", "status", "ok") {
		t.Fatalf("provider snapshots = %s, exit 2 should not produce osv-scanner ok snapshot", string(body))
	}
	if !hasSnapshot(body, "provider", "osv-scanner", "status", "error") {
		t.Fatalf("provider snapshots = %s, want osv-scanner error snapshot", string(body))
	}
}

func TestOSVScannerFailureMakesScanPartial(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "package-lock.json"), `{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}`)
	writeFakeTool(t, root, "osv-scanner", "#!/bin/sh\necho broken >&2\nexit 2\n")
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
		t.Fatalf("records = %#v, want partial scan on osv-scanner failure", records)
	}
	if !hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, want provider_failed diagnostic", records)
	}
}

func TestOSVScannerFailureDoesNotLeakExternalOutputPaths(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	lockfile := filepath.Join(project, "package-lock.json")
	writeFile(t, lockfile, `{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}`)
	writeFakeTool(t, root, "osv-scanner", "#!/bin/sh\necho failed scanning "+lockfile+" >&2\nexit 2\n")
	withFakeOSVBatch(t, `{"results":[{}]}`)
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson", "--redact-paths", "all"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	out := stdout.String()
	if strings.Contains(out, lockfile) || strings.Contains(out, project) {
		t.Fatalf("scan output leaked external provider path: %s", out)
	}
	records := parseNDJSONRecords(t, out)
	if scanSummaryRecord(t, records)["status"] != "partial" {
		t.Fatalf("records = %#v, want partial scan on osv-scanner failure", records)
	}
	if !hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, want provider_failed diagnostic", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), lockfile) || strings.Contains(string(body), project) {
		t.Fatalf("provider snapshots leaked external provider path: %s", string(body))
	}
}

func TestOSVScannerRedactsOutputPaths(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	lockfile := filepath.Join(project, "package-lock.json")
	writeFile(t, lockfile, `{"lockfileVersion":3,"packages":{"node_modules/vuln":{"version":"1.0.0"}}}`)
	writeFakeTool(t, root, "osv-scanner", `#!/bin/sh
echo '{"results":[{"source":{"path":"`+lockfile+`"},"packages":[{"package":{"name":"vuln","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":"GHSA-redacted","summary":"redacted path vuln","database_specific":{"severity":"HIGH"}}]}]}]}'
`)
	withFakeOSVBatch(t, `{"results":[{}]}`)
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "json", "--redact-paths", "all"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	out := stdout.String()
	if strings.Contains(out, lockfile) || strings.Contains(out, project) {
		t.Fatalf("scan output leaked unredacted path: %s", out)
	}
	if !strings.Contains(out, `"source_path": "[redacted]"`) {
		t.Fatalf("scan output = %s, want redacted source path", out)
	}
}

func TestOSVScannerReadsCopiedLockfileAfterOriginalChanges(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	lockfile := filepath.Join(project, "package-lock.json")
	seenArg := filepath.Join(root, "seen-arg")
	seenContent := filepath.Join(root, "seen-content")
	writeFile(t, lockfile, `{"lockfileVersion":3,"packages":{"node_modules/vuln":{"version":"1.0.0"}}}`)
	writeFakeTool(t, root, "osv-scanner", `#!/bin/sh
lockfile="$3"
printf '%s' "$lockfile" > `+shellQuote(seenArg)+`
printf '{"lockfileVersion":3,"packages":{"node_modules/evil":{"version":"9.9.9"}}}\n' > `+shellQuote(lockfile)+`
/bin/cat "$lockfile" > `+shellQuote(seenContent)+`
echo '{"results":[{"source":{"path":"'"$lockfile"'"},"packages":[{"package":{"name":"vuln","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":"GHSA-copy","database_specific":{"severity":"HIGH"}}]}]}]}'
exit 1
`)
	t.Setenv("PATH", root)

	findings, diagnostics, snapshot := runOSVScannerProvider(t.Context(), "run", []string{project})

	if len(diagnostics) != 0 || snapshot.Status != "ok" {
		t.Fatalf("diagnostics = %#v snapshot = %#v, want successful copied read", diagnostics, snapshot)
	}
	if len(findings) != 1 || findings[0].ProviderRecordID != "GHSA-copy" || findings[0].SourcePath != lockfile {
		t.Fatalf("findings = %#v, want copied source remapped to original lockfile path", findings)
	}
	arg := readTextFile(t, seenArg)
	if arg == lockfile || !strings.Contains(arg, "lsec-scan-provider-") {
		t.Fatalf("osv-scanner arg = %q, want provider temp copy", arg)
	}
	if got := readTextFile(t, seenContent); !strings.Contains(got, `"node_modules/vuln"`) || strings.Contains(got, "node_modules/evil") {
		t.Fatalf("copied lockfile content = %q, want original safe content", got)
	}
}
