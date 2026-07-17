package lsec

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const safeCycloneDXSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.5",
	"components": [{"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]
}`

func TestGrypeMissingIsNonFatalWhenSafeSBOMExists(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "bom.json"), safeCycloneDXSBOM)
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
		t.Fatalf("records = %#v, missing grype should not make scan partial", records)
	}
	if hasDiagnostic(records, "provider_unavailable") || hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, missing grype should not emit provider diagnostic", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasSnapshot(body, "provider", "grype", "status", "not_available") {
		t.Fatalf("provider snapshots = %s, want missing grype snapshot", string(body))
	}
	snapshot := readProviderSnapshot(t, lsecHome, runID, "grype")
	if snapshot.CandidateCount != 1 || snapshot.AcceptedCount != 1 || snapshot.SkippedCount != 0 || snapshot.QueriedCount != 0 || snapshot.FailedCount != 0 {
		t.Fatalf("snapshot = %#v, want one accepted candidate and no query for missing provider", snapshot)
	}
}

func TestGrypeNetworkOffDoesNotInvokeProvider(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	marker := filepath.Join(root, "grype-called")
	writeFile(t, filepath.Join(project, "sbom.json"), safeCycloneDXSBOM)
	writeFakeTool(t, root, "grype", "#!/bin/sh\nprintf called > "+shellQuote(marker)+"\n")
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("grype marker stat err = %v, want not invoked", err)
	}
}

func TestGrypeDoesNotRunWithoutAcceptedSBOMObservation(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	marker := filepath.Join(root, "grype-called")
	writeFile(t, filepath.Join(project, "bom.json"), `{
		"bomFormat": "CycloneDX",
		"components": [{"type":"library","name":"left-pad","version":"1.3.0"}]
	}`)
	writeFakeTool(t, root, "grype", "#!/bin/sh\nprintf called > "+shellQuote(marker)+"\n")
	withFakeOSVBatch(t, `{"results":[]}`)
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "advisories", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("grype marker stat err = %v, want not invoked", err)
	}
}

func TestGrypeReceivesAcceptedCycloneDXSBOMObservationPaths(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	argsPath := filepath.Join(root, "args.txt")
	safeA := filepath.Join(project, "bom.json")
	safeB := filepath.Join(project, "nested", "deps.cdx.json")
	acceptedUnderNodeModules := filepath.Join(project, "node_modules", "pkg", "bom.json")
	writeFile(t, safeA, safeCycloneDXSBOM)
	writeFile(t, safeB, safeCycloneDXSBOM)
	writeFile(t, filepath.Join(project, "not-cyclonedx", "sbom.json"), `{"bomFormat":"SPDX"}`)
	writeFile(t, filepath.Join(project, "malformed", "bad.cdx.json"), `{"bomFormat":"CycloneDX","components":`)
	writeFile(t, filepath.Join(project, "src", "index.js"), `console.log("nope")`)
	writeFile(t, acceptedUnderNodeModules, safeCycloneDXSBOM)
	writeFile(t, filepath.Join(project, "regular.txt"), safeCycloneDXSBOM)
	if err := os.MkdirAll(filepath.Join(project, "nonregular", "sbom.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(project, "linked.cdx.json")
	if err := os.Symlink(safeA, linkPath); err != nil {
		t.Fatal(err)
	}
	writeFakeTool(t, root, "grype", "#!/bin/sh\nprintf '%s\\n' \"$@\" >> "+shellQuote(argsPath)+"\necho '{\"matches\":[]}'\n")
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
	if len(gotArgs) != 9 {
		t.Fatalf("grype args = %#v, want three invocations", gotArgs)
	}
	for i := 0; i < len(gotArgs); i += 3 {
		if !strings.HasPrefix(gotArgs[i], "sbom:") || gotArgs[i+1] != "-o" || gotArgs[i+2] != "json" {
			t.Fatalf("grype args = %#v, want copied SBOM invocations", gotArgs)
		}
		copied := strings.TrimPrefix(gotArgs[i], "sbom:")
		if !strings.Contains(copied, "lsec-scan-provider-") || !filepath.IsAbs(copied) {
			t.Fatalf("grype sbom arg = %q, want private provider copy", gotArgs[i])
		}
	}
	for _, unwanted := range []string{
		project,
		safeA,
		safeB,
		acceptedUnderNodeModules,
		filepath.Join(project, "not-cyclonedx", "sbom.json"),
		filepath.Join(project, "malformed", "bad.cdx.json"),
		filepath.Join(project, "src", "index.js"),
		filepath.Join(project, "regular.txt"),
		filepath.Join(project, "nonregular", "sbom.json"),
		linkPath,
	} {
		if strings.Contains(got, unwanted+"\n") || strings.Contains(got, "sbom:"+unwanted+"\n") {
			t.Fatalf("grype args = %q, should not include %s", got, unwanted)
		}
	}
}

func TestGrypeJSONOutputMapsFinding(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	sbom := filepath.Join(project, "bom.json")
	writeFile(t, sbom, safeCycloneDXSBOM)
	writeFakeTool(t, root, "grype", `#!/bin/sh
echo '{"matches":[{"vulnerability":{"id":"CVE-2026-0001","severity":"Critical","description":"bad left-pad vuln"},"artifact":{"name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}}]}'
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
	if !hasProviderScanFinding(records, "grype", "CVE-2026-0001", "vulnerability", "high") {
		t.Fatalf("records = %#v, want grype vulnerability finding", records)
	}
}

func TestGrypeJSONOutputIgnoresFindingWithoutArtifactPURL(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	sbom := filepath.Join(project, "bom.json")
	writeFile(t, sbom, safeCycloneDXSBOM)
	writeFakeTool(t, root, "grype", `#!/bin/sh
echo '{"matches":[{"vulnerability":{"id":"CVE-no-purl","severity":"Critical","description":"bad left-pad vuln"},"artifact":{"type":"npm","name":"left-pad","version":"1.3.0"}}]}'
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
	if hasProviderScanFinding(records, "grype", "CVE-no-purl", "vulnerability", "high") {
		t.Fatalf("records = %#v, Grype finding without artifact purl should be ignored", records)
	}
}

func TestGrypeJSONOutputIgnoresStderrNoise(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "bom.json"), safeCycloneDXSBOM)
	writeFakeTool(t, root, "grype", `#!/bin/sh
echo 'warning: noisy stderr' >&2
echo '{"matches":[{"vulnerability":{"id":"CVE-stderr-noise","severity":"High","description":"bad left-pad vuln"},"artifact":{"name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}}]}'
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
	if !hasProviderScanFinding(records, "grype", "CVE-stderr-noise", "vulnerability", "review") {
		t.Fatalf("records = %#v, want grype finding despite stderr noise", records)
	}
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, want complete scan when grype emits stderr noise with valid json", records)
	}
	if hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, valid grype json with stderr noise should not emit provider_failed", records)
	}
}

func TestGrypeFailureMakesScanPartialAndCapsOutput(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "bom.json"), safeCycloneDXSBOM)
	writeFakeTool(t, root, "grype", `#!/bin/sh
i=0
while [ "$i" -lt 9000 ]; do
	printf 'x' >&2
	i=$((i + 1))
done
printf 'TAIL_SECRET' >&2
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
		t.Fatalf("records = %#v, want partial scan on grype failure", records)
	}
	message := diagnosticMessage(records, "provider_failed")
	if !strings.Contains(message, "truncated") {
		t.Fatalf("provider_failed message = %q, want truncation marker", message)
	}
	if strings.Contains(stdout.String(), "TAIL_SECRET") || len(message) > 1200 {
		t.Fatalf("provider_failed message was not bounded: len=%d body=%q", len(message), message)
	}
}

func TestGrypeInvalidJSONMakesScanPartial(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "bom.json"), safeCycloneDXSBOM)
	writeFakeTool(t, root, "grype", "#!/bin/sh\necho '{not-json'\n")
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
		t.Fatalf("records = %#v, want partial scan on invalid grype json", records)
	}
	if !hasDiagnostic(records, "provider_failed") {
		t.Fatalf("records = %#v, want provider_failed diagnostic", records)
	}
	runID, _ := scanSummaryRecord(t, records)["run_id"].(string)
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasSnapshot(body, "provider", "grype", "status", "error") {
		t.Fatalf("provider snapshots = %s, want grype error snapshot", string(body))
	}
}

func TestGrypeKeepsEarlierFindingsAndCountsFailedInput(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	first := filepath.Join(project, "a", "bom.json")
	second := filepath.Join(project, "z", "bom.json")
	observations := []ScanObservation{
		{SourceType: "cyclonedx_sbom", SourcePath: first},
		{SourceType: "cyclonedx_sbom", SourcePath: second},
	}
	writeFile(t, first, safeCycloneDXSBOM)
	writeFile(t, second, safeCycloneDXSBOM)
	writeFakeTool(t, root, "grype", `#!/bin/sh
count_file=`+shellQuote(filepath.Join(root, "grype-count"))+`
count=0
if [ -f "$count_file" ]; then
  IFS= read -r count < "$count_file"
fi
count=$((count + 1))
printf '%s' "$count" > "$count_file"
if [ "$count" -eq 1 ]; then
  echo '{"matches":[{"vulnerability":{"id":"CVE-retained","severity":"high"},"artifact":{"purl":"pkg:npm/left-pad@1.3.0"}}]}'
else
  echo 'secret provider output from /private/project/bom.json' >&2
  exit 2
fi
`)
	t.Setenv("PATH", root)

	findings, diagnostics, snapshot := runGrypeProvider(t.Context(), "run", observations)

	if len(findings) != 1 || findings[0].ProviderRecordID != "CVE-retained" {
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

func TestGrypeReadsCopiedSBOMAfterOriginalChanges(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	sbom := filepath.Join(project, "bom.json")
	seenArg := filepath.Join(root, "seen-arg")
	seenContent := filepath.Join(root, "seen-content")
	writeFile(t, sbom, safeCycloneDXSBOM)
	writeFakeTool(t, root, "grype", `#!/bin/sh
sbom="${1#sbom:}"
printf '%s' "$sbom" > `+shellQuote(seenArg)+`
printf '{"bomFormat":"CycloneDX","components":[{"name":"evil"}]}\n' > `+shellQuote(sbom)+`
/bin/cat "$sbom" > `+shellQuote(seenContent)+`
echo '{"matches":[{"vulnerability":{"id":"CVE-copy","severity":"critical"},"artifact":{"purl":"pkg:npm/left-pad@1.3.0"}}]}'
`)
	t.Setenv("PATH", root)

	findings, diagnostics, snapshot := runGrypeProvider(t.Context(), "run", []ScanObservation{{SourceType: "cyclonedx_sbom", SourcePath: sbom}})

	if len(diagnostics) != 0 || snapshot.Status != "ok" {
		t.Fatalf("diagnostics = %#v snapshot = %#v, want successful copied read", diagnostics, snapshot)
	}
	if len(findings) != 1 || findings[0].ProviderRecordID != "CVE-copy" || findings[0].SourcePath != sbom {
		t.Fatalf("findings = %#v, want finding mapped to original SBOM path", findings)
	}
	arg := readTextFile(t, seenArg)
	if arg == sbom || !strings.Contains(arg, "lsec-scan-provider-") {
		t.Fatalf("grype arg = %q, want provider temp copy", arg)
	}
	if got := readTextFile(t, seenContent); got != safeCycloneDXSBOM {
		t.Fatalf("copied SBOM content = %q, want original safe content", got)
	}
}
