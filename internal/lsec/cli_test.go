package lsec

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunEvidenceEmitsJSONBundle(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := Run([]string{"evidence", "curl", "http://example.invalid/install.sh"}, strings.NewReader(""), &stdout, &stderr)

	if err != nil {
		t.Fatal(err)
	}
	var bundle EvidenceBundle
	if err := json.Unmarshal(stdout.Bytes(), &bundle); err != nil {
		t.Fatalf("stdout is not evidence JSON: %q err=%v", stdout.String(), err)
	}
	if bundle.Analysis.Manager != "curl" {
		t.Fatalf("manager = %q, want curl", bundle.Analysis.Manager)
	}
	if bundle.Decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %q, want block", bundle.Decision.Verdict)
	}
	if bundle.Sandbox.FakeEnvironment != nil {
		t.Fatal("evidence command should not include fake secrets before sandbox evidence exists")
	}
}

func TestRewriteCommandUsesStagedNPMArtifact(t *testing.T) {
	got := rewriteCommandForSelectedVersion([]string{"npm", "install", "left-pad"}, RunReport{
		Analysis: CommandAnalysis{
			Manager: "npm",
			Action:  "install",
			PackageSpecs: []PackageSpec{{
				Raw:  "left-pad",
				Name: "left-pad",
			}},
		},
		Version: VersionInfo{Found: true, Selected: RegistryVersion{Version: "1.3.0"}},
		Artifacts: []Artifact{{
			Path: "/tmp/left-pad-1.3.0.tgz",
			Kind: "tar",
		}},
	})

	if got[2] != "/tmp/left-pad-1.3.0.tgz" {
		t.Fatalf("rewritten package = %q, want staged artifact path", got[2])
	}
	if !stringSliceContains(got, "--ignore-scripts") {
		t.Fatalf("command = %#v, want --ignore-scripts for real npm install", got)
	}
}

func TestRewriteNPMInstallDoesNotDuplicateIgnoreScripts(t *testing.T) {
	got := rewriteCommandForSelectedVersion([]string{"npm", "install", "--ignore-scripts", "left-pad"}, RunReport{
		Analysis: CommandAnalysis{
			Manager: "npm",
			Action:  "install",
			PackageSpecs: []PackageSpec{{
				Raw:  "left-pad",
				Name: "left-pad",
			}},
		},
		Version: VersionInfo{Found: true, Selected: RegistryVersion{Version: "1.3.0"}},
		Artifacts: []Artifact{{
			Path: "/tmp/left-pad-1.3.0.tgz",
			Kind: "tar",
		}},
	})

	count := 0
	for _, arg := range got {
		if arg == "--ignore-scripts" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("command = %#v, want one --ignore-scripts", got)
	}
}

func TestRewriteCommandUsesStagedPipArtifact(t *testing.T) {
	got := rewriteCommandForSelectedVersion([]string{"python3", "-m", "pip", "install", "dspy"}, RunReport{
		Analysis: CommandAnalysis{
			Manager:         "pip",
			Action:          "install",
			PythonModulePip: true,
			PackageSpecs: []PackageSpec{{
				Raw:  "dspy",
				Name: "dspy",
			}},
		},
		Version: VersionInfo{Found: true, Selected: RegistryVersion{Version: "2.0.0"}},
		Artifacts: []Artifact{{
			Path: "/tmp/dspy-2.0.0-py3-none-any.whl",
			Kind: "wheel",
		}},
	})

	wantPrefix := []string{"python3", "-m", "pip", "install", "--no-index", "--no-deps", "/tmp/dspy-2.0.0-py3-none-any.whl"}
	if len(got) != len(wantPrefix) {
		t.Fatalf("command = %#v, want %#v", got, wantPrefix)
	}
	for i, want := range wantPrefix {
		if got[i] != want {
			t.Fatalf("command[%d] = %q, want %q in %#v", i, got[i], want, got)
		}
	}
}

func TestRewritePipInstallUsesWheelhouseForMultipleArtifacts(t *testing.T) {
	got := rewriteCommandForSelectedVersion([]string{"python3", "-m", "pip", "install", "example"}, RunReport{
		Analysis: CommandAnalysis{
			Manager:         "pip",
			Action:          "install",
			PythonModulePip: true,
			PackageSpecs: []PackageSpec{{
				Raw:  "example",
				Name: "example",
			}},
		},
		Version: VersionInfo{Found: true, Selected: RegistryVersion{Version: "1.0.0"}},
		Artifacts: []Artifact{
			{Path: "/tmp/wheelhouse/example-1.0.0-py3-none-any.whl", Kind: "wheel"},
			{Path: "/tmp/wheelhouse/dep_pkg-2.0.0-py3-none-any.whl", Kind: "wheel"},
		},
	})

	wantPrefix := []string{"python3", "-m", "pip", "install", "--no-index", "--find-links", "/tmp/wheelhouse", "example==1.0.0"}
	if len(got) != len(wantPrefix) {
		t.Fatalf("command = %#v, want %#v", got, wantPrefix)
	}
	for i, want := range wantPrefix {
		if got[i] != want {
			t.Fatalf("command[%d] = %q, want %q in %#v", i, got[i], want, got)
		}
	}
	if stringSliceContains(got, "--no-deps") {
		t.Fatalf("command = %#v, did not expect --no-deps for recursive wheelhouse install", got)
	}
}

func TestRefreshDependencyAdvisoriesChecksExactDependencies(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	withFakeOSV(t, `{
		"vulns": [{
			"id": "GHSA-dependency",
			"summary": "dependency advisory",
			"database_specific": {"severity": "HIGH"}
		}]
	}`)

	advisories, findings := RefreshDependencyAdvisories(context.Background(), store, []Artifact{{
		Dependencies: []DependencyRef{{
			Ecosystem: "npm",
			Name:      "dep-pkg",
			Version:   "1.2.3",
			Raw:       "1.2.3",
			Exact:     true,
		}},
	}}, 30*time.Minute)

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if len(advisories) != 1 || advisories[0].Name != "dep-pkg" || advisories[0].ID != "GHSA-dependency" {
		t.Fatalf("advisories = %#v, want dependency advisory", advisories)
	}
}

func TestRefreshDependencyAdvisoriesIncludesExternalAdvisories(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFakeTool(t, bin, "socket", `#!/bin/sh
echo '{"alerts":[{"name":"knownMalware","severity":"critical","type":"malware","title":"Known malware"}]}'
`)
	t.Setenv("PATH", bin)
	withFakeOSV(t, `{"vulns":[]}`)

	advisories, findings := RefreshDependencyAdvisories(context.Background(), store, []Artifact{{
		Dependencies: []DependencyRef{{
			Ecosystem: "npm",
			Name:      "dep-pkg",
			Version:   "1.2.3",
			Raw:       "1.2.3",
			Exact:     true,
		}},
	}}, 30*time.Minute)

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if !hasAdvisory(advisories, "socket", "critical", "malware") {
		t.Fatalf("advisories = %#v, want socket dependency advisory", advisories)
	}
}

func TestPreflightLockfileInstallDoesNotRunNpmPack(t *testing.T) {
	root := t.TempDir()
	writeNpmLockfile(t, root)
	marker := filepath.Join(root, "npm-called")
	bin := t.TempDir()
	writeFakeTool(t, bin, "npm", "#!/bin/sh\nprintf called > '"+marker+"'\nexit 0\n")
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Chdir(root)
	withFakeOSV(t, `{"vulns":[]}`)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	_, err := preflight([]string{"npm", "install"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("npm was executed during lockfile preflight")
	}
}

func TestPreflightLockfileInstallIncludesSocketAdvisory(t *testing.T) {
	root := t.TempDir()
	writeNpmLockfile(t, root)
	bin := t.TempDir()
	writeFakeTool(t, bin, "socket", `#!/bin/sh
echo '{"alerts":[{"name":"knownMalware","severity":"critical","type":"malware","title":"Known malware"}]}'
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Chdir(root)
	withFakeOSV(t, `{"vulns":[]}`)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"npm", "install"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if report.Decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %q, want block; report = %#v", report.Decision.Verdict, report)
	}
	if !hasAdvisory(report.Advisories, "socket", "critical", "malware") {
		t.Fatalf("advisories = %#v, want socket critical malware", report.Advisories)
	}
}

func TestPreflightNPMCreateUsesMappedPackageForAdvisories(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	writeFakeTool(t, bin, "npm", "#!/bin/sh\nexit 1\n")
	t.Setenv("PATH", bin)
	t.Chdir(root)
	withFakeOSV(t, `{"vulns":[]}`)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"npm", "create", "vite@1.2.3"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Analysis.PackageSpecs) != 1 || report.Analysis.PackageSpecs[0].Name != "create-vite" {
		t.Fatalf("package specs = %#v, want create-vite", report.Analysis.PackageSpecs)
	}
	if report.Decision.Verdict == VerdictAllow {
		t.Fatalf("verdict = allow, want prompt/block for one-shot npm create")
	}
}

func TestPreflightFollowsAdvisoryToOlderCleanVersionBeforeStaging(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	writeFakeTool(t, bin, "npm", `#!/bin/sh
dest=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--pack-destination" ]; then
    dest="$2"
    shift 2
  else
    shift
  fi
done
mkdir -p "$dest/pkg/package"
printf '{"name":"example","version":"2.4.7"}' > "$dest/pkg/package/package.json"
tar -czf "$dest/example-2.4.7.tgz" -C "$dest/pkg" package
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Chdir(root)
	now := time.Now().UTC()
	withFakeDefaultHTTP(t, fmt.Sprintf(`{
		"dist-tags":{"latest":"2.4.9"},
		"time":{
			"created":"%s",
			"modified":"%s",
			"2.4.9":"%s",
			"2.4.8":"%s",
			"2.4.7":"%s"
		}
	}`, now.Add(-90*24*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339), now.Add(-3*time.Hour).Format(time.RFC3339), now.Add(-19*24*time.Hour).Format(time.RFC3339), now.Add(-60*24*time.Hour).Format(time.RFC3339)))
	withFakeOSVByVersion(t, map[string]string{
		"2.4.8": `{"vulns":[{"id":"GHSA-bad","summary":"bad","database_specific":{"severity":"CRITICAL"}}]}`,
		"2.4.7": `{"vulns":[]}`,
	})
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"npm", "install", "example"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if report.Version.Selected.Version != "2.4.7" {
		t.Fatalf("selected version = %s, want 2.4.7", report.Version.Selected.Version)
	}
	if len(report.Artifacts) != 1 || !strings.Contains(report.Artifacts[0].Path, "example-2.4.7.tgz") {
		t.Fatalf("artifacts = %#v, want staged 2.4.7 tarball", report.Artifacts)
	}
	if !hasSkippedVersion(report.Version.Skipped, "2.4.8", "advisory") {
		t.Fatalf("skipped = %#v, want advisory skip for 2.4.8", report.Version.Skipped)
	}
}

func TestPreflightChecksStagedDependencyAdvisoriesAfterTopLevelFollow(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	writeFakeTool(t, bin, "npm", `#!/bin/sh
dest=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--pack-destination" ]; then
    dest="$2"
    shift 2
  else
    shift
  fi
done
mkdir -p "$dest/pkg/package"
printf '{"name":"example","version":"2.4.7","dependencies":{"dep-pkg":"1.2.3"}}' > "$dest/pkg/package/package.json"
tar -czf "$dest/example-2.4.7.tgz" -C "$dest/pkg" package
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Chdir(root)
	now := time.Now().UTC()
	withFakeDefaultHTTP(t, fmt.Sprintf(`{
		"dist-tags":{"latest":"2.4.7"},
		"time":{
			"created":"%s",
			"modified":"%s",
			"2.4.7":"%s"
		}
	}`, now.Add(-90*24*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339), now.Add(-60*24*time.Hour).Format(time.RFC3339)))
	withFakeOSVByVersion(t, map[string]string{
		"1.2.3": `{"vulns":[{"id":"GHSA-dep","summary":"bad dep","database_specific":{"severity":"CRITICAL"}}]}`,
	})
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"npm", "install", "example"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if report.Decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %q, want block for dependency advisory; report = %#v", report.Decision.Verdict, report)
	}
	if !hasNamedAdvisory(report.Advisories, "dep-pkg", "GHSA-dep") {
		t.Fatalf("advisories = %#v, want dep-pkg GHSA-dep", report.Advisories)
	}
}

func TestPreflightBlocksAdvisoryOnResolvedPipDependencyWheel(t *testing.T) {
	root := t.TempDir()
	fixtures := t.TempDir()
	topWheel := filepath.Join(fixtures, "example-1.0.0-py3-none-any.whl")
	depWheel := filepath.Join(fixtures, "dep_pkg-2.0.0-py3-none-any.whl")
	writeTestWheel(t, topWheel, "example-1.0.0.dist-info", "Name: example\nVersion: 1.0.0\nRequires-Dist: dep-pkg (>=2)\n")
	writeTestWheel(t, depWheel, "dep_pkg-2.0.0.dist-info", "Name: dep-pkg\nVersion: 2.0.0\n")
	bin := t.TempDir()
	writeFakeTool(t, bin, "python3", `#!/bin/sh
dest=""
for arg in "$@"; do
  if [ "$arg" = "--no-deps" ]; then
    echo "unexpected --no-deps" >&2
    exit 2
  fi
done
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-d" ]; then
    dest="$2"
    shift 2
  else
    shift
  fi
done
mkdir -p "$dest"
cp `+shellQuote(topWheel)+` "$dest/"
cp `+shellQuote(depWheel)+` "$dest/"
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Chdir(root)
	now := time.Now().UTC()
	withFakeDefaultHTTP(t, fmt.Sprintf(`{
		"info":{"version":"1.0.0"},
		"releases":{"1.0.0":[{"upload_time_iso_8601":"%s","yanked":false}]}
	}`, now.Add(-30*24*time.Hour).Format(time.RFC3339Nano)))
	withFakeOSVByVersion(t, map[string]string{
		"1.0.0": `{"vulns":[]}`,
		"2.0.0": `{"vulns":[{"id":"GHSA-dep","summary":"bad dependency","database_specific":{"severity":"CRITICAL"}}]}`,
	})
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"pip", "install", "example"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if report.Decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %q, want block for resolved dependency advisory; report = %#v", report.Decision.Verdict, report)
	}
	if !hasNamedAdvisory(report.Advisories, "dep-pkg", "GHSA-dep") {
		t.Fatalf("advisories = %#v, want dep-pkg GHSA-dep", report.Advisories)
	}
	if firstFindingSeverity(report.Findings, "python_source_build_or_download_failed") != "" {
		t.Fatalf("findings = %#v, did not expect wheel download failure", report.Findings)
	}
}

func TestPreflightPromptsOnFreshResolvedPipDependencyWheel(t *testing.T) {
	root := t.TempDir()
	fixtures := t.TempDir()
	topWheel := filepath.Join(fixtures, "example-1.0.0-py3-none-any.whl")
	depWheel := filepath.Join(fixtures, "dep_pkg-2.0.0-py3-none-any.whl")
	writeTestWheel(t, topWheel, "example-1.0.0.dist-info", "Name: example\nVersion: 1.0.0\nRequires-Dist: dep-pkg (>=2)\n")
	writeTestWheel(t, depWheel, "dep_pkg-2.0.0.dist-info", "Name: dep-pkg\nVersion: 2.0.0\n")
	bin := t.TempDir()
	writeFakeTool(t, bin, "python3", `#!/bin/sh
dest=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-d" ]; then
    dest="$2"
    shift 2
  else
    shift
  fi
done
mkdir -p "$dest"
cp `+shellQuote(topWheel)+` "$dest/"
cp `+shellQuote(depWheel)+` "$dest/"
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Chdir(root)
	now := time.Now().UTC()
	withFakePyPIMetadata(t, map[string]string{
		"example": fmt.Sprintf(`{
			"info":{"version":"1.0.0"},
			"releases":{"1.0.0":[{"upload_time_iso_8601":"%s","yanked":false}]}
		}`, now.Add(-30*24*time.Hour).Format(time.RFC3339Nano)),
		"dep-pkg": fmt.Sprintf(`{
			"info":{"version":"2.0.0"},
			"releases":{"2.0.0":[{"upload_time_iso_8601":"%s","yanked":false}]}
		}`, now.Add(-2*time.Hour).Format(time.RFC3339Nano)),
	})
	withFakeOSV(t, `{"vulns":[]}`)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"pip", "install", "example"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if report.Decision.Verdict != VerdictPrompt {
		t.Fatalf("verdict = %q, want prompt for fresh resolved dependency; report = %#v", report.Decision.Verdict, report)
	}
	if firstFindingSeverity(report.Findings, "artifact_version_inside_maturity_window") != "prompt" {
		t.Fatalf("findings = %#v, want artifact_version_inside_maturity_window prompt", report.Findings)
	}
}

func TestTopLevelApprovalDoesNotSuppressDependencyPrompt(t *testing.T) {
	root := t.TempDir()
	fixtures := t.TempDir()
	topWheel := filepath.Join(fixtures, "aaa-1.0.0-py3-none-any.whl")
	depWheel := filepath.Join(fixtures, "zzz_dep-2.0.0-py3-none-any.whl")
	writeTestWheel(t, topWheel, "aaa-1.0.0.dist-info", "Name: aaa\nVersion: 1.0.0\nRequires-Dist: zzz-dep (>=2)\n")
	writeTestWheel(t, depWheel, "zzz_dep-2.0.0.dist-info", "Name: zzz-dep\nVersion: 2.0.0\n")
	topHash, err := fileSHA256(topWheel)
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFakeTool(t, bin, "python3", `#!/bin/sh
dest=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-d" ]; then
    dest="$2"
    shift 2
  else
    shift
  fi
done
mkdir -p "$dest"
cp `+shellQuote(topWheel)+` "$dest/"
cp `+shellQuote(depWheel)+` "$dest/"
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Chdir(root)
	now := time.Now().UTC()
	withFakePyPIMetadata(t, map[string]string{
		"aaa": fmt.Sprintf(`{
			"info":{"version":"1.0.0"},
			"releases":{"1.0.0":[{"upload_time_iso_8601":"%s","yanked":false}]}
		}`, now.Add(-30*24*time.Hour).Format(time.RFC3339Nano)),
		"zzz-dep": fmt.Sprintf(`{
			"info":{"version":"2.0.0"},
			"releases":{"2.0.0":[{"upload_time_iso_8601":"%s","yanked":false}]}
		}`, now.Add(-2*time.Hour).Format(time.RFC3339Nano)),
	})
	withFakeOSV(t, `{"vulns":[]}`)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.AddApproval(Approval{Ecosystem: "PyPI", Name: "aaa", Version: "1.0.0", Hash: topHash, Reason: "top reviewed"}); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"pip", "install", "aaa"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if report.Decision.Verdict != VerdictPrompt {
		t.Fatalf("verdict = %q, want prompt because dependency is fresh despite top-level approval; report = %#v", report.Decision.Verdict, report)
	}
}

func TestAllArtifactApprovalsAllowDependencyPrompt(t *testing.T) {
	root := t.TempDir()
	fixtures := t.TempDir()
	topWheel := filepath.Join(fixtures, "aaa-1.0.0-py3-none-any.whl")
	depWheel := filepath.Join(fixtures, "zzz_dep-2.0.0-py3-none-any.whl")
	writeTestWheel(t, topWheel, "aaa-1.0.0.dist-info", "Name: aaa\nVersion: 1.0.0\nRequires-Dist: zzz-dep (>=2)\n")
	writeTestWheel(t, depWheel, "zzz_dep-2.0.0.dist-info", "Name: zzz-dep\nVersion: 2.0.0\n")
	topHash, err := fileSHA256(topWheel)
	if err != nil {
		t.Fatal(err)
	}
	depHash, err := fileSHA256(depWheel)
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFakeTool(t, bin, "python3", `#!/bin/sh
dest=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-d" ]; then
    dest="$2"
    shift 2
  else
    shift
  fi
done
mkdir -p "$dest"
cp `+shellQuote(topWheel)+` "$dest/"
cp `+shellQuote(depWheel)+` "$dest/"
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Chdir(root)
	now := time.Now().UTC()
	withFakePyPIMetadata(t, map[string]string{
		"aaa": fmt.Sprintf(`{
			"info":{"version":"1.0.0"},
			"releases":{"1.0.0":[{"upload_time_iso_8601":"%s","yanked":false}]}
		}`, now.Add(-30*24*time.Hour).Format(time.RFC3339Nano)),
		"zzz-dep": fmt.Sprintf(`{
			"info":{"version":"2.0.0"},
			"releases":{"2.0.0":[{"upload_time_iso_8601":"%s","yanked":false}]}
		}`, now.Add(-2*time.Hour).Format(time.RFC3339Nano)),
	})
	withFakeOSV(t, `{"vulns":[]}`)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.AddApproval(Approval{Ecosystem: "PyPI", Name: "aaa", Version: "1.0.0", Hash: topHash, Reason: "top reviewed"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddApproval(Approval{Ecosystem: "PyPI", Name: "zzz-dep", Version: "2.0.0", Hash: depHash, Reason: "dep reviewed"}); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"pip", "install", "aaa"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if report.Decision.Verdict != VerdictAllow {
		t.Fatalf("verdict = %q, want allow when every artifact is approved; report = %#v", report.Decision.Verdict, report)
	}
}

func TestPreflightBlocksStagedPackageWithUnexpandedDependencies(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	writeFakeTool(t, bin, "npm", `#!/bin/sh
dest=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--pack-destination" ]; then
    dest="$2"
    shift 2
  else
    shift
  fi
done
mkdir -p "$dest/pkg/package"
printf '{"name":"example","version":"2.4.7","dependencies":{"dep-pkg":"1.2.3"}}' > "$dest/pkg/package/package.json"
tar -czf "$dest/example-2.4.7.tgz" -C "$dest/pkg" package
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Chdir(root)
	now := time.Now().UTC()
	withFakeDefaultHTTP(t, fmt.Sprintf(`{
		"dist-tags":{"latest":"2.4.7"},
		"time":{
			"created":"%s",
			"modified":"%s",
			"2.4.7":"%s"
		}
	}`, now.Add(-90*24*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339), now.Add(-60*24*time.Hour).Format(time.RFC3339)))
	withFakeOSV(t, `{"vulns":[]}`)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"npm", "install", "example"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if report.Decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %q, want block because dependencies are not staged recursively; report = %#v", report.Decision.Verdict, report)
	}
	if firstFindingSeverity(report.Findings, "dependency_metadata_present") != "block" {
		t.Fatalf("findings = %#v, want blocking dependency metadata finding", report.Findings)
	}
}

func TestRewritePipRequirementsUsesStagedWheelhouse(t *testing.T) {
	got := rewriteCommandForSelectedVersion([]string{"python3", "-m", "pip", "install", "-r", "requirements.txt"}, RunReport{
		Analysis: CommandAnalysis{
			Manager:          "pip",
			RequirementsFile: true,
			RequirementFiles: []string{"requirements.txt"},
			PackageSpecs: []PackageSpec{{
				Raw:     "requests==2.31.0",
				Name:    "requests",
				Version: "2.31.0",
			}},
		},
		Artifacts: []Artifact{{
			Path: "/tmp/lsec-stage/requests-2.31.0-py3-none-any.whl",
			Kind: "wheel",
		}},
	})

	wantPrefix := []string{"python3", "-m", "pip", "install", "--require-hashes", "--no-index", "--find-links", "/tmp/lsec-stage"}
	if len(got) < len(wantPrefix) {
		t.Fatalf("command = %#v, too short", got)
	}
	for i, want := range wantPrefix {
		if got[i] != want {
			t.Fatalf("command[%d] = %q, want %q in %#v", i, got[i], want, got)
		}
	}
	if stringSliceContains(got, "--no-deps") {
		t.Fatalf("command = %#v, did not expect --no-deps for requirements wheelhouse install", got)
	}
}

func TestPreflightRequirementsAdvisoryBlocksBeforePipDownload(t *testing.T) {
	root := t.TempDir()
	requirementsPath := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(requirementsPath, []byte("badpkg==1.0.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "pip-download-called")
	bin := t.TempDir()
	writeFakeTool(t, bin, "python3", "#!/bin/sh\nprintf called > "+shellQuote(marker)+"\n")
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Chdir(root)
	withFakeOSV(t, `{"vulns":[{"id":"MAL-REQ","summary":"malicious requirement"}]}`)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"python3", "-m", "pip", "install", "-r", "requirements.txt"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if report.Decision.Verdict != VerdictBlock {
		t.Fatalf("verdict = %q, want block for requirement advisory; report = %#v", report.Decision.Verdict, report)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("pip download ran before top-level requirements advisory check")
	}
}

func TestPreflightPromptsOnFreshNpmLockfilePackage(t *testing.T) {
	root := t.TempDir()
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app"},
			"node_modules/fresh-pkg": {
				"version": "1.0.0",
				"integrity": "sha512-test",
				"resolved": "https://registry.npmjs.org/fresh-pkg/-/fresh-pkg-1.0.0.tgz"
			}
		}
	}`)
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	now := time.Now().UTC()
	withFakeNPMMetadata(t, map[string]string{
		"fresh-pkg": fmt.Sprintf(`{
			"dist-tags":{"latest":"1.0.0"},
			"time":{
				"created":"%s",
				"modified":"%s",
				"1.0.0":"%s"
			}
		}`, now.Add(-2*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339), now.Add(-2*time.Hour).Format(time.RFC3339)),
	})
	withFakeOSV(t, `{"vulns":[]}`)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	report, err := preflight([]string{"npm", "install"}, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}

	if report.Decision.Verdict != VerdictPrompt {
		t.Fatalf("verdict = %q, want prompt for fresh lockfile package; report = %#v", report.Decision.Verdict, report)
	}
	if firstFindingSeverity(report.Findings, "package_version_inside_maturity_window") != "prompt" {
		t.Fatalf("findings = %#v, want package_version_inside_maturity_window prompt", report.Findings)
	}
}

func writeNpmLockfile(t *testing.T, root string) {
	t.Helper()
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app"},
			"node_modules/left-pad": {
				"version": "1.3.0",
				"integrity": "sha512-test"
			}
		}
	}`)
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasSkippedVersion(skipped []VersionSkip, version, reason string) bool {
	for _, item := range skipped {
		if item.Version == version && item.Reason == reason {
			return true
		}
	}
	return false
}

func hasNamedAdvisory(advisories []Advisory, name, id string) bool {
	for _, advisory := range advisories {
		if advisory.Name == name && advisory.ID == id {
			return true
		}
	}
	return false
}

func stringSliceContains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestRewriteNpmLockfileInstallUsesCiIgnoreScripts(t *testing.T) {
	got := rewriteCommandForSelectedVersion([]string{"npm", "install"}, RunReport{
		Analysis: CommandAnalysis{
			Manager:         "npm",
			LockfileInstall: true,
			LockfilePath:    "package-lock.json",
			PackageSpecs: []PackageSpec{{
				Raw:     "left-pad@1.3.0",
				Name:    "left-pad",
				Version: "1.3.0",
			}},
		},
	})

	want := []string{"npm", "ci", "--ignore-scripts"}
	if len(got) != len(want) {
		t.Fatalf("command = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command[%d] = %q, want %q in %#v", i, got[i], want[i], got)
		}
	}
}

func TestRewriteNPMInitUsesMappedCreatePackage(t *testing.T) {
	got := rewriteCommandForSelectedVersion([]string{"npm", "init", "vite@latest", "--", "--hello"}, RunReport{
		Analysis: CommandAnalysis{
			Manager: "npm",
			Action:  "init",
			OneShot: true,
			PackageSpecs: []PackageSpec{{
				Raw:  "vite@latest",
				Name: "create-vite",
			}},
		},
		Version: VersionInfo{Found: true, Selected: RegistryVersion{Version: "5.0.0"}},
	})

	want := []string{"npm", "exec", "create-vite@5.0.0", "--", "--hello"}
	if len(got) != len(want) {
		t.Fatalf("command = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command[%d] = %q, want %q in %#v", i, got[i], want[i], got)
		}
	}
}

func TestRewriteOneShotEqualsPackageFlagPinsSelectedVersion(t *testing.T) {
	got := rewriteCommandForSelectedVersion([]string{"npx", "--package=create-vite@latest", "vite"}, RunReport{
		Analysis: CommandAnalysis{
			Manager: "npx",
			OneShot: true,
			PackageSpecs: []PackageSpec{{
				Raw:  "create-vite@latest",
				Name: "create-vite",
			}},
		},
		Version: VersionInfo{Found: true, Selected: RegistryVersion{Version: "5.0.0"}},
	})

	if got[1] != "--package=create-vite@5.0.0" {
		t.Fatalf("command = %#v, want pinned --package flag", got)
	}
}

func TestRewriteUVXEqualsFromFlagPinsSelectedVersion(t *testing.T) {
	got := rewriteCommandForSelectedVersion([]string{"uvx", "--from=ruff", "ruff-lsp"}, RunReport{
		Analysis: CommandAnalysis{
			Manager: "uvx",
			OneShot: true,
			PackageSpecs: []PackageSpec{{
				Raw:  "ruff",
				Name: "ruff",
			}},
		},
		Version: VersionInfo{Found: true, Selected: RegistryVersion{Version: "1.2.3"}},
	})

	if got[1] != "--from=ruff==1.2.3" {
		t.Fatalf("command = %#v, want pinned --from flag", got)
	}
}

func TestRewritePipxEqualsSpecFlagPinsSelectedVersion(t *testing.T) {
	got := rewriteCommandForSelectedVersion([]string{"pipx", "run", "--spec=rich", "rich-cli"}, RunReport{
		Analysis: CommandAnalysis{
			Manager: "pipx",
			Action:  "run",
			OneShot: true,
			PackageSpecs: []PackageSpec{{
				Raw:  "rich",
				Name: "rich",
			}},
		},
		Version: VersionInfo{Found: true, Selected: RegistryVersion{Version: "13.7.0"}},
	})

	if got[2] != "--spec=rich==13.7.0" {
		t.Fatalf("command = %#v, want pinned --spec flag", got)
	}
}

func TestGuardRunsPinnedOneShotEqualsPackageFlag(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	outFile := filepath.Join(root, "args.txt")
	writeFakeTool(t, bin, "npx", "#!/bin/sh\nprintf '%s\\n' \"$@\" > '"+outFile+"'\n")
	t.Setenv("PATH", bin)
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.PutAdvisoryCache(AdvisoryCacheEntry{
		Ecosystem:  "npm",
		Name:       "create-vite",
		Version:    "5.0.0",
		CheckedAt:  time.Now().Add(time.Hour),
		Advisories: nil,
	}); err != nil {
		t.Fatal(err)
	}
	withFakeDefaultHTTP(t, `{"dist-tags":{"latest":"5.0.0"},"time":{"created":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z","5.0.0":"2026-01-01T00:00:00Z"}}`)
	withFailingOSV(t)

	err := runGuard([]string{"npx", "--package=create-vite@latest", "vite"}, strings.NewReader("yes\n"), io.Discard, io.Discard, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "--package=create-vite@5.0.0") {
		t.Fatalf("executed args = %q, want pinned package flag", string(body))
	}
}

func TestGuardDownloaderStreamsStagedBytesWithoutRefetch(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	marker := filepath.Join(root, "curl-called")
	writeFakeTool(t, bin, "curl", "#!/bin/sh\nprintf called > "+shellQuote(marker)+"\n")
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	previousClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("safe staged bytes")),
			Header:     make(http.Header),
		}, nil
	})}
	previousStdoutIsTerminal := stdoutIsTerminalFunc
	stdoutIsTerminalFunc = func() bool { return true }
	t.Cleanup(func() {
		http.DefaultClient = previousClient
		stdoutIsTerminalFunc = previousStdoutIsTerminal
	})
	store := NewStore(pathsFromRoot(filepath.Join(root, ".lsec")))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	err := runGuard([]string{"curl", "https://example.invalid/install.sh"}, strings.NewReader("yes\n"), &stdout, io.Discard, pathsFromRoot(filepath.Join(root, ".lsec")), store)
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "safe staged bytes" {
		t.Fatalf("stdout = %q, want staged bytes only", stdout.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("curl was executed after preflight instead of using staged bytes")
	}
}

func withFakeDefaultHTTP(t *testing.T, body string) {
	t.Helper()
	previousClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() {
		http.DefaultClient = previousClient
	})
}

func withFakePyPIMetadata(t *testing.T, bodies map[string]string) {
	t.Helper()
	previousClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		name := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/pypi/"), "/json")
		body, ok := bodies[name]
		if !ok {
			body = `{"info":{"version":""},"releases":{}}`
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() {
		http.DefaultClient = previousClient
	})
}

func withFakeNPMMetadata(t *testing.T, bodies map[string]string) {
	t.Helper()
	previousClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		name := strings.TrimPrefix(req.URL.Path, "/")
		body, ok := bodies[name]
		if !ok {
			body = `{"dist-tags":{"latest":""},"time":{}}`
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() {
		http.DefaultClient = previousClient
	})
}

func writeTestWheel(t *testing.T, path, distInfo, metadata string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create(distInfo + "/METADATA")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(metadata)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func TestIsApprovedRequiresMatchingHash(t *testing.T) {
	goodHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	approvals := []Approval{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		Hash:      goodHash,
	}}

	if !IsApproved(approvals, "npm", "left-pad", "1.3.0", goodHash) {
		t.Fatal("expected matching hash approval")
	}
	if IsApproved(approvals, "npm", "left-pad", "1.3.0", "sha256-other") {
		t.Fatal("approval with different hash must not match")
	}
	if IsApproved([]Approval{{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}}, "npm", "left-pad", "1.3.0", goodHash) {
		t.Fatal("hashless persistent approval must not match artifact bytes")
	}
	if IsApproved([]Approval{{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Hash: "not-a-sha"}}, "npm", "left-pad", "1.3.0", "not-a-sha") {
		t.Fatal("malformed hashes must not match approvals")
	}
}

func TestRunApprovalsAddRequiresHash(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	err := runApprovals([]string{"add", "npm", "left-pad", "1.3.0"}, io.Discard, store)

	if err == nil {
		t.Fatal("expected approvals add to require a hash")
	}
}

func TestRunApprovalsAddRejectsEmptyHash(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	err := runApprovals([]string{"add", "npm", "left-pad", "1.3.0", ""}, io.Discard, store)

	if err == nil {
		t.Fatal("expected approvals add to reject an empty hash")
	}
}

func TestRunApprovalsAddRejectsMalformedHash(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	err := runApprovals([]string{"add", "npm", "left-pad", "1.3.0", "sha256-good"}, io.Discard, store)

	if err == nil {
		t.Fatal("expected approvals add to reject malformed sha256")
	}
}

func TestRunApprovalsAddStoresHash(t *testing.T) {
	goodHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	err := runApprovals([]string{"add", "npm", "left-pad", "1.3.0", goodHash, "reviewed"}, io.Discard, store)
	if err != nil {
		t.Fatal(err)
	}
	approvals, err := store.LoadApprovals()
	if err != nil {
		t.Fatal(err)
	}
	if len(approvals) != 1 || approvals[0].Hash != goodHash {
		t.Fatalf("approvals = %#v, want stored hash", approvals)
	}
}

func TestRunApprovalsAddIsIdempotentForExactHash(t *testing.T) {
	goodHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	for _, reason := range []string{"first-review", "second-review"} {
		if err := runApprovals([]string{"add", "npm", "left-pad", "1.3.0", goodHash, reason}, io.Discard, store); err != nil {
			t.Fatal(err)
		}
	}

	approvals, err := store.LoadApprovals()
	if err != nil {
		t.Fatal(err)
	}
	if len(approvals) != 1 {
		t.Fatalf("approvals = %#v, want one exact approval", approvals)
	}
	if approvals[0].Reason != "second-review" {
		t.Fatalf("approval reason = %q, want updated reason", approvals[0].Reason)
	}
}

func TestRunApprovalsRevokeCanTargetExactHash(t *testing.T) {
	firstHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	secondHash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{firstHash, secondHash} {
		if err := runApprovals([]string{"add", "npm", "left-pad", "1.3.0", hash, "reviewed"}, io.Discard, store); err != nil {
			t.Fatal(err)
		}
	}

	if err := runApprovals([]string{"revoke", "npm", "left-pad", "1.3.0", firstHash}, io.Discard, store); err != nil {
		t.Fatal(err)
	}

	approvals, err := store.LoadApprovals()
	if err != nil {
		t.Fatal(err)
	}
	if IsApproved(approvals, "npm", "left-pad", "1.3.0", firstHash) {
		t.Fatal("first hash approval should be revoked")
	}
	if !IsApproved(approvals, "npm", "left-pad", "1.3.0", secondHash) {
		t.Fatal("second hash approval should remain")
	}
}

func TestRunApprovalsSuggestPrintsExactArtifactApprovals(t *testing.T) {
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
	if err := store.AppendEvent("preflight", RunReport{
		RunID: "run-approve-1",
		Artifacts: []Artifact{{
			Ecosystem: "PyPI",
			Name:      "example",
			Version:   "1.0.0",
			SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Kind:      "wheel",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"approvals", "suggest", "run-approve-1"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := "lsec approvals add PyPI example 1.0.0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef reviewed-run-approve-1"
	if !strings.Contains(stdout.String(), want) {
		t.Fatalf("suggest output = %q, want %q", stdout.String(), want)
	}
}

func TestRunApprovalsSuggestRejectsBlockedRuns(t *testing.T) {
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
	if err := store.AppendEvent("preflight", RunReport{
		RunID:    "run-blocked-approve",
		Decision: Decision{Verdict: VerdictBlock, Lane: LaneBlock, Reasons: []string{"known malware"}},
		Artifacts: []Artifact{{
			Ecosystem: "npm",
			Name:      "bad",
			Version:   "1.0.0",
			SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Kind:      "tar",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	err = Run([]string{"approvals", "suggest", "run-blocked-approve"}, strings.NewReader(""), &stdout, io.Discard)

	if err == nil {
		t.Fatal("expected blocked run to reject approval suggestions")
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want no approval commands for blocked run", stdout.String())
	}
}

func TestWriteReportPrintsArtifactHashes(t *testing.T) {
	var out strings.Builder
	writeReport(&out, RunReport{
		RunID: "run",
		Analysis: CommandAnalysis{
			Raw: []string{"pip", "install", "demo"},
		},
		Decision: Decision{Verdict: VerdictPrompt, Reasons: []string{"review"}},
		Artifacts: []Artifact{{
			Kind:   "wheel",
			Path:   "/tmp/demo.whl",
			SHA256: "sha256-good",
		}},
	})

	if !strings.Contains(out.String(), "artifact[wheel]: sha256-good /tmp/demo.whl") {
		t.Fatalf("report output = %q, want artifact hash line", out.String())
	}
}

func TestCheckFirstSeenPackagesPromptsUnknownPackage(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	findings := CheckFirstSeenPackages(store, "npm", []PackageSpec{{Name: "left-pad", Version: "1.3.0"}}, nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want first-seen prompt", findings)
	}
	if findings[0].Code != "first_seen_package" || findings[0].Severity != "prompt" {
		t.Fatalf("finding = %#v, want first_seen_package prompt", findings[0])
	}
}

func TestCheckFirstSeenPackagesIgnoresPreviouslyRecordedPackage(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := RunReport{
		RunID: "run-seen",
		Artifacts: []Artifact{{
			Ecosystem: "npm",
			Name:      "left-pad",
			Version:   "1.3.0",
			SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}},
		Decision:  Decision{Verdict: VerdictAllow, Lane: LaneTrusted},
		CreatedAt: time.Now().UTC(),
	}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	findings := CheckFirstSeenPackages(store, "npm", []PackageSpec{{Name: "left-pad", Version: "1.3.0"}}, nil)

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want known package ignored", findings)
	}
}

func TestCheckFirstSeenMaintainersPromptsNewMaintainerForKnownPackage(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := RunReport{
		RunID: "run-maintainer-seen",
		Analysis: CommandAnalysis{PackageSpecs: []PackageSpec{{
			Name: "left-pad",
		}}},
		Version:   VersionInfo{Maintainers: []string{"alice"}},
		Decision:  Decision{Verdict: VerdictAllow, Lane: LaneTrusted},
		CreatedAt: time.Now().UTC(),
	}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	findings := CheckFirstSeenMaintainers(store, "npm", "left-pad", []string{"alice", "bob"})

	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want new maintainer prompt", findings)
	}
	if findings[0].Code != "first_seen_maintainer" || findings[0].Severity != "prompt" {
		t.Fatalf("finding = %#v, want first_seen_maintainer prompt", findings[0])
	}
}

func TestRunHistoryListsRecentLocalEvents(t *testing.T) {
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
	if err := store.AppendEvent("preflight", RunReport{
		RunID: "run-history-1",
		Analysis: CommandAnalysis{
			Raw: []string{"npm", "install", "left-pad"},
		},
		Decision:  Decision{Verdict: VerdictPrompt, Lane: LaneRisky},
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"history"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{"run-history-1", "preflight", "prompt", "risky", "npm install left-pad"} {
		if !strings.Contains(out, want) {
			t.Fatalf("history output = %q, want %q", out, want)
		}
	}
}

func TestRunHistoryLimitShowsNewestEventsFirst(t *testing.T) {
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
	for _, runID := range []string{"old-run", "new-run"} {
		if err := store.AppendEvent("preflight", RunReport{
			RunID:    runID,
			Analysis: CommandAnalysis{Raw: []string{"npm", "install", runID}},
			Decision: Decision{Verdict: VerdictAllow, Lane: LaneTrusted},
		}); err != nil {
			t.Fatal(err)
		}
	}

	var stdout strings.Builder
	if err := Run([]string{"history", "1"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	if !strings.Contains(out, "new-run") || strings.Contains(out, "old-run") {
		t.Fatalf("history output = %q, want only newest run", out)
	}
}

func TestRunPackagesListsArtifactsWithApprovalStatus(t *testing.T) {
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
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := store.AppendEvent("preflight", RunReport{
		RunID:    "run-package-1",
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky},
		Artifacts: []Artifact{{
			Ecosystem: "PyPI",
			Name:      "example",
			Version:   "1.0.0",
			SHA256:    hash,
			Kind:      "wheel",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddApproval(Approval{Ecosystem: "PyPI", Name: "example", Version: "1.0.0", Hash: hash, Reason: "reviewed"}); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"packages"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{"PyPI", "example", "1.0.0", hash, "prompt", "approved"} {
		if !strings.Contains(out, want) {
			t.Fatalf("packages output = %q, want %q", out, want)
		}
	}
}

func TestRunPackagesLimitShowsNewestArtifactsFirst(t *testing.T) {
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
	for _, item := range []struct {
		runID string
		name  string
		hash  string
	}{
		{runID: "old-package-run", name: "oldpkg", hash: hashA},
		{runID: "new-package-run", name: "newpkg", hash: hashB},
	} {
		if err := store.AppendEvent("preflight", RunReport{
			RunID:    item.runID,
			Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky},
			Artifacts: []Artifact{{
				Ecosystem: "npm",
				Name:      item.name,
				Version:   "1.0.0",
				SHA256:    item.hash,
				Kind:      "tar",
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}

	var stdout strings.Builder
	if err := Run([]string{"packages", "1"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	if !strings.Contains(out, "newpkg") || strings.Contains(out, "oldpkg") {
		t.Fatalf("packages output = %q, want only newest package", out)
	}
}

func TestRunPackagesDeduplicatesSameArtifactAcrossEventKinds(t *testing.T) {
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
	report := RunReport{
		RunID:    "run-package-same",
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky},
		Artifacts: []Artifact{{
			Ecosystem: "npm",
			Name:      "samepkg",
			Version:   "1.0.0",
			SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Kind:      "tar",
		}},
	}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("evidence", BuildEvidenceBundle(report)); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"packages"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(stdout.String(), "samepkg"); count != 1 {
		t.Fatalf("packages output = %q, samepkg count = %d, want 1", stdout.String(), count)
	}
}

func TestRunStatusSummarizesLocalState(t *testing.T) {
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
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := store.AppendEvent("preflight", RunReport{
		RunID:    "run-status-1",
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky},
		Artifacts: []Artifact{{
			Ecosystem: "PyPI",
			Name:      "example",
			Version:   "1.0.0",
			SHA256:    hash,
			Kind:      "wheel",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("preflight", RunReport{
		RunID:    "run-status-2",
		Decision: Decision{Verdict: VerdictBlock, Lane: LaneBlock},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddApproval(Approval{Ecosystem: "PyPI", Name: "example", Version: "1.0.0", Hash: hash, Reason: "reviewed"}); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"status"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{
		"runs: 2",
		"packages: 1",
		"approvals: 1",
		"verdict[prompt]: 1",
		"verdict[block]: 1",
		"lane[risky]: 1",
		"lane[block]: 1",
		"approved_packages: 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output = %q, want %q", out, want)
		}
	}
}

func TestRunStatusCountsUniqueRunsAcrossEventKinds(t *testing.T) {
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
	report := RunReport{
		RunID:    "run-status-same",
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky},
	}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("evidence", BuildEvidenceBundle(report)); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"status"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	if !strings.Contains(out, "runs: 1") {
		t.Fatalf("status output = %q, want one unique run", out)
	}
	if !strings.Contains(out, "verdict[prompt]: 1") {
		t.Fatalf("status output = %q, want one prompt verdict", out)
	}
}

func TestRunShowPrintsStoredRunReportJSON(t *testing.T) {
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
	if err := store.AppendEvent("preflight", RunReport{
		RunID: "run-show-1",
		Analysis: CommandAnalysis{
			Raw: []string{"pip", "install", "example"},
		},
		Decision: Decision{Verdict: VerdictBlock, Lane: LaneBlock, Reasons: []string{"blocked"}},
	}); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	if err := Run([]string{"show", "run-show-1"}, strings.NewReader(""), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	var report RunReport
	if err := json.Unmarshal([]byte(stdout.String()), &report); err != nil {
		t.Fatalf("show output is not RunReport JSON: %q err=%v", stdout.String(), err)
	}
	if report.RunID != "run-show-1" || report.Decision.Verdict != VerdictBlock {
		t.Fatalf("report = %#v, want stored run-show-1 block report", report)
	}
}

func TestFindRealExecutableSkipsSymlinkBackToShimDir(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, "shim")
	firstDir := filepath.Join(root, "first")
	realDir := filepath.Join(root, "real")
	for _, dir := range []string{shimDir, firstDir, realDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	shim := filepath.Join(shimDir, "npm")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shim, filepath.Join(firstDir, "npm")); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(realDir, "npm")
	if err := os.WriteFile(real, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LSEC_SHIM_DIR", shimDir)
	t.Setenv("PATH", strings.Join([]string{shimDir, firstDir, realDir}, string(os.PathListSeparator)))

	got, err := findRealExecutable("npm")
	if err != nil {
		t.Fatal(err)
	}
	if got != real {
		t.Fatalf("real executable = %q, want %q", got, real)
	}
}
