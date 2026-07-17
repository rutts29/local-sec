package lsec

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageNPMBlocksVCSBeforePack(t *testing.T) {
	analysis := Classify([]string{"npm", "install", "git+https://github.com/example/pkg.git"})
	_, findings := StageArtifacts(context.Background(), t.TempDir(), analysis, VersionInfo{})

	if !hasFinding(findings, "unsafe_npm_staging_spec") {
		t.Fatalf("expected unsafe_npm_staging_spec finding, got %#v", findings)
	}
	if firstFindingSeverity(findings, "unsafe_npm_staging_spec") != "block" {
		t.Fatalf("expected unsafe_npm_staging_spec to block, got %#v", findings)
	}
}

func TestStagePipWheelOnlyFailureBlocksSourceBuild(t *testing.T) {
	analysis := Classify([]string{"pip", "install", "example"})
	python := filepath.Join(t.TempDir(), "python")
	if err := os.WriteFile(python, []byte("#!/bin/sh\necho no wheel >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	_, findings := stagePipWithPython(context.Background(), t.TempDir(), analysis, VersionInfo{}, python)

	if firstFindingSeverity(findings, "python_source_build_or_download_failed") != "block" {
		t.Fatalf("expected blocking python_source_build_or_download_failed finding, got %#v", findings)
	}
}

func TestStagePipUsesOriginalPythonModuleInterpreter(t *testing.T) {
	root := t.TempDir()
	fixtures := t.TempDir()
	wheel := filepath.Join(fixtures, "example-1.0.0-py3-none-any.whl")
	writeTestWheel(t, wheel, "example-1.0.0.dist-info", "Name: example\nVersion: 1.0.0\n")
	bin := t.TempDir()
	wrongMarker := filepath.Join(root, "python3-called")
	writeFakeTool(t, bin, "python3", "#!/bin/sh\nprintf wrong > "+shellQuote(wrongMarker)+"\nexit 2\n")
	writeFakeTool(t, bin, "python3.14", `#!/bin/sh
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
cp `+shellQuote(wheel)+` "$dest/"
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	analysis := Classify([]string{"python3.14", "-m", "pip", "install", "example"})

	artifacts, findings := StageArtifacts(context.Background(), filepath.Join(root, "stage"), analysis, VersionInfo{})

	if hasFinding(findings, "python_source_build_or_download_failed") {
		t.Fatalf("findings = %#v, staged with wrong Python interpreter", findings)
	}
	if len(artifacts) != 1 || artifacts[0].Name != "example" {
		t.Fatalf("artifacts = %#v findings = %#v, want staged example wheel", artifacts, findings)
	}
	if _, err := os.Stat(wrongMarker); !os.IsNotExist(err) {
		t.Fatal("stagePip used python3 instead of original python3.14 interpreter")
	}
}

func TestStagePipUsesIsolatedHomeInsideStaging(t *testing.T) {
	root := t.TempDir()
	fixtures := t.TempDir()
	wheel := filepath.Join(fixtures, "example-1.0.0-py3-none-any.whl")
	writeTestWheel(t, wheel, "example-1.0.0.dist-info", "Name: example\nVersion: 1.0.0\n")
	observedHome := filepath.Join(root, "observed-home")
	python := filepath.Join(root, "python")
	if err := os.WriteFile(python, []byte(`#!/bin/sh
dest=""
printf '%s' "$HOME" > `+shellQuote(observedHome)+`
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-d" ]; then
    dest="$2"
    shift 2
  else
    shift
  fi
done
mkdir -p "$dest"
cp `+shellQuote(wheel)+` "$dest/"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "stage")
	analysis := Classify([]string{"pip", "install", "example"})

	_, findings := stagePipWithPython(context.Background(), stage, analysis, VersionInfo{}, python)

	if hasBlockingFinding(findings) {
		t.Fatalf("findings = %#v, want staging success", findings)
	}
	body, err := os.ReadFile(observedHome)
	if err != nil {
		t.Fatal(err)
	}
	home := string(body)
	if !strings.HasPrefix(home, stage+string(os.PathSeparator)) {
		t.Fatalf("HOME = %q, want isolated home inside staging %q", home, stage)
	}
}

func TestStagePipRequirementsUsesRequireHashes(t *testing.T) {
	root := t.TempDir()
	fixtures := t.TempDir()
	wheel := filepath.Join(fixtures, "example-1.0.0-py3-none-any.whl")
	writeTestWheel(t, wheel, "example-1.0.0.dist-info", "Name: example\nVersion: 1.0.0\n")
	requirements := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(requirements, []byte("example==1.0.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(root, "python")
	if err := os.WriteFile(python, []byte(`#!/bin/sh
dest=""
has_hashes=0
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--require-hashes" ]; then
    has_hashes=1
  fi
  if [ "$1" = "-d" ]; then
    dest="$2"
    shift 2
  else
    shift
  fi
done
if [ "$has_hashes" != "1" ]; then
  echo missing --require-hashes >&2
  exit 3
fi
mkdir -p "$dest"
cp `+shellQuote(wheel)+` "$dest/"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	analysis := Classify([]string{"pip", "install", "-r", requirements})

	artifacts, findings := stagePipWithPython(context.Background(), filepath.Join(root, "stage"), analysis, VersionInfo{}, python)

	if hasBlockingFinding(findings) {
		t.Fatalf("findings = %#v, want staging success with --require-hashes", findings)
	}
	if len(artifacts) != 1 || artifacts[0].Name != "example" {
		t.Fatalf("artifacts = %#v, want example wheel", artifacts)
	}
}

func TestStagePipBlocksVCSBeforeDownload(t *testing.T) {
	analysis := Classify([]string{"pip", "install", "git+https://github.com/example/pkg.git"})
	_, findings := StageArtifacts(context.Background(), t.TempDir(), analysis, VersionInfo{})

	if firstFindingSeverity(findings, "unsafe_pip_staging_spec") != "block" {
		t.Fatalf("expected blocking unsafe_pip_staging_spec finding, got %#v", findings)
	}
}

func TestStagePipBlocksDirectURLBeforeDownload(t *testing.T) {
	analysis := Classify([]string{"pip", "install", "https://example.invalid/pkg.whl"})
	_, findings := StageArtifacts(context.Background(), t.TempDir(), analysis, VersionInfo{})

	if firstFindingSeverity(findings, "unsafe_pip_staging_spec") != "block" {
		t.Fatalf("expected blocking unsafe_pip_staging_spec finding, got %#v", findings)
	}
}

func TestStagePipBlocksLocalPathBeforeDownload(t *testing.T) {
	analysis := Classify([]string{"pip", "install", "."})
	_, findings := StageArtifacts(context.Background(), t.TempDir(), analysis, VersionInfo{})

	if firstFindingSeverity(findings, "unsafe_pip_staging_spec") != "block" {
		t.Fatalf("expected blocking unsafe_pip_staging_spec finding, got %#v", findings)
	}
}

func TestStageNPMBlocksLocalPathBeforePack(t *testing.T) {
	analysis := Classify([]string{"npm", "install", "../pkg"})
	_, findings := StageArtifacts(context.Background(), t.TempDir(), analysis, VersionInfo{})

	if firstFindingSeverity(findings, "unsafe_npm_staging_spec") != "block" {
		t.Fatalf("expected blocking unsafe_npm_staging_spec finding, got %#v", findings)
	}
}

func TestStageNPMRecursiveUsesIsolatedHomeCacheAndIgnoreScripts(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	records := filepath.Join(root, "records")
	writeFakeTool(t, bin, "npm", `#!/bin/sh
mkdir -p `+shellQuote(records)+`
printf '%s\n' "$@" > `+shellQuote(filepath.Join(records, "args"))+`
printf '%s\n' "$HOME" > `+shellQuote(filepath.Join(records, "home"))+`
printf '%s\n' "$XDG_CACHE_HOME" > `+shellQuote(filepath.Join(records, "cache"))+`
printf '%s\n' "$NPM_CONFIG_USERCONFIG" > `+shellQuote(filepath.Join(records, "userconfig"))+`
printf '%s\n' "$PWD" > `+shellQuote(filepath.Join(records, "pwd"))+`
cat > package-lock.json <<'JSON'
{"lockfileVersion":3,"packages":{"":{"name":"stage"},"node_modules/example":{"version":"1.0.0","resolved":"https://registry.npmjs.org/example/-/example-1.0.0.tgz","integrity":"sha512-test"}}}
JSON
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	t.Setenv("HOME", filepath.Join(root, "real-home"))
	t.Chdir(root)
	stage := filepath.Join(root, "stage")
	analysis := Classify([]string{"npm", "install", "example"})

	_, _ = StageArtifacts(context.Background(), stage, analysis, VersionInfo{})

	args := readTestFile(t, filepath.Join(records, "args"))
	if !strings.Contains(args, "install\n") || !strings.Contains(args, "--package-lock-only\n") || !strings.Contains(args, "--ignore-scripts\n") {
		t.Fatalf("npm args = %q, want install with --package-lock-only and --ignore-scripts", args)
	}
	if strings.Contains(args, "--pack-destination") {
		t.Fatalf("npm args = %q, should not run npm pack", args)
	}
	home := strings.TrimSpace(readTestFile(t, filepath.Join(records, "home")))
	cache := strings.TrimSpace(readTestFile(t, filepath.Join(records, "cache")))
	userconfig := strings.TrimSpace(readTestFile(t, filepath.Join(records, "userconfig")))
	pwd := strings.TrimSpace(readTestFile(t, filepath.Join(records, "pwd")))
	stagePrefix := testRealPath(t, stage) + string(os.PathSeparator)
	for label, got := range map[string]string{"HOME": home, "XDG_CACHE_HOME": cache, "NPM_CONFIG_USERCONFIG": userconfig, "PWD": pwd} {
		if !strings.HasPrefix(testRealPath(t, got), stagePrefix) {
			t.Fatalf("%s = %q, want inside staging %q", label, got, stage)
		}
		if strings.Contains(got, "real-home") {
			t.Fatalf("%s = %q, leaked real HOME", label, got)
		}
	}
}

func TestStageNPMRecursiveStagesLockedDependencies(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	top := makeTestNPMPackageTgz(t, "example", "1.0.0", `{"dep-pkg":"2.0.0"}`)
	dep := makeTestNPMPackageTgz(t, "dep-pkg", "2.0.0", `{}`)
	writeFakeTool(t, bin, "npm", fakeNPMInstallLockfile(map[string][]byte{
		"example": top,
		"dep-pkg": dep,
	}))
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	withFakeNPMTarballs(t, map[string][]byte{
		"/example/-/example-1.0.0.tgz": top,
		"/dep-pkg/-/dep-pkg-2.0.0.tgz": dep,
	})
	analysis := Classify([]string{"npm", "install", "example"})

	artifacts, findings := StageArtifacts(context.Background(), filepath.Join(root, "stage"), analysis, VersionInfo{})

	if hasBlockingFinding(findings) {
		t.Fatalf("findings = %#v, want recursive npm staging success", findings)
	}
	if len(artifacts) != 2 {
		t.Fatalf("artifacts = %#v, want top-level and dependency tarballs", artifacts)
	}
	if !hasArtifact(artifacts, "example", "1.0.0") || !hasArtifact(artifacts, "dep-pkg", "2.0.0") {
		t.Fatalf("artifacts = %#v, want example and dep-pkg", artifacts)
	}
}

func TestStageNPMRecursiveBlocksIntegrityMismatch(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	body := makeTestNPMPackageTgz(t, "example", "1.0.0", `{}`)
	writeFakeTool(t, bin, "npm", `#!/bin/sh
cat > package-lock.json <<'JSON'
{"lockfileVersion":3,"packages":{"":{"name":"stage"},"node_modules/example":{"version":"1.0.0","resolved":"https://registry.npmjs.org/example/-/example-1.0.0.tgz","integrity":"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}}
JSON
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	withFakeNPMTarballs(t, map[string][]byte{"/example/-/example-1.0.0.tgz": body})
	analysis := Classify([]string{"npm", "install", "example"})

	artifacts, findings := StageArtifacts(context.Background(), filepath.Join(root, "stage"), analysis, VersionInfo{})

	if len(artifacts) != 0 {
		t.Fatalf("artifacts = %#v, want none on integrity mismatch", artifacts)
	}
	if firstFindingSeverity(findings, "npm_tarball_integrity_mismatch") != "block" {
		t.Fatalf("findings = %#v, want blocking integrity mismatch", findings)
	}
}

func TestParseNPMStagingLockfileBlocksLinkedPackages(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "stage"},
			"node_modules/local-pkg": {
				"resolved": "../local-pkg",
				"link": true
			}
		}
	}`)
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	locked, findings := parseNPMStagingLockfile(lockfile)

	if len(locked) != 0 {
		t.Fatalf("locked = %#v, want none", locked)
	}
	if firstFindingSeverity(findings, "npm_lockfile_linked_package") != "block" {
		t.Fatalf("findings = %#v, want blocking linked package finding", findings)
	}
}

func TestParseNPMStagingLockfileBlocksUnverifiedPackagePath(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "stage"},
			"packages/local-pkg": {
				"version": "1.0.0",
				"resolved": "https://registry.npmjs.org/local-pkg/-/local-pkg-1.0.0.tgz",
				"integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
			}
		}
	}`)
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	locked, findings := parseNPMStagingLockfile(lockfile)

	if len(locked) != 0 {
		t.Fatalf("locked = %#v, want none", locked)
	}
	if firstFindingSeverity(findings, "npm_lockfile_unverified_package_path") != "block" {
		t.Fatalf("findings = %#v, want blocking unverified package path finding", findings)
	}
}

func TestParseNPMStagingLockfileBlocksMismatchedResolvedURL(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "stage"},
			"node_modules/safe-pkg": {
				"version": "1.2.3",
				"resolved": "https://registry.npmjs.org/other-pkg/-/other-pkg-1.2.3.tgz",
				"integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
			}
		}
	}`)
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	locked, findings := parseNPMStagingLockfile(lockfile)

	if len(locked) != 0 {
		t.Fatalf("locked = %#v, want none", locked)
	}
	if firstFindingSeverity(findings, "npm_lockfile_resolved_mismatch") != "block" {
		t.Fatalf("findings = %#v, want blocking resolved mismatch finding", findings)
	}
}

func TestParseNPMStagingLockfileUsesDeepestPackageName(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "stage"},
			"node_modules/a": {
				"version": "1.0.0",
				"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
				"integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
			},
			"node_modules/a/node_modules/@s/b": {
				"version": "1.0.0",
				"resolved": "https://registry.npmjs.org/@s/b/-/b-1.0.0.tgz",
				"integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
			}
		}
	}`)
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	locked, findings := parseNPMStagingLockfile(lockfile)

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if len(locked) != 2 {
		t.Fatalf("locked = %#v, want 2", locked)
	}
	if locked[0].Name != "@s/b" || locked[0].Version != "1.0.0" {
		t.Fatalf("first locked package = %#v, want @s/b@1.0.0", locked[0])
	}
	if locked[1].Name != "a" || locked[1].Version != "1.0.0" {
		t.Fatalf("second locked package = %#v, want a@1.0.0", locked[1])
	}
}

func TestStageNPMNestedDependenciesDoNotCollideByParentName(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	top := makeTestNPMPackageTgz(t, "a", "1.0.0", `{"b":"1.0.0"}`)
	dep := makeTestNPMPackageTgz(t, "b", "1.0.0", `{}`)
	writeFakeTool(t, bin, "npm", `#!/bin/sh
cat > package-lock.json <<'JSON'
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "stage"},
    "node_modules/a": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
      "integrity": "`+testSRI("sha512", top)+`"
    },
    "node_modules/a/node_modules/b": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz",
      "integrity": "`+testSRI("sha512", dep)+`"
    }
  }
}
JSON
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	withFakeNPMTarballs(t, map[string][]byte{
		"/a/-/a-1.0.0.tgz": top,
		"/b/-/b-1.0.0.tgz": dep,
	})
	analysis := Classify([]string{"npm", "install", "a"})

	artifacts, findings := StageArtifacts(context.Background(), filepath.Join(root, "stage"), analysis, VersionInfo{})

	if hasBlockingFinding(findings) || hasFinding(findings, "npm_tarball_download_failed") {
		t.Fatalf("findings = %#v, want nested npm staging success", findings)
	}
	if len(artifacts) != 2 {
		t.Fatalf("artifacts = %#v, want top-level and nested dependency tarballs", artifacts)
	}
	if !hasArtifact(artifacts, "a", "1.0.0") || !hasArtifact(artifacts, "b", "1.0.0") {
		t.Fatalf("artifacts = %#v, want a and b", artifacts)
	}
}

func TestDownloadNPMTarballAvoidsScopedBasenameCollision(t *testing.T) {
	staging := t.TempDir()
	unscoped := makeTestNPMPackageTgz(t, "pkg", "1.0.0", `{}`)
	scoped := makeTestNPMPackageTgz(t, "@scope/pkg", "1.0.0", `{}`)
	tarballs := map[string][]byte{
		"https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz":        unscoped,
		"https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz": scoped,
	}
	previous := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, ok := tarballs[req.URL.String()]
		if !ok {
			t.Fatalf("unexpected npm tarball URL: %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = previous })

	first := downloadNPMTarball(context.Background(), staging, npmLockedArtifact{
		Name:      "pkg",
		Version:   "1.0.0",
		Resolved:  "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
		Integrity: testSRI("sha512", unscoped),
	})
	second := downloadNPMTarball(context.Background(), staging, npmLockedArtifact{
		Name:      "@scope/pkg",
		Version:   "1.0.0",
		Resolved:  "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
		Integrity: testSRI("sha512", scoped),
	})

	if first != nil || second != nil {
		t.Fatalf("findings = %#v %#v, want both downloads to succeed", first, second)
	}
	entries, err := os.ReadDir(staging)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %#v, want two distinct tarballs", entries)
	}
}

func TestStageDownloadBlocksPlainHTTPBeforeNetwork(t *testing.T) {
	previous := http.DefaultClient
	called := false
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("echo ok\n")),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = previous })

	analysis := Classify([]string{"curl", "http://example.invalid/install.sh"})
	_, findings := StageArtifacts(context.Background(), t.TempDir(), analysis, VersionInfo{})

	if firstFindingSeverity(findings, "plaintext_http_download") != "block" {
		t.Fatalf("findings = %#v, want blocking plaintext_http_download", findings)
	}
	if called {
		t.Fatal("HTTP client was called before plaintext URL was blocked")
	}
}

func TestStageDownloadBlocksPlainHTTPRedirect(t *testing.T) {
	previous := http.DefaultClient
	finalURL, err := url.Parse("http://example.invalid/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("echo unsafe\n")),
			Header:     make(http.Header),
			Request:    &http.Request{URL: finalURL},
		}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = previous })

	analysis := Classify([]string{"curl", "https://example.invalid/install.sh"})
	_, findings := StageArtifacts(context.Background(), t.TempDir(), analysis, VersionInfo{})

	if firstFindingSeverity(findings, "plaintext_http_redirect") != "block" {
		t.Fatalf("findings = %#v, want blocking plaintext_http_redirect", findings)
	}
}

func TestStageDownloadRejectsOversizedResponse(t *testing.T) {
	previousClient := http.DefaultClient
	previousLimit := maxDownloadedFileBytes
	maxDownloadedFileBytes = 4
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("12345")),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() {
		http.DefaultClient = previousClient
		maxDownloadedFileBytes = previousLimit
	})

	analysis := Classify([]string{"curl", "https://example.invalid/install.sh"})
	_, findings := StageArtifacts(context.Background(), t.TempDir(), analysis, VersionInfo{})

	if firstFindingSeverity(findings, "download_too_large") != "block" {
		t.Fatalf("findings = %#v, want blocking download_too_large", findings)
	}
}

func TestStageUVInstallBlocksUntilStagingSupported(t *testing.T) {
	tests := [][]string{
		{"uv", "pip", "install", "requests"},
		{"uv", "add", "requests"},
	}

	for _, tt := range tests {
		analysis := Classify(tt)
		_, findings := StageArtifacts(context.Background(), t.TempDir(), analysis, VersionInfo{})

		if firstFindingSeverity(findings, "uv_staging_unsupported") != "block" {
			t.Fatalf("%v findings = %#v, want blocking uv_staging_unsupported", tt, findings)
		}
	}
}

func TestStagePipxInstallBlocksUntilStagingSupported(t *testing.T) {
	analysis := Classify([]string{"pipx", "install", "black"})
	_, findings := StageArtifacts(context.Background(), t.TempDir(), analysis, VersionInfo{})

	if firstFindingSeverity(findings, "pipx_staging_unsupported") != "block" {
		t.Fatalf("findings = %#v, want blocking pipx_staging_unsupported", findings)
	}
}

func TestSafeExtractFileBlocksPortablePathTraversal(t *testing.T) {
	tests := []string{
		"../escape",
		"/tmp/escape",
		`..\escape`,
		`dir\..\escape`,
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			err := safeExtractFile(t.TempDir(), name, func(w io.Writer) error {
				_, err := w.Write([]byte("x"))
				return err
			})
			if err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestSafeExtractFileRejectsOversizedFile(t *testing.T) {
	previous := maxExtractedFileBytes
	maxExtractedFileBytes = 4
	t.Cleanup(func() { maxExtractedFileBytes = previous })

	err := safeExtractFile(t.TempDir(), "package/big.js", func(w io.Writer) error {
		_, err := w.Write([]byte("12345"))
		return err
	})

	if err == nil {
		t.Fatal("expected oversized extracted file to be rejected")
	}
}

func TestExtractDependencyRefsFromNPMMetadata(t *testing.T) {
	root := t.TempDir()
	body := []byte(`{"dependencies":{"safe-pkg":"1.2.3","range-pkg":"^4.5.6"}}`)
	if err := os.WriteFile(filepath.Join(root, "package.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	deps, findings, err := ExtractDependencyRefs(root, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("deps = %#v, want 2", deps)
	}
	if !deps[0].Exact || deps[0].Name != "safe-pkg" || deps[0].Version != "1.2.3" {
		t.Fatalf("first dep = %#v, want exact safe-pkg 1.2.3", deps[0])
	}
	if firstFindingSeverity(findings, "dependency_version_unresolved") != "prompt" {
		t.Fatalf("expected unresolved dependency prompt, got %#v", findings)
	}
}

func TestExtractDependencyRefsFromWheelMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pkg.dist-info")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("Metadata-Version: 2.1\nRequires-Dist: requests (==2.31.0)\nRequires-Dist: httpx >=0.27\n")
	if err := os.WriteFile(filepath.Join(root, "METADATA"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	deps, findings, err := ExtractDependencyRefs(filepath.Dir(root), "PyPI")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("deps = %#v, want 2", deps)
	}
	if !deps[0].Exact || deps[0].Name != "requests" || deps[0].Version != "2.31.0" {
		t.Fatalf("first dep = %#v, want exact requests 2.31.0", deps[0])
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for wheel metadata ranges after recursive wheel staging", findings)
	}
}

func TestParsePinnedRequirementsFile(t *testing.T) {
	requirements := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(requirements, []byte("requests==2.31.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n# comment\nhttpx==0.27.0 --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseRequirementsFiles([]string{requirements})

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if len(specs) != 2 {
		t.Fatalf("specs = %#v, want 2", specs)
	}
	if specs[0].Name != "requests" || specs[0].Version != "2.31.0" {
		t.Fatalf("first spec = %#v, want requests==2.31.0", specs[0])
	}
}

func TestParsePinnedRequirementsSupportsHashContinuations(t *testing.T) {
	requirements := filepath.Join(t.TempDir(), "requirements.txt")
	body := "requests==2.31.0 \\\n" +
		"    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\\n" +
		"    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
	if err := os.WriteFile(requirements, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseRequirementsFiles([]string{requirements})

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if len(specs) != 1 || specs[0].Name != "requests" || specs[0].Version != "2.31.0" {
		t.Fatalf("specs = %#v, want requests==2.31.0", specs)
	}
}

func TestParseRequirementsBlocksPinnedEntryWithoutHash(t *testing.T) {
	requirements := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(requirements, []byte("requests==2.31.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseRequirementsFiles([]string{requirements})

	if len(specs) != 0 {
		t.Fatalf("specs = %#v, want none", specs)
	}
	if firstFindingSeverity(findings, "requirements_missing_hash") != "block" {
		t.Fatalf("findings = %#v, want blocking requirements_missing_hash", findings)
	}
}

func TestParseRequirementsBlocksMalformedSHA256Hash(t *testing.T) {
	requirements := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(requirements, []byte("requests==2.31.0 --hash=sha256:not-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseRequirementsFiles([]string{requirements})

	if len(specs) != 0 {
		t.Fatalf("specs = %#v, want none", specs)
	}
	if firstFindingSeverity(findings, "requirements_invalid_hash") != "block" {
		t.Fatalf("findings = %#v, want blocking requirements_invalid_hash", findings)
	}
}

func TestParseRequirementsBlocksDanglingContinuation(t *testing.T) {
	requirements := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(requirements, []byte("requests==2.31.0 \\\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseRequirementsFiles([]string{requirements})

	if len(specs) != 0 {
		t.Fatalf("specs = %#v, want none", specs)
	}
	if firstFindingSeverity(findings, "requirements_continuation_unclosed") != "block" {
		t.Fatalf("findings = %#v, want blocking requirements_continuation_unclosed", findings)
	}
}

func TestParseRequirementsBlocksUnsafeLines(t *testing.T) {
	requirements := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(requirements, []byte("git+https://github.com/example/pkg.git\nunversioned\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseRequirementsFiles([]string{requirements})

	if len(specs) != 0 {
		t.Fatalf("specs = %#v, want none", specs)
	}
	if firstFindingSeverity(findings, "requirements_unsafe_entry") != "block" {
		t.Fatalf("expected unsafe entry block, got %#v", findings)
	}
	if firstFindingSeverity(findings, "requirements_unpinned_entry") != "block" {
		t.Fatalf("expected unpinned entry block, got %#v", findings)
	}
}

func TestParseNPMLockfileExactPackages(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app"},
			"node_modules/left-pad": {
				"version": "1.3.0",
				"integrity": "sha512-test",
				"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
			},
			"node_modules/@scope/pkg": {
				"version": "2.0.0",
				"integrity": "sha512-test",
				"resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz"
			}
		}
	}`)
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseNPMLockfile(lockfile)

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if len(specs) != 2 {
		t.Fatalf("specs = %#v, want 2", specs)
	}
	if specs[0].Name != "@scope/pkg" || specs[0].Version != "2.0.0" {
		t.Fatalf("first spec = %#v, want @scope/pkg@2.0.0", specs[0])
	}
}

func TestParseNPMLockfileBlocksMissingIntegrity(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/left-pad": {"version": "1.3.0"}
		}
	}`)
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseNPMLockfile(lockfile)

	if len(specs) != 0 {
		t.Fatalf("specs = %#v, want none", specs)
	}
	if firstFindingSeverity(findings, "npm_lockfile_missing_integrity") != "block" {
		t.Fatalf("expected missing integrity block, got %#v", findings)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func testRealPath(t *testing.T, path string) string {
	t.Helper()
	realPath, err := filepath.EvalSymlinks(path)
	if err == nil {
		return realPath
	}
	if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	dir, base := filepath.Split(path)
	realDir, err := filepath.EvalSymlinks(filepath.Clean(dir))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(realDir, base)
}

func makeTestNPMPackageTgz(t *testing.T, name, version, dependencies string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	pkg := `{"name":"` + name + `","version":"` + version + `","dependencies":` + dependencies + `}`
	header := &tar.Header{Name: "package/package.json", Mode: 0o600, Size: int64(len(pkg))}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(pkg)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func fakeNPMInstallLockfile(tarballs map[string][]byte) string {
	return `#!/bin/sh
cat > package-lock.json <<'JSON'
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "stage"},
    "node_modules/example": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
      "integrity": "` + testSRI("sha512", tarballs["example"]) + `"
    },
    "node_modules/dep-pkg": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/dep-pkg/-/dep-pkg-2.0.0.tgz",
      "integrity": "` + testSRI("sha512", tarballs["dep-pkg"]) + `"
    }
  }
}
JSON
`
}

func testSRI(algorithm string, body []byte) string {
	switch algorithm {
	case "sha512":
		sum := sha512.Sum512(body)
		return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	case "sha1":
		sum := sha1.Sum(body)
		return "sha1-" + base64.StdEncoding.EncodeToString(sum[:])
	default:
		return ""
	}
}

func withFakeNPMTarballs(t *testing.T, tarballs map[string][]byte) {
	t.Helper()
	previous := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme != "https" || req.URL.Hostname() != "registry.npmjs.org" {
			t.Fatalf("unexpected npm tarball URL: %s", req.URL.String())
		}
		body, ok := tarballs[req.URL.EscapedPath()]
		if !ok {
			return &http.Response{
				StatusCode: 404,
				Status:     "404 Not Found",
				Body:       io.NopCloser(strings.NewReader("missing")),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = previous })
}

func withFakeNPMHTTP(t *testing.T, metadata map[string]string, tarballs map[string][]byte) {
	t.Helper()
	previous := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if body, ok := tarballs[req.URL.EscapedPath()]; ok {
			return &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}
		name := strings.TrimPrefix(req.URL.Path, "/")
		body, ok := metadata[name]
		if !ok {
			body = `{"dist-tags":{"latest":""},"time":{}}`
		}
		return &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = previous })
}

func hasArtifact(artifacts []Artifact, name, version string) bool {
	for _, artifact := range artifacts {
		if artifact.Name == name && artifact.Version == version {
			return true
		}
	}
	return false
}

func firstFindingSeverity(findings []Finding, code string) string {
	for _, finding := range findings {
		if finding.Code == code {
			return finding.Severity
		}
	}
	return ""
}
