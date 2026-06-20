package lsec

import (
	"context"
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
				"integrity": "sha512-test"
			},
			"node_modules/@scope/pkg": {
				"version": "2.0.0",
				"integrity": "sha512-test"
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

func firstFindingSeverity(findings []Finding, code string) string {
	for _, finding := range findings {
		if finding.Code == code {
			return finding.Severity
		}
	}
	return ""
}
