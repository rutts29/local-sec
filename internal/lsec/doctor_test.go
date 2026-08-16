package lsec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorReportsOptionalCLIToolsWhenAvailable(t *testing.T) {
	paths := pathsFromRoot(t.TempDir())
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	tools := []string{"sqlite3", "socket", "snyk", "osv-scanner", "pip-audit", "syft", "grype", "cargo-vet", "bumblebee", "docker", "ollama"}
	for _, tool := range tools {
		writeFakeTool(t, bin, tool, "#!/bin/sh\nexit 0\n")
	}
	t.Setenv("PATH", strings.Join([]string{paths.Bin, bin}, string(os.PathListSeparator)))

	var out bytes.Buffer
	if err := Doctor(paths, &out); err != nil {
		t.Fatal(err)
	}

	output := out.String()
	for _, want := range []string{
		"current scan/advisory tools:",
		"ok: osv-scanner [active scan/advisory] role: npm lockfile advisory scan",
		"ok: pip-audit [active scan/advisory] role: pinned Python requirements advisory scan",
		"ok: grype [active scan/advisory] role: accepted CycloneDX SBOM advisory scan",
		"advisory amplifiers:",
		"ok: socket [preflight amplifier] role: optional package preflight enrichment",
		"ok: snyk [preflight amplifier] role: optional npm preflight enrichment",
		"detected-only / future integrations:",
		"ok: syft [detected-only] role: future SBOM inventory input",
		"ok: bumblebee [detected-only] role: future endpoint correlation input",
		"ok: cargo-vet [detected-only] role: future Rust audit input",
		"runtime/local evidence tools:",
		"ok: docker [fixture/local evidence] role: docker-fixture sandbox runner",
		"ok: ollama [fixture/local evidence] role: local review helper",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("doctor output = %q, want %q", output, want)
		}
	}
}

func TestDoctorMissingOptionalToolsReturnsNil(t *testing.T) {
	paths := pathsFromRoot(t.TempDir())
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", strings.Join([]string{paths.Bin, bin}, string(os.PathListSeparator)))

	var out bytes.Buffer
	if err := Doctor(paths, &out); err != nil {
		t.Fatal(err)
	}

	output := out.String()
	for _, want := range []string{
		"optional missing: osv-scanner [active scan/advisory] role: npm lockfile advisory scan",
		"optional missing: socket [preflight amplifier] role: optional package preflight enrichment",
		"optional missing: syft [detected-only] role: future SBOM inventory input",
		"optional missing: bumblebee [detected-only] role: future endpoint correlation input",
		"optional missing: docker [fixture/local evidence] role: docker-fixture sandbox runner",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("doctor output = %q, want %q", output, want)
		}
	}
}

func TestCheckMacOSEndpointAppsUsesApplicationRoot(t *testing.T) {
	appRoot := t.TempDir()
	for _, name := range []string{"BlockBlock.app", "LuLu.app"} {
		if err := os.Mkdir(filepath.Join(appRoot, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	var out bytes.Buffer
	checkMacOSEndpointApps(&out, appRoot)

	output := out.String()
	for _, want := range []string{
		"macOS endpoint apps:",
		"ok: BlockBlock.app [detected-only] role: endpoint context app",
		"ok: LuLu.app [detected-only] role: endpoint context app",
		"optional missing: KnockKnock.app [detected-only] role: endpoint context app",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("endpoint app output = %q, want %q", output, want)
		}
	}
}
