package lsec

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageURLIdentity(t *testing.T) {
	tests := []struct {
		name          string
		purl          string
		wantEcosystem string
		wantName      string
		wantVersion   string
		wantOK        bool
	}{
		{name: "scoped npm unescaped", purl: "pkg:npm/@scope/name@1.0.0", wantEcosystem: "npm", wantName: "@scope/name", wantVersion: "1.0.0", wantOK: true},
		{name: "scoped npm escaped with qualifiers and subpath", purl: "pkg:npm/%40scope/name@1.0.0?checksum=abc#dist/index.js", wantEcosystem: "npm", wantName: "@scope/name", wantVersion: "1.0.0", wantOK: true},
		{name: "pypi qualifiers and subpath", purl: "pkg:pypi/requests@2.32.5?download_url=https%3A%2F%2Fexample.invalid#src", wantEcosystem: "PyPI", wantName: "requests", wantVersion: "2.32.5", wantOK: true},
		{name: "homebrew type alias", purl: "pkg:homebrew/wget@1.25.0", wantEcosystem: "Homebrew", wantName: "wget", wantVersion: "1.25.0", wantOK: true},
		{name: "missing scheme", purl: "npm/left-pad@1.3.0"},
		{name: "missing slash", purl: "pkg:npm"},
		{name: "missing version", purl: "pkg:npm/left-pad"},
		{name: "bad escape", purl: "pkg:npm/left%zzpad@1.3.0"},
		{name: "unsupported type", purl: "pkg:cargo/serde@1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEcosystem, gotName, gotVersion, gotOK := scanIdentityFromPackageURL(tt.purl)
			if gotOK != tt.wantOK || gotEcosystem != tt.wantEcosystem || gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Fatalf("scanIdentityFromPackageURL(%q) = (%q, %q, %q, %v), want (%q, %q, %q, %v)", tt.purl, gotEcosystem, gotName, gotVersion, gotOK, tt.wantEcosystem, tt.wantName, tt.wantVersion, tt.wantOK)
			}
		})
	}
}

func TestPackageURLRejectsUnsafeDecodedIdentity(t *testing.T) {
	for _, purl := range []string{
		"pkg:npm/..@1.0.0",
		"pkg:npm/%40scope//@1.0.0",
		"pkg:npm/%40scope/name@../1.0.0",
		"pkg:npm/%40scope%2Fname%2Fextra@1.0.0",
		"pkg:pypi/requests%2Fextra@2.32.5",
		"pkg:pypi/requests@file%3A..%2Fpkg",
		"pkg:pypi/requests@1.0.0%0A",
		"pkg:brew/wget@..",
		"pkg:brew/archive.tgz@1.0.0",
		"pkg:pypi/git%2Bhttps%3A%2F%2Fexample.invalid%2Frepo@1.0.0",
	} {
		t.Run(purl, func(t *testing.T) {
			if ecosystem, name, version, ok := scanIdentityFromPackageURL(purl); ok {
				t.Fatalf("scanIdentityFromPackageURL(%q) = (%q, %q, %q, true), want rejected", purl, ecosystem, name, version)
			}
		})
	}
}

func TestCycloneDXRequiresCycloneDXBomFormat(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "sbom.json"), `{
		"bomFormat": "SPDX",
		"components": [{"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if hasRecordType(records, "observation") || hasRecordType(records, "diagnostic") {
		t.Fatalf("records = %#v, want non-CycloneDX SBOM ignored without inventory or diagnostics", records)
	}
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, ignored non-CycloneDX SBOM should not make scan partial", records)
	}
}

func TestCycloneDXRejectsComponentTypeFallback(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	writeFile(t, filepath.Join(project, "bom.json"), `{
		"bomFormat": "CycloneDX",
		"components": [{"type":"npm","name":"left-pad","version":"1.3.0"}]
	}`)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	records := parseNDJSONRecords(t, stdout.String())
	if hasRecordType(records, "observation") {
		t.Fatalf("records = %#v, want CycloneDX component without supported purl ignored", records)
	}
	if scanSummaryRecord(t, records)["status"] != "complete" {
		t.Fatalf("records = %#v, ignored fallback component should not make scan partial", records)
	}
}

func TestCycloneDXNetworkOffDoesNotInvokeOSVScanner(t *testing.T) {
	root := t.TempDir()
	lsecHome := filepath.Join(root, ".local-sec")
	project := filepath.Join(root, "project")
	marker := filepath.Join(root, "osv-scanner-called")
	writeFile(t, filepath.Join(project, "sbom.json"), `{
		"bomFormat": "CycloneDX",
		"components": [{"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]
	}`)
	writeFakeTool(t, root, "osv-scanner", "#!/bin/sh\nprintf called > "+shellQuote(marker)+"\n")
	t.Setenv("PATH", root)
	t.Setenv("LSEC_HOME", lsecHome)

	var stdout strings.Builder
	err := Run([]string{"scan", "--profile", "project", "--root", project, "--network", "off", "--format", "ndjson"}, strings.NewReader(""), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("osv-scanner marker stat err = %v, want not invoked", err)
	}
}
