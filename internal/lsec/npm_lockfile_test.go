package lsec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNPMLockfileBlocksNonRegistryResolvedURL(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app"},
			"node_modules/safe-pkg": {
				"version": "1.2.3",
				"integrity": "sha512-safe",
				"resolved": "https://registry.npmjs.org/safe-pkg/-/safe-pkg-1.2.3.tgz"
			},
			"node_modules/evil-pkg": {
				"version": "9.9.9",
				"integrity": "sha512-evil",
				"resolved": "https://packages.example.invalid/evil-pkg-9.9.9.tgz"
			},
			"node_modules/local-pkg": {
				"version": "0.0.1",
				"integrity": "sha512-local",
				"resolved": "../local-pkg-0.0.1.tgz"
			}
		}
	}`)
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseNPMLockfile(lockfile)

	if len(specs) != 1 || specs[0].Name != "safe-pkg" {
		t.Fatalf("specs = %#v, want only safe-pkg", specs)
	}
	if firstFindingSeverity(findings, "npm_lockfile_external_source") != "block" {
		t.Fatalf("findings = %#v, want blocking external source finding", findings)
	}
}

func TestParseNPMLockfileBlocksMismatchedResolvedURL(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app"},
			"node_modules/safe-pkg": {
				"version": "1.2.3",
				"integrity": "sha512-safe",
				"resolved": "https://registry.npmjs.org/other-pkg/-/other-pkg-1.2.3.tgz"
			}
		}
	}`)
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseNPMLockfile(lockfile)

	if len(specs) != 0 {
		t.Fatalf("specs = %#v, want none", specs)
	}
	if firstFindingSeverity(findings, "npm_lockfile_resolved_mismatch") != "block" {
		t.Fatalf("findings = %#v, want blocking resolved mismatch finding", findings)
	}
}

func TestPackageNameFromNodeModulesPathUsesDeepestPackage(t *testing.T) {
	tests := map[string]string{
		"node_modules/a":                             "a",
		"node_modules/@s/a":                          "@s/a",
		"node_modules/a/node_modules/b":              "b",
		"node_modules/a/node_modules/@s/b":           "@s/b",
		"node_modules/@s/a/node_modules/@t/b":        "@t/b",
		"packages/app/node_modules/a/node_modules/b": "b",
	}
	for path, want := range tests {
		got, ok := packageNameFromNodeModulesPath(path)
		if !ok || got != want {
			t.Fatalf("packageNameFromNodeModulesPath(%q) = %q, %v; want %q, true", path, got, ok, want)
		}
	}
}

func TestParseNPMLockfileUsesDeepestPackageName(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app"},
			"node_modules/a": {
				"version": "1.0.0",
				"integrity": "sha512-a",
				"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"
			},
			"node_modules/a/node_modules/@s/b": {
				"version": "2.0.0",
				"integrity": "sha512-b",
				"resolved": "https://registry.npmjs.org/@s/b/-/b-2.0.0.tgz"
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
	if specs[0].Name != "@s/b" || specs[0].Version != "2.0.0" {
		t.Fatalf("first spec = %#v, want @s/b@2.0.0", specs[0])
	}
	if specs[1].Name != "a" || specs[1].Version != "1.0.0" {
		t.Fatalf("second spec = %#v, want a@1.0.0", specs[1])
	}
}

func TestParseNPMLockfileBlocksLinkedPackages(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app"},
			"node_modules/local-pkg": {
				"resolved": "../local-pkg",
				"link": true
			}
		}
	}`)
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseNPMLockfile(lockfile)

	if len(specs) != 0 {
		t.Fatalf("specs = %#v, want none", specs)
	}
	if firstFindingSeverity(findings, "npm_lockfile_linked_package") != "block" {
		t.Fatalf("findings = %#v, want blocking linked package finding", findings)
	}
}

func TestParseNPMLockfileBlocksMissingResolvedURL(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
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
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseNPMLockfile(lockfile)

	if len(specs) != 0 {
		t.Fatalf("specs = %#v, want none", specs)
	}
	if firstFindingSeverity(findings, "npm_lockfile_missing_resolved") != "block" {
		t.Fatalf("findings = %#v, want blocking missing resolved finding", findings)
	}
}

func TestParseNPMLockfileBlocksUnverifiedWorkspacePackagePath(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app"},
			"packages/local-pkg": {
				"version": "1.0.0",
				"integrity": "sha512-test",
				"resolved": "https://registry.npmjs.org/local-pkg/-/local-pkg-1.0.0.tgz"
			}
		}
	}`)
	if err := os.WriteFile(lockfile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	specs, findings := ParseNPMLockfile(lockfile)

	if len(specs) != 0 {
		t.Fatalf("specs = %#v, want none", specs)
	}
	if firstFindingSeverity(findings, "npm_lockfile_unverified_package_path") != "block" {
		t.Fatalf("findings = %#v, want blocking unverified package path finding", findings)
	}
}
