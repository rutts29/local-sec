package lsec

import (
	"context"
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

func TestIsAllowedNPMRegistryResolvedURLRequiresCanonicalAuthority(t *testing.T) {
	tests := map[string]bool{
		"https://registry.npmjs.org/example/-/example-1.0.0.tgz":          true,
		"http://registry.npmjs.org/example/-/example-1.0.0.tgz":           false,
		"https://registry.npmjs.org:443/example/-/example-1.0.0.tgz":      false,
		"https://registry.npmjs.org:8080/example/-/example-1.0.0.tgz":     false,
		"https://user@registry.npmjs.org/example/-/example-1.0.0.tgz":     false,
		"https://registry.npmjs.org/example/-/example-1.0.0.tgz?x=1":      false,
		"https://registry.npmjs.org/example/-/example-1.0.0.tgz#fragment": false,
		"https://registry.npmjs.org.evil/example/-/example-1.0.0.tgz":     false,
	}
	for raw, want := range tests {
		if got := isAllowedNPMRegistryResolvedURL(raw); got != want {
			t.Fatalf("isAllowedNPMRegistryResolvedURL(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestParseNPMLockfilePackagesReturnsDeterministicV3Metadata(t *testing.T) {
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/z": {
				"version": "3.0.0",
				"resolved": "https://registry.npmjs.org/z/-/z-3.0.0.tgz",
				"integrity": "sha512-z"
			},
			"node_modules/a/node_modules/@scope/b": {
				"name": "@scope/b",
				"version": "2.0.0",
				"resolved": "https://registry.npmjs.org/@scope/b/-/b-2.0.0.tgz",
				"integrity": "sha512-b"
			},
			"node_modules/local": {
				"name": "local",
				"resolved": "../local",
				"link": true
			}
		}
	}`)

	packages, err := parseNPMLockfilePackages(body)

	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 3 {
		t.Fatalf("packages = %#v, want 3", packages)
	}
	if packages[0] != (npmLockfilePackage{Path: "node_modules/a/node_modules/@scope/b", Name: "@scope/b", Version: "2.0.0", Resolved: "https://registry.npmjs.org/@scope/b/-/b-2.0.0.tgz", Integrity: "sha512-b"}) {
		t.Fatalf("packages[0] = %#v, want nested scoped package", packages[0])
	}
	if packages[1] != (npmLockfilePackage{Path: "node_modules/local", Name: "local", Resolved: "../local", Link: true}) {
		t.Fatalf("packages[1] = %#v, want linked package metadata", packages[1])
	}
	if packages[2].Path != "node_modules/z" || packages[2].Name != "z" || packages[2].Version != "3.0.0" {
		t.Fatalf("packages[2] = %#v, want derived z metadata", packages[2])
	}
}

func TestParseNPMLockfilePackagesWalksLegacyScopedDependencies(t *testing.T) {
	body := []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"@scope/a": {
				"version": "1.0.0",
				"resolved": "https://registry.npmjs.org/@scope/a/-/a-1.0.0.tgz",
				"integrity": "sha512-a",
				"dependencies": {
					"b": {
						"version": "2.0.0",
						"resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz",
						"integrity": "sha512-b"
					}
				}
			}
		}
	}`)

	packages, err := parseNPMLockfilePackages(body)

	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatalf("packages = %#v, want 2", packages)
	}
	if packages[0].Path != "node_modules/@scope/a" || packages[0].Name != "@scope/a" {
		t.Fatalf("packages[0] = %#v, want scoped legacy package", packages[0])
	}
	if packages[1].Path != "node_modules/@scope/a/node_modules/b" || packages[1].Name != "b" {
		t.Fatalf("packages[1] = %#v, want nested legacy dependency", packages[1])
	}
}

func TestParseNPMLockfilePackagesRejectsMalformedJSON(t *testing.T) {
	if packages, err := parseNPMLockfilePackages([]byte(`{"packages":`)); err == nil {
		t.Fatalf("packages = %#v, want parse error", packages)
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

func TestPackageNameFromNodeModulesPathRejectsNonPackagePaths(t *testing.T) {
	for _, path := range []string{
		"node_modules/a/package.json",
		"node_modules/@scope",
		"node_modules/",
		"node_modules/a/node_modules",
	} {
		if name, ok := packageNameFromNodeModulesPath(path); ok {
			t.Fatalf("packageNameFromNodeModulesPath(%q) = %q, true; want empty, false", path, name)
		}
	}
}

func TestParseNPMLockfileWalksV1NestedDependencies(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"a": {
				"version": "1.0.0",
				"integrity": "sha512-a",
				"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
				"dependencies": {
					"b": {
						"version": "2.0.0",
						"integrity": "sha512-b",
						"resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz"
					}
				}
			},
			"c": {
				"version": "3.0.0",
				"integrity": "sha512-c",
				"resolved": "https://registry.npmjs.org/c/-/c-3.0.0.tgz"
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
	if len(specs) != 3 {
		t.Fatalf("specs = %#v, want a, b, and c", specs)
	}
	for i, want := range []string{"a", "b", "c"} {
		if specs[i].Name != want {
			t.Fatalf("specs[%d] = %#v, want %s", i, specs[i], want)
		}
	}
}

func TestParseNPMStagingLockfileWalksV1NestedDependencies(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	integrity := "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	body := []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"a": {
				"version": "1.0.0",
				"integrity": "` + integrity + `",
				"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
				"dependencies": {
					"b": {
						"version": "2.0.0",
						"integrity": "` + integrity + `",
						"resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz"
					}
				}
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
	if len(locked) != 2 || locked[0].Name != "a" || locked[1].Name != "b" {
		t.Fatalf("locked = %#v, want a and b", locked)
	}
}

func TestParseNPMStagingLockfileBlocksUnsupportedIntegrity(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/example": {
				"version": "1.0.0",
				"integrity": "sha256-unsupported",
				"resolved": "https://registry.npmjs.org/example/-/example-1.0.0.tgz"
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
	if firstFindingSeverity(findings, "npm_lockfile_unsupported_integrity") != "block" {
		t.Fatalf("findings = %#v, want blocking unsupported integrity finding", findings)
	}
}

func TestStageNPMDeduplicatesIdenticalNestedLockEntries(t *testing.T) {
	for _, lockfileVersion := range []string{"2", "3"} {
		t.Run("v"+lockfileVersion, func(t *testing.T) {
			root := t.TempDir()
			bin := t.TempDir()
			tarball := makeTestNPMPackageTgz(t, "dup", "1.0.0", `{}`)
			integrity := testSRI("sha512", tarball)
			writeFakeTool(t, bin, "npm", `#!/bin/sh
cat > package-lock.json <<'JSON'
{
  "lockfileVersion": `+lockfileVersion+`,
  "packages": {
    "": {"name": "stage"},
    "node_modules/dup": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/dup/-/dup-1.0.0.tgz",
      "integrity": "`+integrity+`"
    },
    "node_modules/parent/node_modules/dup": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/dup/-/dup-1.0.0.tgz",
      "integrity": "`+integrity+`"
    }
  }
}
JSON
`)
			t.Setenv("PATH", bin+":/bin:/usr/bin")
			withFakeNPMTarballs(t, map[string][]byte{"/dup/-/dup-1.0.0.tgz": tarball})

			artifacts, findings := StageArtifacts(context.Background(), filepath.Join(root, "stage"), Classify([]string{"npm", "install", "dup"}), VersionInfo{})

			if hasBlockingFinding(findings) || hasFinding(findings, "npm_tarball_download_failed") {
				t.Fatalf("findings = %#v, want deduplicated staging success", findings)
			}
			if len(artifacts) != 1 || !hasArtifact(artifacts, "dup", "1.0.0") {
				t.Fatalf("artifacts = %#v, want one dup@1.0.0 tarball", artifacts)
			}
		})
	}
}

func TestStageNPMBlocksConflictingNestedDuplicate(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	first := makeTestNPMPackageTgz(t, "dup", "1.0.0", `{}`)
	second := append([]byte(nil), first...)
	second = append(second, 'x')
	writeFakeTool(t, bin, "npm", `#!/bin/sh
cat > package-lock.json <<'JSON'
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "stage"},
    "node_modules/dup": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/dup/-/dup-1.0.0.tgz",
      "integrity": "`+testSRI("sha512", first)+`"
    },
    "node_modules/parent/node_modules/dup": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/dup/-/dup-1.0.0.tgz",
      "integrity": "`+testSRI("sha512", second)+`"
    }
  }
}
JSON
`)
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	withFakeNPMTarballs(t, map[string][]byte{})

	artifacts, findings := StageArtifacts(context.Background(), filepath.Join(root, "stage"), Classify([]string{"npm", "install", "dup"}), VersionInfo{})

	if len(artifacts) != 0 {
		t.Fatalf("artifacts = %#v, want none", artifacts)
	}
	if firstFindingSeverity(findings, "npm_lockfile_conflicting_duplicate") != "block" {
		t.Fatalf("findings = %#v, want blocking conflicting duplicate finding", findings)
	}
}

func TestParseNPMStagingLockfilePreservesDistinctVersions(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	integrity := "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/dup": {
				"version": "1.0.0",
				"resolved": "https://registry.npmjs.org/dup/-/dup-1.0.0.tgz",
				"integrity": "` + integrity + `"
			},
			"node_modules/parent/node_modules/dup": {
				"version": "2.0.0",
				"resolved": "https://registry.npmjs.org/dup/-/dup-2.0.0.tgz",
				"integrity": "` + integrity + `"
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
	if len(locked) != 2 || locked[0].Version != "1.0.0" || locked[1].Version != "2.0.0" {
		t.Fatalf("locked = %#v, want both dup versions", locked)
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
