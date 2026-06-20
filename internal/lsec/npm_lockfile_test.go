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
