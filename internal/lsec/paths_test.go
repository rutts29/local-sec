package lsec

import (
	"path/filepath"
	"testing"
)

func TestDefaultPathsHonorsLSECHome(t *testing.T) {
	t.Setenv("LSEC_HOME", filepath.Join(t.TempDir(), "state"))

	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(paths.Root) != "state" {
		t.Fatalf("root = %s, want state suffix", paths.Root)
	}
	if filepath.Dir(paths.DB) != filepath.Join(paths.Root, "db") {
		t.Fatalf("db path = %s, want inside root db dir", paths.DB)
	}
}
