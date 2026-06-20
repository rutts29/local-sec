package lsec

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallShimsCoversPythonLauncherAndVersionedInterpreters(t *testing.T) {
	paths := pathsFromRoot(t.TempDir())

	if err := InstallShims(paths, io.Discard); err != nil {
		t.Fatal(err)
	}

	for _, command := range []string{"py", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14"} {
		info, err := os.Stat(filepath.Join(paths.Bin, command))
		if err != nil {
			t.Fatalf("expected shim %s: %v", command, err)
		}
		if info.Mode()&0o111 == 0 {
			t.Fatalf("shim %s is not executable", command)
		}
	}
}

func TestDoctorWarnsOnShimThatDoesNotInvokeGuard(t *testing.T) {
	paths := pathsFromRoot(t.TempDir())
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.Bin, "npm"), []byte("#!/bin/sh\nexec npm \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", paths.Bin)

	var out bytes.Buffer
	if err := Doctor(paths, &out); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), "warn: shim does not invoke local-sec guard: npm") {
		t.Fatalf("doctor output = %q, want tampered shim warning", out.String())
	}
}

func TestDoctorAcceptsInstalledGuardShim(t *testing.T) {
	paths := pathsFromRoot(t.TempDir())
	if err := InstallShims(paths, io.Discard); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", paths.Bin)

	var out bytes.Buffer
	if err := Doctor(paths, &out); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(out.String(), "warn: shim does not invoke local-sec guard") {
		t.Fatalf("doctor output = %q, did not expect guard shim warning", out.String())
	}
}
