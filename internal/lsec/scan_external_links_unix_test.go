//go:build unix

package lsec

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestHardlinkedProviderInputsAreSkippedBeforeProviderInvocation(t *testing.T) {
	tests := []struct {
		name     string
		tool     string
		fileName string
		run      func(string)
	}{
		{
			name:     "OSV scanner lockfile",
			tool:     "osv-scanner",
			fileName: "package-lock.json",
			run: func(project string) {
				_, _, snapshot := runOSVScannerProvider(t.Context(), "run", []string{project})
				assertRejectedProviderInput(t, snapshot)
			},
		},
		{
			name:     "pip audit requirements",
			tool:     "pip-audit",
			fileName: "requirements.txt",
			run: func(project string) {
				_, _, snapshot := runPipAuditProvider(t.Context(), "run", []string{project})
				assertRejectedProviderInput(t, snapshot)
			},
		},
		{
			name:     "grype SBOM",
			tool:     "grype",
			fileName: "bom.json",
			run: func(project string) {
				path := filepath.Join(project, "bom.json")
				_, _, snapshot := runGrypeProvider(t.Context(), "run", []ScanObservation{{SourceType: "cyclonedx_sbom", SourcePath: path}})
				assertRejectedProviderInput(t, snapshot)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			project := filepath.Join(root, "project")
			original := filepath.Join(root, "unrelated-input")
			linked := filepath.Join(project, tt.fileName)
			marker := filepath.Join(root, "provider-called")
			if err := os.MkdirAll(project, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(original, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(original, linked); err != nil {
				t.Fatal(err)
			}
			writeFakeTool(t, root, tt.tool, "#!/bin/sh\nprintf called > "+shellQuote(marker)+"\n")
			t.Setenv("PATH", root)

			tt.run(project)

			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("provider marker stat err = %v, want provider not invoked", err)
			}
		})
	}
}

func assertRejectedProviderInput(t *testing.T, snapshot ScanProviderSnapshot) {
	t.Helper()
	if snapshot.Status != "not_applicable" || snapshot.CandidateCount != 1 || snapshot.AcceptedCount != 0 || snapshot.SkippedCount != 1 || snapshot.QueriedCount != 0 || snapshot.FailedCount != 0 {
		t.Fatalf("snapshot = %#v, want one hardlinked input skipped before provider invocation", snapshot)
	}
	if snapshot.SkipReasons["link_count"] != 1 {
		t.Fatalf("skip reasons = %#v, want link count rejection", snapshot.SkipReasons)
	}
}

func TestProviderInputRejectionRejectsFIFOAndDevice(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "requirements.txt")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := providerInputRejection(fifo); got != "non_regular" {
		t.Fatalf("FIFO rejection = %q, want non_regular", got)
	}
	if got := providerInputRejection("/dev/null"); got != "non_regular" {
		t.Fatalf("device rejection = %q, want non_regular", got)
	}
}
