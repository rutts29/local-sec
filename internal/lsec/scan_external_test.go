package lsec

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProviderSnapshotErrorIsCategorical(t *testing.T) {
	tests := []struct {
		name     string
		runErr   error
		parseErr error
		want     string
	}{
		{name: "timeout", runErr: errors.New("provider timed out: context deadline exceeded"), want: "timeout"},
		{name: "execution failure", runErr: errors.New("exit status 2: /private/project/requirements.txt: secret output"), want: "execution_failed"},
		{name: "invalid output", parseErr: errors.New("invalid character in /private/project/secret.json"), want: "invalid_output"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := providerSnapshotError(tt.runErr, tt.parseErr); got != tt.want {
				t.Fatalf("providerSnapshotError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProviderFailureMessageDoesNotIncludeProviderOutput(t *testing.T) {
	stdout := []byte("AWS_SECRET_ACCESS_KEY=super-secret\nprivate-package==1.0\n" + providerOutputTruncatedMarker)
	stderr := []byte("failed reading /private/project/requirements.txt")

	message := providerFailureMessage("pip-audit", errors.New("exit status 2"), stdout, stderr, errors.New("invalid json"))

	for _, leaked := range []string{"super-secret", "private-package", "/private/project", "requirements.txt", "invalid json"} {
		if strings.Contains(message, leaked) {
			t.Fatalf("provider failure message leaked %q: %q", leaked, message)
		}
	}
	if !strings.Contains(message, "execution_failed") || !strings.Contains(message, "truncated") {
		t.Fatalf("provider failure message = %q, want category and truncation state", message)
	}
}

func TestGrypeRevalidatesObservationPathBeforeExec(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	sbom := filepath.Join(root, "bom.json")
	marker := filepath.Join(root, "called")
	if err := os.WriteFile(target, []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, sbom); err != nil {
		t.Fatal(err)
	}
	writeFakeTool(t, root, "grype", "#!/bin/sh\nprintf called > "+shellQuote(marker)+"\n")
	t.Setenv("PATH", root)

	_, diagnostics, snapshot := runGrypeProvider(t.Context(), "run", []ScanObservation{{SourceType: "cyclonedx_sbom", SourcePath: sbom}})

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("grype marker stat err = %v, want provider not invoked", err)
	}
	if len(diagnostics) != 0 || snapshot.Status != "not_applicable" {
		t.Fatalf("diagnostics = %#v snapshot = %#v, want safe skip", diagnostics, snapshot)
	}
	if snapshot.CandidateCount != 1 || snapshot.AcceptedCount != 0 || snapshot.SkippedCount != 1 || snapshot.SkipReasons["symlink"] != 1 {
		t.Fatalf("snapshot = %#v, want categorical symlink rejection", snapshot)
	}
}

func TestScanProviderCommandTimeoutReturnsPromptly(t *testing.T) {
	root := t.TempDir()
	writeFakeTool(t, root, "slow-tool", "#!/bin/sh\nsleep 1\n")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	stdout, stderr, err := runScanProviderCommand(ctx, root+"/slow-tool")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if len(stdout) != 0 {
		t.Fatalf("stdout = %q, want empty", string(stdout))
	}
	if len(stderr) != 0 {
		t.Fatalf("stderr = %q, want empty", string(stderr))
	}
	if !strings.Contains(strings.ToLower(err.Error()), "timed out") && !strings.Contains(strings.ToLower(err.Error()), "deadline exceeded") && !strings.Contains(strings.ToLower(err.Error()), "canceled") {
		t.Fatalf("err = %q, want timeout or canceled semantics", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("elapsed = %s, want prompt cancellation", elapsed)
	}
}

func TestScanProviderCommandTimeoutKillsBackgroundChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-tree timeout behavior is implemented with Unix process groups")
	}
	root := t.TempDir()
	marker := filepath.Join(root, "child-marker")
	started := filepath.Join(root, "child-started")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, _, err := runScanProviderCommand(ctx, os.Args[0], "-test.run=TestScanProviderBackgroundChildHelper", "--", marker, started)
		errCh <- err
	}()

	waitForFile(t, started, 500*time.Millisecond)
	cancel()

	err := <-errCh
	if err == nil {
		t.Fatal("expected timeout error")
	}

	time.Sleep(350 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker stat err = %v, want background child killed before writing marker", err)
	}
}

func TestScanProviderBackgroundChildHelper(t *testing.T) {
	args := helperArgs()
	if len(args) != 2 {
		return
	}
	child := exec.Command(os.Args[0], "-test.run=TestScanProviderMarkerWriterHelper", "--", args[0])
	if err := child.Start(); err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(args[1], []byte("started"), 0o600); err != nil {
		os.Exit(2)
	}
	time.Sleep(time.Second)
	os.Exit(0)
}

func TestScanProviderMarkerWriterHelper(t *testing.T) {
	args := helperArgs()
	if len(args) != 1 {
		return
	}
	time.Sleep(200 * time.Millisecond)
	if err := os.WriteFile(args[0], []byte("child"), 0o600); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func helperArgs() []string {
	for i, arg := range os.Args {
		if arg == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func TestScanProviderEnvFiltersCredentialedSchemelessProxyAndControls(t *testing.T) {
	t.Setenv("HTTP_PROXY", "user:pass@proxy:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy.local:8080")
	t.Setenv("ALL_PROXY", "http://proxy.local:8080\nbad")
	t.Setenv("NO_PROXY", "localhost")

	env := scanProviderEnv("/tmp/home", "/tmp/cache", "/tmp/config")

	if hasEnvPrefix(env, "HTTP_PROXY=") {
		t.Fatalf("env = %#v, want schemeless credentialed HTTP_PROXY omitted", env)
	}
	if hasEnvPrefix(env, "ALL_PROXY=") {
		t.Fatalf("env = %#v, want control-character ALL_PROXY omitted", env)
	}
	if !hasEnvValue(env, "HTTPS_PROXY=http://proxy.local:8080") {
		t.Fatalf("env = %#v, want safe HTTPS_PROXY preserved", env)
	}
	if !hasEnvValue(env, "NO_PROXY=localhost") {
		t.Fatalf("env = %#v, want NO_PROXY preserved", env)
	}
}

func hasEnvPrefix(env []string, prefix string) bool {
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return true
		}
	}
	return false
}

func hasEnvValue(env []string, value string) bool {
	for _, entry := range env {
		if entry == value {
			return true
		}
	}
	return false
}

func readProviderSnapshot(t *testing.T, lsecHome, runID, provider string) ScanProviderSnapshot {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(lsecHome, "scans", runID, "provider-snapshots.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshots []ScanProviderSnapshot
	if err := json.Unmarshal(body, &snapshots); err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range snapshots {
		if snapshot.Provider == provider {
			return snapshot
		}
	}
	t.Fatalf("provider %q not found in %s", provider, string(body))
	return ScanProviderSnapshot{}
}
