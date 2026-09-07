package lsec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMacOSDetonationRunExternalUsesAndRemovesPrivateWorkspace(t *testing.T) {
	root := t.TempDir()
	paths := pathsFromRoot(filepath.Join(root, ".local-sec"))
	store := NewStore(paths)
	seedRawRunEvent(t, paths, rawSecretRunReport())

	fixtureResult, err := RunLocalMacOSDetonationFixture(store, "run-remote-1", time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	fixtureBody, err := json.Marshal(fixtureResult)
	if err != nil {
		t.Fatal(err)
	}
	fixturePath := filepath.Join(root, "fixture-result.json")
	if err := os.WriteFile(fixturePath, fixtureBody, 0o600); err != nil {
		t.Fatal(err)
	}
	observedPath := filepath.Join(root, "observed-paths")
	runnerDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(runnerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFakeTool(t, runnerDir, "runner", `#!/bin/sh
set -eu
job=""
result=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --job) job="$2"; shift 2 ;;
    --result) result="$2"; shift 2 ;;
    *) exit 64 ;;
  esac
done
printf '%s\n%s\n' "$job" "$result" > `+shellQuote(observedPath)+`
cp `+shellQuote(fixturePath)+` "$result"
`)
	t.Setenv("LSEC_MACOS_DETONATION_RUNNER", filepath.Join(runnerDir, "runner"))

	var stdout bytes.Buffer
	if err := runMacOSDetonationCLI([]string{"run-external", "run-remote-1"}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	var result MacOSDetonationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not a result: %s: %v", stdout.String(), err)
	}

	pathsUsed := strings.Split(strings.TrimSpace(readTestFile(t, observedPath)), "\n")
	if len(pathsUsed) != 2 {
		t.Fatalf("runner paths = %#v, want job and result", pathsUsed)
	}
	workspaceDir := filepath.Dir(pathsUsed[0])
	if filepath.Dir(pathsUsed[1]) != workspaceDir {
		t.Fatalf("runner paths use different workspaces: %#v", pathsUsed)
	}
	if !strings.HasPrefix(filepath.Base(workspaceDir), "lsec-macos-detonation-") {
		t.Fatalf("workspace = %q, want private random prefix", workspaceDir)
	}
	if _, err := os.Stat(workspaceDir); !os.IsNotExist(err) {
		t.Fatalf("private workspace remains after runner: %v", err)
	}
}
