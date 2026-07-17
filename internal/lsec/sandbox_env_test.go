package lsec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFakeSandboxEnvironmentCreatesCanaryFilesUnderRoot(t *testing.T) {
	root := t.TempDir()

	env, err := BuildFakeSandboxEnvironment(root)
	if err != nil {
		t.Fatal(err)
	}

	if env.Home == "" {
		t.Fatal("home is empty")
	}
	assertPathUnderRoot(t, root, env.Home)
	assertPathUnderRoot(t, root, env.WorkDir)
	for _, key := range []string{"HOME", "PWD", "TMPDIR"} {
		assertPathUnderRoot(t, root, env.EnvMap[key])
		if _, err := os.Stat(env.EnvMap[key]); err != nil {
			t.Fatalf("%s path %q is missing: %v", key, env.EnvMap[key], err)
		}
	}
	for _, generated := range env.Evidence.GeneratedFiles {
		assertPathUnderRoot(t, root, generated.Path)
		data, err := os.ReadFile(generated.Path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "lsec-canary-") {
			t.Fatalf("%s does not contain a canary marker", generated.Path)
		}
	}
	for _, rel := range []string{
		".ssh/id_rsa",
		".aws/credentials",
		".npmrc",
		".pypirc",
		".claude/settings.json",
		".codex/config.toml",
		".vscode/tasks.json",
	} {
		path := filepath.Join(env.Home, rel)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing fake file %s: %v", rel, err)
		}
	}
	for _, key := range []string{
		"OPENAI_API_KEY",
		"ANTHROPIC_API_KEY",
		"GITHUB_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
	} {
		value := env.EnvMap[key]
		if !strings.Contains(value, "lsec-canary-") {
			t.Fatalf("%s = %q, want fake canary value", key, value)
		}
	}
	if !env.Evidence.Enabled {
		t.Fatalf("evidence = %#v, want enabled sandbox evidence", env.Evidence)
	}
	if env.Evidence.Mode != string(SandboxModeFakeCanary) {
		t.Fatalf("mode = %q, want %q", env.Evidence.Mode, SandboxModeFakeCanary)
	}
	if len(env.Evidence.FakeEnvironment) == 0 {
		t.Fatal("fake environment evidence is empty")
	}
}

func TestFakeSandboxEnvironmentDoesNotLeakRealHomeOrUsersPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", "/Users/real-developer")
	t.Setenv("USER", "real-developer")
	t.Setenv("PATH", "/Users/real-developer/bin:/usr/bin:/bin")

	env, err := BuildFakeSandboxEnvironment(root)
	if err != nil {
		t.Fatal(err)
	}

	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(envJSON), "/Users/real-developer") || strings.Contains(string(envJSON), "/Users/") {
		t.Fatalf("fake environment leaked real user path: %s", string(envJSON))
	}
	for _, generated := range env.Evidence.GeneratedFiles {
		data, err := os.ReadFile(generated.Path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "/Users/real-developer") || strings.Contains(string(data), "/Users/") {
			t.Fatalf("%s leaked real user path: %s", generated.Path, string(data))
		}
	}
}

func assertPathUnderRoot(t *testing.T, root, path string) {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatal(err)
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		t.Fatalf("path %q is not under root %q", path, root)
	}
}
