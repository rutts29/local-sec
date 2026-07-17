package lsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type FakeSandboxEnvironment struct {
	Root     string            `json:"root"`
	Home     string            `json:"home"`
	WorkDir  string            `json:"work_dir"`
	Env      []string          `json:"env"`
	EnvMap   map[string]string `json:"env_map"`
	Evidence SandboxEvidence   `json:"evidence"`
}

func BuildFakeSandboxEnvironment(root string) (FakeSandboxEnvironment, error) {
	root = filepath.Clean(root)
	home := filepath.Join(root, "home")
	workDir := filepath.Join(root, "work")
	tmpDir := filepath.Join(root, "tmp")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return FakeSandboxEnvironment{}, err
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return FakeSandboxEnvironment{}, err
	}
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return FakeSandboxEnvironment{}, err
	}

	envMap := fakeSandboxEnvMap(home, workDir, tmpDir)
	files := map[string]string{
		".ssh/id_rsa":           fakePrivateKey(envMap["LSEC_CANARY_SSH_KEY"]),
		".aws/credentials":      fakeAWSCredentials(envMap),
		".npmrc":                fmt.Sprintf("//registry.npmjs.org/:_authToken=%s\n", envMap["NPM_TOKEN"]),
		".pypirc":               fakePyPIRC(envMap["PYPI_TOKEN"]),
		".claude/settings.json": fakeJSON(map[string]string{"apiKey": envMap["ANTHROPIC_API_KEY"], "canary": envMap["LSEC_CANARY_SETTINGS"]}),
		".codex/config.toml":    fmt.Sprintf("api_key = %q\ncanary = %q\n", envMap["OPENAI_API_KEY"], envMap["LSEC_CANARY_SETTINGS"]),
		".vscode/tasks.json":    fakeJSON(map[string]any{"version": "2.0.0", "tasks": []map[string]string{{"label": "lsec-canary", "type": "shell", "command": "printf " + envMap["LSEC_CANARY_TASK"]}}}),
	}

	generatedFiles := make([]GeneratedFile, 0, len(files))
	for rel, content := range files {
		path := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return FakeSandboxEnvironment{}, err
		}
		perm := os.FileMode(0o600)
		if err := os.WriteFile(path, []byte(content), perm); err != nil {
			return FakeSandboxEnvironment{}, err
		}
		generatedFiles = append(generatedFiles, GeneratedFile{Path: path, SHA256: sha256Hex(content)})
	}
	sort.Slice(generatedFiles, func(i, j int) bool {
		return generatedFiles[i].Path < generatedFiles[j].Path
	})

	return FakeSandboxEnvironment{
		Root:    root,
		Home:    home,
		WorkDir: workDir,
		Env:     envMapEntries(envMap),
		EnvMap:  envMap,
		Evidence: SandboxEvidence{
			Enabled:         true,
			Mode:            string(SandboxModeFakeCanary),
			GeneratedFiles:  generatedFiles,
			FakeEnvironment: envMap,
		},
	}, nil
}

func fakeSandboxEnvMap(home, workDir, tmpDir string) map[string]string {
	return map[string]string{
		"HOME":                  home,
		"PWD":                   workDir,
		"PATH":                  "/usr/bin:/bin:/usr/sbin:/sbin",
		"TMPDIR":                tmpDir,
		"NO_COLOR":              "1",
		"OPENAI_API_KEY":        "lsec-canary-openai-api-key",
		"ANTHROPIC_API_KEY":     "lsec-canary-anthropic-api-key",
		"GITHUB_TOKEN":          "lsec-canary-github-token",
		"AWS_ACCESS_KEY_ID":     "lsec-canary-aws-access-key-id",
		"AWS_SECRET_ACCESS_KEY": "lsec-canary-aws-secret-access-key",
		"AWS_SESSION_TOKEN":     "lsec-canary-aws-session-token",
		"AWS_DEFAULT_REGION":    "us-east-1",
		"NPM_TOKEN":             "lsec-canary-npm-token",
		"PYPI_TOKEN":            "lsec-canary-pypi-token",
		"LSEC_CANARY_SSH_KEY":   "lsec-canary-ssh-private-key",
		"LSEC_CANARY_SETTINGS":  "lsec-canary-settings",
		"LSEC_CANARY_TASK":      "lsec-canary-vscode-task",
	}
}

func envMapEntries(envMap map[string]string) []string {
	keys := make([]string, 0, len(envMap))
	for key := range envMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+envMap[key])
	}
	return env
}

func fakePrivateKey(canary string) string {
	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + canary + "\n-----END OPENSSH PRIVATE KEY-----\n"
}

func fakeAWSCredentials(envMap map[string]string) string {
	return fmt.Sprintf("[default]\naws_access_key_id=%s\naws_secret_access_key=%s\naws_session_token=%s\n", envMap["AWS_ACCESS_KEY_ID"], envMap["AWS_SECRET_ACCESS_KEY"], envMap["AWS_SESSION_TOKEN"])
}

func fakePyPIRC(token string) string {
	return fmt.Sprintf("[distutils]\nindex-servers = pypi\n[pypi]\nusername = __token__\npassword = %s\n", token)
}

func fakeJSON(value any) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "{}\n"
	}
	return string(data) + "\n"
}

func sha256Hex(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}
