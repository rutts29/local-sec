package lsec

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunSandboxDockerFixturePrintsRedactedJSONAndReturnsErrorForBlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker script uses POSIX shell")
	}
	home := filepath.Join(t.TempDir(), "real-home")
	t.Setenv("HOME", home)
	t.Setenv("NPM_TOKEN", "real-npm-token")

	fakeDocker := writeAssertingSandboxCLIDocker(t, home)
	var stdout bytes.Buffer

	err := Run([]string{
		"sandbox", "run",
		"--mode", "docker-fixture",
		"--docker", fakeDocker,
		"--",
		"node", "install.js", "--token", "sk-real-token-1234567890abcd",
	}, strings.NewReader(""), &stdout, io.Discard)

	if err == nil {
		t.Fatal("sandbox block finding should return an error")
	}
	var result SandboxResult
	if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
		t.Fatalf("stdout is not SandboxResult JSON: %q err=%v", stdout.String(), decodeErr)
	}
	if dockerFixtureFindingSeverity(result.Findings, "sandbox_canary_exfiltration") != "block" {
		t.Fatalf("findings = %#v, want sandbox_canary_exfiltration block", result.Findings)
	}
	body := stdout.String()
	for _, forbidden := range []string{
		"lsec-canary-",
		"/Users/",
		home,
		"real-npm-token",
		"sk-real-token-1234567890abcd",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("sandbox JSON leaked %q: %s", forbidden, body)
		}
	}
}

func TestRunSandboxRejectsInvalidMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var stdout bytes.Buffer

	err := Run([]string{"sandbox", "run", "--mode", "fake-canary", "--", "true"}, strings.NewReader(""), &stdout, io.Discard)

	if err == nil || !strings.Contains(err.Error(), "unsupported sandbox mode") {
		t.Fatalf("err = %v, want unsupported sandbox mode", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunSandboxRejectsInvalidModeWithoutCreatingLSECHome(t *testing.T) {
	lsecHome := filepath.Join(t.TempDir(), ".local-sec")
	t.Setenv("LSEC_HOME", lsecHome)

	err := Run([]string{"sandbox", "run", "--mode", "fake-canary", "--", "true"}, strings.NewReader(""), io.Discard, io.Discard)

	if err == nil || !strings.Contains(err.Error(), "unsupported sandbox mode") {
		t.Fatalf("err = %v, want unsupported sandbox mode", err)
	}
	if _, statErr := os.Stat(lsecHome); !os.IsNotExist(statErr) {
		t.Fatalf("LSEC_HOME stat err = %v, want not exist", statErr)
	}
}

func TestRunSandboxPersistsRedactedEvidenceBundle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker script uses POSIX shell")
	}
	root := t.TempDir()
	home := filepath.Join(root, "real-home")
	lsecHome := filepath.Join(root, ".local-sec")
	t.Setenv("HOME", home)
	t.Setenv("LSEC_HOME", lsecHome)
	t.Setenv("NPM_TOKEN", "real-npm-token")

	fakeDocker := writeAssertingSandboxCLIDocker(t, home)

	err := Run([]string{
		"sandbox", "run",
		"--mode", "docker-fixture",
		"--docker", fakeDocker,
		"--",
		"node", "install.js", "--token", "sk-real-token-1234567890abcd",
	}, strings.NewReader(""), io.Discard, io.Discard)

	if err == nil {
		t.Fatal("sandbox block finding should return an error")
	}
	body, readErr := os.ReadFile(filepath.Join(lsecHome, "logs", "events.jsonl"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var row eventLogRow
	if decodeErr := json.Unmarshal(bytes.TrimSpace(body), &row); decodeErr != nil {
		t.Fatalf("event log row is not JSON: %q err=%v", string(body), decodeErr)
	}
	if row.Kind != "sandbox_run" {
		t.Fatalf("event kind = %q, want sandbox_run", row.Kind)
	}
	var bundle EvidenceBundle
	if decodeErr := json.Unmarshal(row.JSON, &bundle); decodeErr != nil {
		t.Fatalf("event payload is not EvidenceBundle JSON: %s err=%v", string(row.JSON), decodeErr)
	}
	if bundle.RunID == "" {
		t.Fatal("event bundle missing run_id")
	}
	if !validSHA256Hex(bundle.EvidenceSHA256) {
		t.Fatalf("evidence_sha256 = %q, want sha256 hex", bundle.EvidenceSHA256)
	}
	for _, forbidden := range []string{
		"lsec-canary-",
		"/Users/",
		home,
		"real-npm-token",
		"sk-real-token-1234567890abcd",
	} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("sandbox event leaked %q: %s", forbidden, string(body))
		}
	}
}

func TestRunSandboxRequiresSeparator(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := Run([]string{"sandbox", "run", "--mode", "docker-fixture", "true"}, strings.NewReader(""), io.Discard, io.Discard)

	if err == nil || !strings.Contains(err.Error(), "requires -- before the fixture command") {
		t.Fatalf("err = %v, want missing separator error", err)
	}
}

func TestRunSandboxRejectsEmptyCommand(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := Run([]string{"sandbox", "run", "--mode", "docker-fixture", "--"}, strings.NewReader(""), io.Discard, io.Discard)

	if err == nil || !strings.Contains(err.Error(), "requires a fixture command") {
		t.Fatalf("err = %v, want empty command error", err)
	}
}

func writeAssertingSandboxCLIDocker(t *testing.T, realHome string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	script := "#!/bin/sh\n" +
		"args=$(printf '%s\\n' \"$@\")\n" +
		"need() { printf '%s\\n' \"$args\" | grep -Fx -- \"$1\" >/dev/null || { echo \"missing $1\" >&2; exit 33; }; }\n" +
		"need '--network'\n" +
		"need 'none'\n" +
		"need '--read-only'\n" +
		"need '--cap-drop'\n" +
		"need 'ALL'\n" +
		"need '--security-opt'\n" +
		"need 'no-new-privileges'\n" +
		"need '--pids-limit'\n" +
		"need '128'\n" +
		"need '--memory'\n" +
		"need '256m'\n" +
		"need '--cpus'\n" +
		"need '1'\n" +
		"printf '%s\\n' \"$args\" | grep -F '/Users' >/dev/null && { echo '/Users leaked' >&2; exit 34; }\n" +
		"printf '%s\\n' \"$args\" | grep -F " + shellQuoteSandboxCLITest(realHome) + " >/dev/null && { echo 'home leaked' >&2; exit 35; }\n" +
		"printf '%s\\n' \"$args\" | grep -F 'real-npm-token' >/dev/null && { echo 'token leaked' >&2; exit 36; }\n" +
		"mounts=$(printf '%s\\n' \"$args\" | grep -F 'type=bind,source=')\n" +
		"[ \"$(printf '%s\\n' \"$mounts\" | grep -c 'type=bind,source=')\" = '4' ] || { echo 'unexpected mount count' >&2; exit 41; }\n" +
		"printf '%s\\n' \"$mounts\" | grep -F 'target=/home/lsec' >/dev/null || { echo 'missing synthetic home mount' >&2; exit 37; }\n" +
		"printf '%s\\n' \"$mounts\" | grep -F 'target=/work' >/dev/null || { echo 'missing synthetic work mount' >&2; exit 38; }\n" +
		"printf '%s\\n' \"$mounts\" | grep -F 'target=/opt/lsec-bin' >/dev/null || { echo 'missing synthetic bin mount' >&2; exit 39; }\n" +
		"printf '%s\\n' \"$mounts\" | grep -F 'target=/out' >/dev/null || { echo 'missing synthetic out mount' >&2; exit 40; }\n" +
		"cat <<'EOF'\n" +
		"{\"type\":\"network\",\"protocol\":\"https\",\"destination\":\"https://example.invalid/collect/lsec-canary-openai-api-key\",\"contains_canary\":true}\n" +
		"{\"type\":\"canary\",\"kind\":\"env\",\"marker\":\"lsec-canary-openai-api-key\",\"destination\":\"https://example.invalid/collect/lsec-canary-openai-api-key\"}\n" +
		"EOF\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func shellQuoteSandboxCLITest(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
