package lsec

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestDockerFixtureRunnerUsesHardenedDockerArgvWithoutHostLeaks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker script uses POSIX shell")
	}
	projectRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	realHome := filepath.Join(t.TempDir(), "real-home")
	t.Setenv("HOME", realHome)
	t.Setenv("NPM_TOKEN", "real-npm-token")
	t.Setenv("DOCKER_CONFIG", filepath.Join(realHome, ".docker"))

	fakeDocker := writeFakeDocker(t, "")
	runner := NewDockerFixtureRunner(DockerFixtureConfig{
		DockerPath: fakeDocker,
		Image:      "local-sec-fixture:latest",
		PidsLimit:  "64",
		Memory:     "128m",
		CPUs:       "0.5",
	})

	_, err = runner.RunSandbox(context.Background(), SandboxRequest{
		Mode:    SandboxModeDockerFixture,
		Command: []string{"node", "install.js"},
		Root:    projectRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	argv := readCapturedDockerArgv(t, fakeDocker)
	wantInOrder := []string{
		"run", "--pull", "never", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "128m", "--cpus", "0.5",
	}
	assertSubsequence(t, argv, wantInOrder)

	joined := strings.Join(argv, "\x00")
	for _, required := range []string{
		"HOME=/home/lsec",
		"PWD=/work",
		"TMPDIR=/tmp",
		"PATH=/opt/lsec-bin:/usr/bin:/bin",
		"/home/lsec",
		"/work",
		"/opt/lsec-bin",
		"/out",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("docker argv missing %q: %#v", required, argv)
		}
	}
	for _, forbidden := range []string{
		"/Users",
		realHome,
		projectRoot,
		"/var/run/docker.sock",
		".docker",
		".npmrc",
		"real-npm-token",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("docker argv leaked forbidden value %q: %#v", forbidden, argv)
		}
	}
}

func TestDockerFixtureRunnerDoesNotRecordRawRequestArgs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker script uses POSIX shell")
	}
	fakeDocker := writeFakeDocker(t, "")
	runner := NewDockerFixtureRunner(DockerFixtureConfig{DockerPath: fakeDocker, Image: "fixture"})

	result, err := runner.RunSandbox(context.Background(), SandboxRequest{
		Mode:    SandboxModeDockerFixture,
		Command: []string{"node", "install.js", "--token", "real-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Evidence.ProcessEvents) != 1 {
		t.Fatalf("process events = %#v, want one synthetic event", result.Evidence.ProcessEvents)
	}
	if result.Evidence.ProcessEvents[0].Executable != "node" {
		t.Fatalf("process executable = %q, want node", result.Evidence.ProcessEvents[0].Executable)
	}
	if result.Evidence.ProcessEvents[0].Args != nil {
		t.Fatalf("process args = %#v, want nil", result.Evidence.ProcessEvents[0].Args)
	}
	body, err := json.Marshal(result.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"--token", "real-secret"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("raw command arg %q leaked in unredacted evidence: %s", forbidden, body)
		}
	}
}

func TestDockerFixtureRunnerParsesCanaryNDJSONIntoBlockFinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker script uses POSIX shell")
	}
	output := strings.Join([]string{
		`{"type":"network","protocol":"https","destination":"https://example.invalid/collect","contains_canary":true}`,
		`{"type":"canary","kind":"env","marker":"lsec-canary-openai-api-key","destination":"https://example.invalid/collect"}`,
		``,
	}, "\n")
	fakeDocker := writeFakeDocker(t, output)
	runner := NewDockerFixtureRunner(DockerFixtureConfig{DockerPath: fakeDocker, Image: "fixture"})

	result, err := runner.RunSandbox(context.Background(), SandboxRequest{
		Mode:    SandboxModeDockerFixture,
		Command: []string{"npm", "install"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Mode != SandboxModeDockerFixture {
		t.Fatalf("mode = %q, want %q", result.Mode, SandboxModeDockerFixture)
	}
	if len(result.Evidence.NetworkEvents) != 1 {
		t.Fatalf("network events = %#v, want one", result.Evidence.NetworkEvents)
	}
	if !result.Evidence.NetworkEvents[0].ContainsCanary {
		t.Fatalf("network event = %#v, want canary flag", result.Evidence.NetworkEvents[0])
	}
	if len(result.Evidence.CanaryEvents) != 1 {
		t.Fatalf("canary events = %#v, want one", result.Evidence.CanaryEvents)
	}
	if dockerFixtureFindingSeverity(result.Findings, "sandbox_canary_exfiltration") != "block" {
		t.Fatalf("findings = %#v, want sandbox_canary_exfiltration block", result.Findings)
	}
}

func TestDockerFixtureRunnerParsesMountedOutputNDJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker script uses POSIX shell")
	}
	fakeDocker := writeFakeDockerOutputFile(t, `{"type":"network","protocol":"https","destination":"https://out.invalid","contains_canary":true}`)
	runner := NewDockerFixtureRunner(DockerFixtureConfig{DockerPath: fakeDocker, Image: "fixture"})

	result, err := runner.RunSandbox(context.Background(), SandboxRequest{
		Mode:    SandboxModeDockerFixture,
		Command: []string{"npm", "install"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Evidence.NetworkEvents) != 1 {
		t.Fatalf("network events = %#v, want one from output file", result.Evidence.NetworkEvents)
	}
	if result.Evidence.NetworkEvents[0].Destination != "https://out.invalid" {
		t.Fatalf("network event = %#v, want output file destination", result.Evidence.NetworkEvents[0])
	}
	if dockerFixtureFindingSeverity(result.Findings, "sandbox_canary_exfiltration") != "block" {
		t.Fatalf("findings = %#v, want sandbox_canary_exfiltration block", result.Findings)
	}
}

func TestDockerFixtureParserReadsLongNDJSONLine(t *testing.T) {
	destination := "https://out.invalid/" + strings.Repeat("a", 70*1024)
	line, err := json.Marshal(map[string]any{
		"type":            "network",
		"protocol":        "https",
		"destination":     destination,
		"contains_canary": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(line) >= dockerFixtureMaxOutputBytes {
		t.Fatalf("test line length = %d, want under cap", len(line))
	}

	evidence, findings := parseDockerFixtureOutput(append(line, '\n'))

	if len(evidence.NetworkEvents) != 1 {
		t.Fatalf("network events = %#v, want long line parsed", evidence.NetworkEvents)
	}
	if evidence.NetworkEvents[0].Destination != destination {
		t.Fatalf("destination length = %d, want %d", len(evidence.NetworkEvents[0].Destination), len(destination))
	}
	if dockerFixtureFindingSeverity(findings, "sandbox_canary_exfiltration") != "block" {
		t.Fatalf("findings = %#v, want canary finding from long line", findings)
	}
}

func TestDockerFixtureRunnerReportsAggregateMountedOutputTruncation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker script uses POSIX shell")
	}
	outputs := map[string]string{
		"one.ndjson":   strings.Repeat("x", dockerFixtureMaxOutputBytes/2),
		"two.ndjson":   strings.Repeat("y", dockerFixtureMaxOutputBytes/2),
		"three.ndjson": "z",
	}
	fakeDocker := writeFakeDockerOutputFiles(t, outputs)
	runner := NewDockerFixtureRunner(DockerFixtureConfig{DockerPath: fakeDocker, Image: "fixture"})

	result, err := runner.RunSandbox(context.Background(), SandboxRequest{
		Mode:    SandboxModeDockerFixture,
		Command: []string{"npm", "install"},
	})
	if err != nil {
		t.Fatal(err)
	}

	finding := dockerFixtureFinding(result.Findings, "sandbox_output_truncated")
	if finding == nil {
		t.Fatalf("findings = %#v, want sandbox_output_truncated", result.Findings)
	}
	if finding.Severity != "prompt" || finding.Message != "sandbox output exceeded capture limit" {
		t.Fatalf("finding = %#v, want aggregate truncation prompt", *finding)
	}
}

func TestDockerFixtureRunnerSkipsSymlinkedMountedOutputNDJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker script uses POSIX shell")
	}
	forbidden := filepath.Join(t.TempDir(), "forbidden.ndjson")
	if err := os.WriteFile(forbidden, []byte(`{"type":"network","protocol":"https","destination":"https://leak.invalid/lsec-canary-openai-api-key","contains_canary":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeDocker := writeFakeDockerOutputSymlink(t, forbidden)
	runner := NewDockerFixtureRunner(DockerFixtureConfig{DockerPath: fakeDocker, Image: "fixture"})

	result, err := runner.RunSandbox(context.Background(), SandboxRequest{
		Mode:    SandboxModeDockerFixture,
		Command: []string{"npm", "install"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Evidence.NetworkEvents) != 0 {
		t.Fatalf("network events = %#v, want no symlinked output read", result.Evidence.NetworkEvents)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %#v, want no leak-derived finding", result.Findings)
	}
}

func TestDockerFixtureShimsCaptureFlaggedCurlAndWgetURL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shim script uses POSIX shell")
	}
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	outDir := filepath.Join(root, "out")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeDockerFixtureShims(binDir); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "curl", args: []string{"-fsSL", "https://x.invalid/a"}},
		{name: "wget", args: []string{"-qO-", "https://x.invalid/a"}},
		{name: "curl", args: []string{"-fsSL", `http://x.invalid/a?quote="yes"&path=c:\tmp`}},
	} {
		cmd := exec.Command(filepath.Join(binDir, tc.name), tc.args...)
		cmd.Env = append(os.Environ(), "LSEC_DOCKER_FIXTURE_OUT="+outDir)
		err := cmd.Run()
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 7 {
			t.Fatalf("%s err = %v, want exit 7", tc.name, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(outDir, "network.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := parseDockerFixtureOutput(data)
	if len(evidence.NetworkEvents) != 3 {
		t.Fatalf("network events = %#v, want curl and wget events", evidence.NetworkEvents)
	}
	for _, event := range evidence.NetworkEvents[:2] {
		if event.Destination != "https://x.invalid/a" {
			t.Fatalf("network event = %#v, want flagged URL destination", event)
		}
		if event.Protocol != "https" {
			t.Fatalf("network event = %#v, want https protocol", event)
		}
	}
	if evidence.NetworkEvents[2].Protocol != "http" {
		t.Fatalf("network event = %#v, want http protocol", evidence.NetworkEvents[2])
	}
	if evidence.NetworkEvents[2].Destination != `http://x.invalid/a?quote="yes"&path=c:\tmp` {
		t.Fatalf("network event = %#v, want safely escaped destination", evidence.NetworkEvents[2])
	}
}

func TestDockerFixtureRunnerReportsTruncatedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker script uses POSIX shell")
	}
	for _, tc := range []struct {
		name         string
		fakeDocker   func(*testing.T) string
		wantEvidence string
	}{
		{
			name: "stdout",
			fakeDocker: func(t *testing.T) string {
				return writeFakeDockerStreams(t, strings.Repeat("x", dockerFixtureMaxOutputBytes+1), "")
			},
			wantEvidence: "stdout",
		},
		{
			name: "stderr",
			fakeDocker: func(t *testing.T) string {
				return writeFakeDockerStreams(t, "", strings.Repeat("x", dockerFixtureMaxOutputBytes+1))
			},
			wantEvidence: "stderr",
		},
		{
			name: "output file",
			fakeDocker: func(t *testing.T) string {
				return writeFakeDockerOutputFile(t, strings.Repeat("x", dockerFixtureMaxOutputBytes+1))
			},
			wantEvidence: "network.ndjson",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeDocker := tc.fakeDocker(t)
			runner := NewDockerFixtureRunner(DockerFixtureConfig{DockerPath: fakeDocker, Image: "fixture"})

			result, err := runner.RunSandbox(context.Background(), SandboxRequest{
				Mode:    SandboxModeDockerFixture,
				Command: []string{"npm", "install"},
			})
			if err != nil {
				t.Fatal(err)
			}

			finding := dockerFixtureFinding(result.Findings, "sandbox_output_truncated")
			if finding == nil {
				t.Fatalf("findings = %#v, want sandbox_output_truncated", result.Findings)
			}
			if finding.Severity != "prompt" || finding.Message != "sandbox output exceeded capture limit" || finding.Evidence != tc.wantEvidence {
				t.Fatalf("finding = %#v, want %s truncation prompt", *finding, tc.wantEvidence)
			}
		})
	}
}

func TestDockerFixtureParserFlagsCanaryDestinationAsBlockFinding(t *testing.T) {
	evidence, findings := parseDockerFixtureOutput([]byte(`{"type":"network","protocol":"https","destination":"https://example.invalid/lsec-canary-openai-api-key","contains_canary":false}`))

	if len(evidence.NetworkEvents) != 1 {
		t.Fatalf("network events = %#v, want one", evidence.NetworkEvents)
	}
	if !evidence.NetworkEvents[0].ContainsCanary {
		t.Fatalf("network event = %#v, want parser-detected canary flag", evidence.NetworkEvents[0])
	}
	if dockerFixtureFindingSeverity(findings, "sandbox_canary_exfiltration") != "block" {
		t.Fatalf("findings = %#v, want sandbox_canary_exfiltration block", findings)
	}
}

func writeFakeDockerOutputFile(t *testing.T, output string) string {
	t.Helper()
	return writeFakeDockerOutputFiles(t, map[string]string{"network.ndjson": output})
}

func writeFakeDockerOutputFiles(t *testing.T, outputs map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	script := "#!/bin/sh\n" +
		"out=''\n" +
		"while [ \"$#\" -gt 0 ]; do\n" +
		"  if [ \"$1\" = '--mount' ]; then\n" +
		"    shift\n" +
		"    case \"$1\" in *target=/out*) out=$(printf '%s' \"$1\" | sed 's/^.*source=//; s/,target=.*$//') ;; esac\n" +
		"  fi\n" +
		"  shift\n" +
		"done\n" +
		"mkdir -p \"$out\"\n"
	names := make([]string, 0, len(outputs))
	for name := range outputs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		script += "cat > \"$out/" + name + "\" <<'EOF'\n" +
			outputs[name] + "\n" +
			"EOF\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFakeDockerOutputSymlink(t *testing.T, target string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	script := "#!/bin/sh\n" +
		"out=''\n" +
		"while [ \"$#\" -gt 0 ]; do\n" +
		"  if [ \"$1\" = '--mount' ]; then\n" +
		"    shift\n" +
		"    case \"$1\" in *target=/out*) out=$(printf '%s' \"$1\" | sed 's/^.*source=//; s/,target=.*$//') ;; esac\n" +
		"  fi\n" +
		"  shift\n" +
		"done\n" +
		"mkdir -p \"$out\"\n" +
		"ln -s " + shellQuoteDockerFixtureTest(target) + " \"$out/network.ndjson\"\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func shellQuoteDockerFixtureTest(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func writeFakeDocker(t *testing.T, output string) string {
	t.Helper()
	return writeFakeDockerStreams(t, output, "")
}

func writeFakeDockerStreams(t *testing.T, stdout, stderr string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	script := "#!/bin/sh\n" +
		"printf '%s\n' \"$@\" > \"$0.argv\"\n" +
		"cat <<'EOF'\n" +
		stdout +
		"EOF\n" +
		"cat >&2 <<'EOF'\n" +
		stderr +
		"EOF\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func readCapturedDockerArgv(t *testing.T, dockerPath string) []string {
	t.Helper()
	data, err := os.ReadFile(dockerPath + ".argv")
	if err != nil {
		t.Fatal(err)
	}
	var argv []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			argv = append(argv, line)
		}
	}
	return argv
}

func assertSubsequence(t *testing.T, got, want []string) {
	t.Helper()
	next := 0
	for _, item := range got {
		if next < len(want) && item == want[next] {
			next++
		}
	}
	if next != len(want) {
		body, _ := json.Marshal(got)
		t.Fatalf("argv missing subsequence %#v in %s", want, body)
	}
}

func dockerFixtureFindingSeverity(findings []Finding, code string) string {
	finding := dockerFixtureFinding(findings, code)
	if finding == nil {
		return ""
	}
	return finding.Severity
}

func dockerFixtureFinding(findings []Finding, code string) *Finding {
	for _, finding := range findings {
		if finding.Code == code {
			return &finding
		}
	}
	return nil
}
