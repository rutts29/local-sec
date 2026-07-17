package lsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	dockerContainerHome = "/home/lsec"
	dockerContainerWork = "/work"
	dockerContainerTmp  = "/tmp"
	dockerContainerBin  = "/opt/lsec-bin"
	dockerContainerOut  = "/out"

	dockerFixtureMaxOutputBytes = 1 << 20
)

type DockerFixtureConfig struct {
	DockerPath string
	Image      string
	PidsLimit  string
	Memory     string
	CPUs       string
}

type DockerFixtureRunner struct {
	config DockerFixtureConfig
}

func NewDockerFixtureRunner(config DockerFixtureConfig) DockerFixtureRunner {
	if config.DockerPath == "" {
		config.DockerPath = "docker"
	}
	if config.Image == "" {
		config.Image = "local-sec-docker-fixture"
	}
	if config.PidsLimit == "" {
		config.PidsLimit = "128"
	}
	if config.Memory == "" {
		config.Memory = "256m"
	}
	if config.CPUs == "" {
		config.CPUs = "1"
	}
	return DockerFixtureRunner{config: config}
}

func (runner DockerFixtureRunner) RunSandbox(ctx context.Context, request SandboxRequest) (SandboxResult, error) {
	if len(request.Command) == 0 {
		return SandboxResult{}, errors.New("docker fixture sandbox requires a command")
	}
	root, err := os.MkdirTemp("", "lsec-docker-fixture-")
	if err != nil {
		return SandboxResult{}, err
	}
	defer os.RemoveAll(root)

	fixtureEnv, err := BuildFakeSandboxEnvironment(root)
	if err != nil {
		return SandboxResult{}, err
	}
	binDir := filepath.Join(root, "bin")
	outDir := filepath.Join(root, "out")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return SandboxResult{}, err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return SandboxResult{}, err
	}
	if err := writeDockerFixtureShims(binDir); err != nil {
		return SandboxResult{}, err
	}

	args := runner.dockerArgs(fixtureEnv, binDir, outDir, request.Command)
	var stdout, stderr dockerFixtureOutputCapture
	cmd := exec.CommandContext(ctx, runner.config.DockerPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	err = cmd.Run()

	outputChunks, truncationFindings, readErr := readDockerFixtureOutputFiles(outDir)
	if stdout.truncated {
		truncationFindings = append(truncationFindings, dockerFixtureTruncationFinding("stdout"))
	}
	if stderr.truncated {
		truncationFindings = append(truncationFindings, dockerFixtureTruncationFinding("stderr"))
	}
	outputChunks = append([][]byte{stdout.Bytes(), stderr.Bytes()}, outputChunks...)
	evidence, findings := parseDockerFixtureOutput(outputChunks...)
	findings = append(findings, truncationFindings...)
	evidence.Enabled = true
	evidence.Mode = string(SandboxModeDockerFixture)
	evidence.ProcessEvents = append(evidence.ProcessEvents, ProcessEvent{Executable: request.Command[0]})
	evidence.GeneratedFiles = fixtureEnv.Evidence.GeneratedFiles
	evidence.FakeEnvironment = dockerFixtureEnvMap(fixtureEnv.EnvMap)

	result := SandboxResult{
		Mode:     SandboxModeDockerFixture,
		Findings: findings,
		Evidence: evidence,
	}
	if err != nil {
		return result, fmt.Errorf("docker fixture sandbox failed: %w", err)
	}
	if readErr != nil {
		return result, readErr
	}
	return result, nil
}

type dockerFixtureOutputCapture struct {
	buf       bytes.Buffer
	truncated bool
}

func (capture *dockerFixtureOutputCapture) Write(p []byte) (int, error) {
	remaining := dockerFixtureMaxOutputBytes - capture.buf.Len()
	if remaining > 0 {
		if len(p) <= remaining {
			_, _ = capture.buf.Write(p)
		} else {
			_, _ = capture.buf.Write(p[:remaining])
			capture.truncated = true
		}
	} else if len(p) > 0 {
		capture.truncated = true
	}
	return len(p), nil
}

func (capture *dockerFixtureOutputCapture) Bytes() []byte {
	return capture.buf.Bytes()
}

func (runner DockerFixtureRunner) dockerArgs(env FakeSandboxEnvironment, binDir, outDir string, command []string) []string {
	args := []string{
		"run",
		"--pull", "never",
		"--rm",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", runner.config.PidsLimit,
		"--memory", runner.config.Memory,
		"--cpus", runner.config.CPUs,
		"--mount", dockerBindMount(env.Home, dockerContainerHome, true),
		"--mount", dockerBindMount(env.WorkDir, dockerContainerWork, false),
		"--mount", dockerBindMount(binDir, dockerContainerBin, true),
		"--mount", dockerBindMount(outDir, dockerContainerOut, false),
		"--workdir", dockerContainerWork,
	}
	for _, entry := range dockerFixtureEnvEntries(env.EnvMap) {
		args = append(args, "--env", entry)
	}
	args = append(args, runner.config.Image)
	args = append(args, command...)
	return args
}

func dockerBindMount(source, target string, readonly bool) string {
	parts := []string{"type=bind", "source=" + source, "target=" + target}
	if readonly {
		parts = append(parts, "readonly")
	}
	return strings.Join(parts, ",")
}

func dockerFixtureEnvEntries(envMap map[string]string) []string {
	return envMapEntries(dockerFixtureEnvMap(envMap))
}

func dockerFixtureEnvMap(envMap map[string]string) map[string]string {
	converted := make(map[string]string, len(envMap))
	for key, value := range envMap {
		converted[key] = value
	}
	converted["HOME"] = dockerContainerHome
	converted["PWD"] = dockerContainerWork
	converted["TMPDIR"] = dockerContainerTmp
	converted["PATH"] = dockerContainerBin + ":/usr/bin:/bin"
	return converted
}

func writeDockerFixtureShims(binDir string) error {
	for _, name := range []string{"curl", "wget"} {
		path := filepath.Join(binDir, name)
		body := "#!/bin/sh\n" +
			"out=\"${LSEC_DOCKER_FIXTURE_OUT:-/out}\"\n" +
			"dest=\"\"\n" +
			"for arg in \"$@\"; do\n" +
			"  case \"$arg\" in\n" +
			"    http://*|https://*) dest=\"$arg\"; break ;;\n" +
			"  esac\n" +
			"done\n" +
			"[ -n \"$dest\" ] || exit 7\n" +
			"proto=${dest%%://*}\n" +
			"escaped=$(printf '%s' \"$dest\" | awk 'BEGIN { ORS = \"\" } { if (NR > 1) printf \"\\\\n\"; gsub(/\\\\/, \"\\\\\\\\\"); gsub(/\"/, \"\\\\\\\"\"); gsub(/\\t/, \"\\\\t\"); gsub(/\\r/, \"\\\\r\"); printf \"%s\", $0 }')\n" +
			"printf '{\"type\":\"network\",\"protocol\":\"%s\",\"destination\":\"%s\",\"contains_canary\":false}\\n' \"$proto\" \"$escaped\" >> \"$out/network.ndjson\"\n" +
			"exit 7\n"
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
			return err
		}
	}
	return nil
}

func parseDockerFixtureOutput(chunks ...[]byte) (SandboxEvidence, []Finding) {
	var evidence SandboxEvidence
	for _, chunk := range chunks {
		for len(chunk) > 0 {
			index := bytes.IndexByte(chunk, '\n')
			if index < 0 {
				parseDockerFixtureLine(chunk, &evidence)
				break
			}
			parseDockerFixtureLine(chunk[:index], &evidence)
			chunk = chunk[index+1:]
		}
	}
	return evidence, dockerFixtureFindings(evidence)
}

func readDockerFixtureOutputFiles(outDir string) ([][]byte, []Finding, error) {
	var paths []string
	err := filepath.WalkDir(outDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if strings.HasSuffix(entry.Name(), ".ndjson") || strings.HasSuffix(entry.Name(), ".jsonl") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(paths)
	chunks := make([][]byte, 0, len(paths))
	var findings []Finding
	remaining := dockerFixtureMaxOutputBytes
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if remaining <= 0 {
			findings = append(findings, dockerFixtureTruncationFinding(filepath.Base(path)))
			continue
		}
		data, truncated, err := readDockerFixtureOutputFile(path, remaining)
		if err != nil {
			return nil, nil, err
		}
		remaining -= len(data)
		chunks = append(chunks, data)
		if truncated {
			findings = append(findings, dockerFixtureTruncationFinding(filepath.Base(path)))
		}
	}
	return chunks, findings, nil
}

func readDockerFixtureOutputFile(path string, maxBytes int) ([]byte, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()

	if maxBytes > dockerFixtureMaxOutputBytes {
		maxBytes = dockerFixtureMaxOutputBytes
	}
	if maxBytes <= 0 {
		return nil, true, nil
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxBytes {
		return data[:maxBytes], true, nil
	}
	return data, false, nil
}

func parseDockerFixtureLine(line []byte, evidence *SandboxEvidence) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	var event struct {
		Type           string   `json:"type"`
		Protocol       string   `json:"protocol"`
		Destination    string   `json:"destination"`
		ContainsCanary bool     `json:"contains_canary"`
		Kind           string   `json:"kind"`
		Marker         string   `json:"marker"`
		Path           string   `json:"path"`
		Executable     string   `json:"executable"`
		Args           []string `json:"args"`
		Operation      string   `json:"operation"`
	}
	if err := json.Unmarshal(line, &event); err != nil {
		return
	}
	switch event.Type {
	case "network":
		evidence.NetworkEvents = append(evidence.NetworkEvents, NetworkEvent{
			Protocol:       event.Protocol,
			Destination:    event.Destination,
			ContainsCanary: event.ContainsCanary || dockerFixtureContainsCanary(event.Destination),
		})
	case "canary":
		evidence.CanaryEvents = append(evidence.CanaryEvents, CanaryEvent{
			Kind:        event.Kind,
			Marker:      event.Marker,
			Path:        event.Path,
			Destination: event.Destination,
		})
	case "process":
		evidence.ProcessEvents = append(evidence.ProcessEvents, ProcessEvent{Executable: event.Executable, Args: event.Args})
	case "file":
		evidence.FileEvents = append(evidence.FileEvents, FileEvent{Operation: event.Operation, Path: event.Path})
	}
}

func dockerFixtureContainsCanary(value string) bool {
	return strings.Contains(value, "lsec-canary")
}

func dockerFixtureFindings(evidence SandboxEvidence) []Finding {
	if len(evidence.CanaryEvents) > 0 {
		event := evidence.CanaryEvents[0]
		return []Finding{dockerFixtureCanaryFinding(event.Marker, event.Destination)}
	}
	for _, event := range evidence.NetworkEvents {
		if event.ContainsCanary {
			return []Finding{dockerFixtureCanaryFinding("", event.Destination)}
		}
	}
	return nil
}

func dockerFixtureCanaryFinding(marker, destination string) Finding {
	evidence := marker
	if destination != "" {
		if evidence != "" {
			evidence += " "
		}
		evidence += destination
	}
	return Finding{
		Code:     "sandbox_canary_exfiltration",
		Severity: "block",
		Message:  "sandbox observed canary exfiltration",
		Evidence: limitDockerFixtureEvidence(evidence),
	}
}

func dockerFixtureTruncationFinding(evidence string) Finding {
	return Finding{
		Code:     "sandbox_output_truncated",
		Severity: "prompt",
		Message:  "sandbox output exceeded capture limit",
		Evidence: evidence,
	}
}

func limitDockerFixtureEvidence(evidence string) string {
	if len(evidence) <= 240 {
		return evidence
	}
	return evidence[:240]
}
