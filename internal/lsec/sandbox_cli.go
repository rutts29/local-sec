package lsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const sandboxCLIModeDockerFixture = "docker-fixture"

type sandboxCLIRequest struct {
	run sandboxRunRequest
}

type sandboxRunRequest struct {
	options sandboxRunOptions
	command []string
}

func validateSandboxCLI(args []string) (sandboxCLIRequest, error) {
	if len(args) == 0 {
		return sandboxCLIRequest{}, errors.New("sandbox requires run")
	}
	switch args[0] {
	case "run":
		run, err := validateSandboxRunCLI(args[1:])
		if err != nil {
			return sandboxCLIRequest{}, err
		}
		return sandboxCLIRequest{run: run}, nil
	default:
		return sandboxCLIRequest{}, fmt.Errorf("unknown sandbox command %q", args[0])
	}
}

func runSandboxCLI(request sandboxCLIRequest, stdout io.Writer, store Store) error {
	return runSandboxRunCLI(request.run, stdout, store)
}

func validateSandboxRunCLI(args []string) (sandboxRunRequest, error) {
	separator := sandboxCommandSeparator(args)
	if separator < 0 {
		return sandboxRunRequest{}, errors.New("sandbox run requires -- before the fixture command")
	}
	command := args[separator+1:]
	if len(command) == 0 {
		return sandboxRunRequest{}, errors.New("sandbox run requires a fixture command after --")
	}
	options, err := parseSandboxRunOptions(args[:separator])
	if err != nil {
		return sandboxRunRequest{}, err
	}
	if options.mode == "" {
		return sandboxRunRequest{}, errors.New("sandbox run requires --mode docker-fixture")
	}
	if options.mode != sandboxCLIModeDockerFixture {
		return sandboxRunRequest{}, fmt.Errorf("unsupported sandbox mode %q; only docker-fixture is supported", options.mode)
	}
	return sandboxRunRequest{options: options, command: append([]string(nil), command...)}, nil
}

func runSandboxRunCLI(request sandboxRunRequest, stdout io.Writer, store Store) error {
	runner := NewDockerFixtureRunner(DockerFixtureConfig{DockerPath: request.options.dockerPath})
	result, runErr := runner.RunSandbox(context.Background(), SandboxRequest{
		Mode:    SandboxModeDockerFixture,
		Command: append([]string(nil), request.command...),
	})
	if hasSandboxResult(result) {
		redacted := redactSandboxResult(result)
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(redacted); err != nil {
			return err
		}
		if err := appendSandboxRunEvent(store, request.command, result); err != nil {
			return err
		}
		if sandboxResultHasBlock(redacted) {
			if runErr != nil {
				return runErr
			}
			return errors.New("blocked by sandbox finding")
		}
	}
	return runErr
}

func appendSandboxRunEvent(store Store, command []string, result SandboxResult) error {
	now := time.Now().UTC()
	report := RunReport{
		RunID:     NewRunID(now),
		CreatedAt: now,
		Analysis:  CommandAnalysis{Raw: append([]string(nil), command...)},
	}
	report = ApplySandboxResult(report, result)
	return store.AppendEvent("sandbox_run", BuildEvidenceBundle(report))
}

type sandboxRunOptions struct {
	mode       string
	dockerPath string
}

func parseSandboxRunOptions(args []string) (sandboxRunOptions, error) {
	var options sandboxRunOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--mode":
			i++
			if i >= len(args) {
				return sandboxRunOptions{}, errors.New("sandbox run --mode requires a value")
			}
			options.mode = args[i]
		case "--docker":
			i++
			if i >= len(args) {
				return sandboxRunOptions{}, errors.New("sandbox run --docker requires a path")
			}
			options.dockerPath = args[i]
		default:
			return sandboxRunOptions{}, fmt.Errorf("unknown sandbox run option %q", args[i])
		}
	}
	return options, nil
}

func sandboxCommandSeparator(args []string) int {
	for i, arg := range args {
		if arg == "--" {
			return i
		}
	}
	return -1
}

func redactSandboxResult(result SandboxResult) SandboxResult {
	result.Findings = redactEvidenceFindings(result.Findings)
	result.Evidence = redactSandboxEvidence(result.Evidence)
	return result
}

func hasSandboxResult(result SandboxResult) bool {
	return result.Mode != "" || len(result.Findings) > 0 || result.Evidence.Enabled
}

func sandboxResultHasBlock(result SandboxResult) bool {
	for _, finding := range result.Findings {
		if finding.Severity == "block" {
			return true
		}
	}
	return false
}
