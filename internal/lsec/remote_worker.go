package lsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// RunLocalRemoteWorker executes the remote-sandbox protocol on this host using the
// Docker fixture runner as a disposable worker. Real VPS/SSH workers use the same
// prepare/submit result schema; only the transport differs (outside testing).
func RunLocalRemoteWorker(ctx context.Context, store Store, runID string, now time.Time) (RemoteSandboxResult, error) {
	request, err := PrepareRemoteSandboxRequest(store, runID, now)
	if err != nil {
		return RemoteSandboxResult{}, err
	}
	runner := NewDockerFixtureRunner(DockerFixtureConfig{})
	sandboxResult, runErr := runner.RunSandbox(ctx, SandboxRequest{
		Mode:     SandboxModeDockerFixture,
		Command:  []string{"true"},
		Analysis: request.Evidence.Analysis,
		Version:  request.Evidence.Version,
	})
	result := RemoteSandboxResult{
		Schema:          remoteSandboxResultSchema,
		Version:         1,
		RunID:           request.RunID,
		EvidenceSHA256:  request.EvidenceSHA256,
		Status:          RemoteSandboxStatusComplete,
		Findings:        sanitizeRemoteSandboxFindings(sandboxResult.Findings),
		SandboxEvidence: redactSandboxEvidence(sandboxResult.Evidence),
		CreatedAt:       now.UTC(),
	}
	if runErr != nil {
		result.Findings = append(result.Findings, Finding{
			Code:     "remote_worker_failed",
			Severity: "prompt",
			Message:  "local remote-worker fixture failed",
			Evidence: runErr.Error(),
		})
	}
	if result.SandboxEvidence.Mode == "" {
		result.SandboxEvidence.Mode = string(SandboxModeDockerFixture)
	}
	result.SandboxEvidence.Enabled = true
	return result, nil
}

func runRemoteSandboxCLI(args []string, stdout io.Writer, store Store) error {
	if len(args) < 1 {
		return errors.New("remote-sandbox requires a subcommand")
	}
	switch args[0] {
	case "prepare":
		if len(args) < 2 {
			return errors.New("remote-sandbox prepare requires run_id")
		}
		out, err := parseRemoteSandboxPathFlag(args[2:], "--out")
		if err != nil {
			return err
		}
		request, err := PrepareRemoteSandboxRequest(store, args[1], time.Now().UTC())
		if err != nil {
			return err
		}
		return writeRemoteSandboxJSON(stdout, out, request)
	case "submit-fake":
		if len(args) < 2 {
			return errors.New("remote-sandbox submit-fake requires run_id")
		}
		resultPath, err := parseRemoteSandboxPathFlag(args[2:], "--result")
		if err != nil {
			return err
		}
		result, err := SubmitFakeRemoteSandbox(store, args[1], time.Now().UTC())
		if err != nil {
			return err
		}
		if err := writeRemoteSandboxJSON(stdout, resultPath, result); err != nil {
			return err
		}
		return appendRemoteSandboxResultEvent(store, result)
	case "submit":
		if len(args) < 2 {
			return errors.New("remote-sandbox submit requires run_id")
		}
		resultPath, err := parseRemoteSandboxPathFlag(args[2:], "--result")
		if err != nil {
			return err
		}
		if resultPath == "" {
			return errors.New("remote-sandbox submit requires --result PATH")
		}
		result, err := SubmitRemoteSandboxResult(store, args[1], resultPath, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := writeRemoteSandboxJSON(stdout, "", result); err != nil {
			return err
		}
		return appendRemoteSandboxResultEvent(store, result)
	case "run-local":
		if len(args) < 2 {
			return errors.New("remote-sandbox run-local requires run_id")
		}
		resultPath, err := parseRemoteSandboxPathFlag(args[2:], "--result")
		if err != nil {
			return err
		}
		result, err := RunLocalRemoteWorker(context.Background(), store, args[1], time.Now().UTC())
		if err != nil {
			return err
		}
		// Round-trip through submit policy so local worker results obey the same gates.
		tmp := filepath.Join(os.TempDir(), fmt.Sprintf("lsec-remote-worker-%s.json", result.RunID))
		body, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := os.WriteFile(tmp, body, 0o600); err != nil {
			return err
		}
		defer os.Remove(tmp)
		validated, err := SubmitRemoteSandboxResult(store, args[1], tmp, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := writeRemoteSandboxJSON(stdout, resultPath, validated); err != nil {
			return err
		}
		return appendRemoteSandboxResultEvent(store, validated)
	default:
		return fmt.Errorf("unknown remote-sandbox subcommand %q", args[0])
	}
}
