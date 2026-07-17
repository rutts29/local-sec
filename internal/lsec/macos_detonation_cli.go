package lsec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Phase 8 coding surface: prepare fixture jobs, validate results, and optionally
// invoke an external disposable VM runner. Real VM hardware/cloud is outside testing.

func runMacOSDetonationCLI(args []string, stdout io.Writer, store Store) error {
	if len(args) == 0 {
		return errors.New("macos-detonation requires a subcommand")
	}
	switch args[0] {
	case "prepare-fixture":
		if len(args) < 2 {
			return errors.New("macos-detonation prepare-fixture requires run_id")
		}
		out, err := parseRemoteSandboxPathFlag(args[2:], "--out")
		if err != nil {
			return err
		}
		job, err := PrepareMacOSDetonationFixtureJob(store, args[1], time.Now().UTC())
		if err != nil {
			return err
		}
		return writeRemoteSandboxJSON(stdout, out, job)
	case "validate-result":
		jobPath, err := parseNamedPathFlag(args[1:], "--job")
		if err != nil {
			return err
		}
		resultPath, err := parseNamedPathFlag(args[1:], "--result")
		if err != nil {
			return err
		}
		if jobPath == "" || resultPath == "" {
			return errors.New("macos-detonation validate-result requires --job PATH --result PATH")
		}
		jobBody, err := os.ReadFile(filepath.Clean(jobPath))
		if err != nil {
			return err
		}
		resultBody, err := os.ReadFile(filepath.Clean(resultPath))
		if err != nil {
			return err
		}
		job, err := ParseMacOSDetonationJobJSON(jobBody)
		if err != nil {
			return err
		}
		result, err := ParseMacOSDetonationResultJSON(resultBody, job)
		if err != nil {
			return err
		}
		return writeRemoteSandboxJSON(stdout, "", result)
	case "run-local-fixture":
		if len(args) < 2 {
			return errors.New("macos-detonation run-local-fixture requires run_id")
		}
		out, err := parseRemoteSandboxPathFlag(args[2:], "--result")
		if err != nil {
			return err
		}
		result, err := RunLocalMacOSDetonationFixture(store, args[1], time.Now().UTC())
		if err != nil {
			return err
		}
		if err := writeRemoteSandboxJSON(stdout, out, result); err != nil {
			return err
		}
		return store.AppendEvent("macos_detonation", map[string]any{
			"run_id":          result.RunID,
			"fixture_id":      result.FixtureID,
			"evidence_sha256": result.EvidenceSHA256,
			"status":          result.State,
			"finding_count":   len(result.Findings),
			"redacted":        true,
		})
	case "run-external":
		// Outside testing: LSEC_MACOS_DETONATION_RUNNER points at a disposable VM driver.
		if len(args) < 2 {
			return errors.New("macos-detonation run-external requires run_id")
		}
		runner := strings.TrimSpace(os.Getenv("LSEC_MACOS_DETONATION_RUNNER"))
		if runner == "" {
			return errors.New("LSEC_MACOS_DETONATION_RUNNER is required for run-external")
		}
		job, err := PrepareMacOSDetonationFixtureJob(store, args[1], time.Now().UTC())
		if err != nil {
			return err
		}
		jobPath := filepath.Join(os.TempDir(), "lsec-macos-job-"+job.RunID+".json")
		resultPath := filepath.Join(os.TempDir(), "lsec-macos-result-"+job.RunID+".json")
		jobBody, err := json.Marshal(job)
		if err != nil {
			return err
		}
		if err := os.WriteFile(jobPath, jobBody, 0o600); err != nil {
			return err
		}
		defer os.Remove(jobPath)
		cmd := exec.Command(runner, "--job", jobPath, "--result", resultPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("external macOS detonation runner failed: %w", err)
		}
		resultBody, err := os.ReadFile(resultPath)
		if err != nil {
			return err
		}
		defer os.Remove(resultPath)
		result, err := ParseMacOSDetonationResultJSON(resultBody, job)
		if err != nil {
			return err
		}
		return writeRemoteSandboxJSON(stdout, "", result)
	default:
		return fmt.Errorf("unknown macos-detonation subcommand %q", args[0])
	}
}

func parseNamedPathFlag(args []string, flag string) (string, error) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			path := strings.TrimSpace(args[i+1])
			if path == "" {
				return "", fmt.Errorf("%s requires a path", flag)
			}
			if err := validateRemoteSandboxOutputPath(flag, path); err != nil {
				// For --job/--result reads, only enforce path safety for writes; allow reads of existing files.
				if flag == "--job" || flag == "--result" {
					return path, nil
				}
				return "", err
			}
			return path, nil
		}
	}
	return "", nil
}

func PrepareMacOSDetonationFixtureJob(store Store, runID string, now time.Time) (MacOSDetonationJob, error) {
	report, ok, err := store.LoadRunReport(runID)
	if err != nil {
		return MacOSDetonationJob{}, err
	}
	if !ok {
		return MacOSDetonationJob{}, fmt.Errorf("run %s not found", runID)
	}
	evidence := BuildEvidenceBundle(report)
	fixture := macOSDetonationFixtures[MacOSDetonationFixtureNPMBenignLifecycleV1]
	artifactSHA := fixture.ArtifactSHA256
	if len(report.Artifacts) > 0 && report.Artifacts[0].SHA256 != "" {
		// Keep fixture catalog identity for safety; do not rebind to arbitrary host artifacts.
		artifactSHA = fixture.ArtifactSHA256
	}
	return MacOSDetonationJob{
		Schema:         MacOSDetonationJobSchema,
		Version:        MacOSDetonationSchemaVersion,
		RunID:          runID,
		FixtureID:      MacOSDetonationFixtureNPMBenignLifecycleV1,
		EvidenceSHA256: evidence.EvidenceSHA256,
		Package:        fixture.Package,
		ArtifactSHA256: artifactSHA,
		ExpectedVM:     fixture.ExpectedVM,
		FixtureOnly:    true,
		CreatedAt:      now.UTC(),
		TimeoutSeconds: 60,
		SafetyPolicy: MacOSDetonationSafetyPolicy{
			DisposableVM: true, NoHostMounts: true, NoSharedFolders: true, NoClipboard: true,
			NoRealCredentials: true, NoRealHome: true, NoShellHistory: true, NoAgentData: true,
			SyntheticHomeGenerated: true, CanariesGeneratedInVM: true, BoundedOutputs: true,
			DestroyOrRevertAfterRun: true,
		},
	}, nil
}

func RunLocalMacOSDetonationFixture(store Store, runID string, now time.Time) (MacOSDetonationResult, error) {
	job, err := PrepareMacOSDetonationFixtureJob(store, runID, now)
	if err != nil {
		return MacOSDetonationResult{}, err
	}
	if err := ValidateMacOSDetonationJob(job); err != nil {
		return MacOSDetonationResult{}, err
	}
	fixture := macOSDetonationFixtures[job.FixtureID]
	started := now.UTC()
	finished := started.Add(30 * time.Second)
	result := MacOSDetonationResult{
		Schema:         MacOSDetonationResultSchema,
		Version:        MacOSDetonationSchemaVersion,
		RunID:          job.RunID,
		FixtureID:      job.FixtureID,
		EvidenceSHA256: job.EvidenceSHA256,
		ArtifactSHA256: job.ArtifactSHA256,
		State:          MacOSDetonationStateComplete,
		FixtureOnly:    true,
		StartedAt:      started,
		FinishedAt:     finished,
		VM: MacOSDetonationVMIdentity{
			Provider:   job.ExpectedVM.Provider,
			ImageID:    job.ExpectedVM.ImageID,
			InstanceID: fixture.Result.VMInstanceIDPrefix + "001",
		},
		DestroyedOrReverted: true,
	}
	for _, image := range fixture.Result.ProcessImages {
		result.Processes = append(result.Processes, MacOSDetonationProcessSummary{Image: image, Behavior: MacOSDetonationBehaviorSpawnedFixtureHelper})
	}
	for _, name := range fixture.Result.FileNames {
		result.Files = append(result.Files, MacOSDetonationFileSummary{Area: MacOSDetonationFileAreaSyntheticHome, Name: name, Operation: MacOSDetonationFileOperationCreated})
	}
	for _, host := range fixture.Result.NetworkHosts {
		result.Network = append(result.Network, MacOSDetonationNetworkSummary{Protocol: MacOSDetonationNetworkProtocolTCP, Host: host, Port: 443, Outcome: MacOSDetonationNetworkOutcomeSinkholed})
	}
	for _, target := range fixture.Result.PersistenceTargets {
		result.Persistence = append(result.Persistence, MacOSDetonationPersistenceSummary{Mechanism: MacOSDetonationPersistenceLaunchAgent, Target: target, Outcome: MacOSDetonationPersistenceOutcomeObserved})
	}
	for _, name := range fixture.Result.CanaryNames {
		result.Canaries = append(result.Canaries, MacOSDetonationCanarySummary{Name: name, Outcome: MacOSDetonationCanaryOutcomeRead})
	}
	result.Findings = []MacOSDetonationFinding{{
		Code:     MacOSDetonationFindingFixtureCanaryRead,
		Severity: MacOSDetonationFindingSeverityPrompt,
		Summary:  MacOSDetonationFindingFixtureCanaryRead,
	}}
	if err := ValidateMacOSDetonationResult(result, job); err != nil {
		return MacOSDetonationResult{}, err
	}
	return result, nil
}
