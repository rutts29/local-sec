package lsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	MacOSDetonationJobSchema           = "lsec.macos_detonation.job"
	MacOSDetonationResultSchema        = "lsec.macos_detonation.result"
	MacOSDetonationSchemaVersion       = 1
	MacOSDetonationMaxTimeoutSeconds   = 900
	MacOSDetonationMaxEventsPerSummary = 256
	MacOSDetonationMaxStringLength     = 64
	MacOSDetonationMaxJSONBytes        = 16 * 1024

	MacOSDetonationStateComplete = "complete"
	MacOSDetonationStateFailed   = "failed"
	MacOSDetonationStateTimedOut = "timed_out"

	MacOSDetonationFixtureNPMBenignLifecycleV1 = "npm-benign-lifecycle-v1"

	MacOSDetonationBehaviorSpawnedFixtureHelper MacOSDetonationBehavior             = "spawned_fixture_helper"
	MacOSDetonationFileAreaSyntheticHome        MacOSDetonationFileArea             = "synthetic_home"
	MacOSDetonationFileOperationCreated         MacOSDetonationFileOperation        = "created"
	MacOSDetonationNetworkProtocolTCP           MacOSDetonationNetworkProtocol      = "tcp"
	MacOSDetonationNetworkOutcomeSinkholed      MacOSDetonationNetworkOutcome       = "sinkholed"
	MacOSDetonationPersistenceLaunchAgent       MacOSDetonationPersistenceMechanism = "launch_agent"
	MacOSDetonationPersistenceOutcomeObserved   MacOSDetonationPersistenceOutcome   = "observed"
	MacOSDetonationCanaryOutcomeRead            MacOSDetonationCanaryOutcome        = "read"
	MacOSDetonationFindingSeverityPrompt        MacOSDetonationFindingSeverity      = "prompt"
	MacOSDetonationFindingFixtureCanaryRead                                         = "fixture_canary_read"
)

type MacOSDetonationBehavior string
type MacOSDetonationFileArea string
type MacOSDetonationFileOperation string
type MacOSDetonationNetworkProtocol string
type MacOSDetonationNetworkOutcome string
type MacOSDetonationPersistenceMechanism string
type MacOSDetonationPersistenceOutcome string
type MacOSDetonationCanaryOutcome string
type MacOSDetonationFindingSeverity string

type MacOSDetonationPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

type MacOSDetonationSafetyPolicy struct {
	DisposableVM            bool `json:"disposable_vm"`
	NoHostMounts            bool `json:"no_host_mounts"`
	NoSharedFolders         bool `json:"no_shared_folders"`
	NoClipboard             bool `json:"no_clipboard"`
	NoRealCredentials       bool `json:"no_real_credentials"`
	NoRealHome              bool `json:"no_real_home"`
	NoShellHistory          bool `json:"no_shell_history"`
	NoAgentData             bool `json:"no_agent_data"`
	SyntheticHomeGenerated  bool `json:"synthetic_home_generated"`
	CanariesGeneratedInVM   bool `json:"canaries_generated_in_vm"`
	BoundedOutputs          bool `json:"bounded_outputs"`
	DestroyOrRevertAfterRun bool `json:"destroy_or_revert_after_run"`
}

type MacOSDetonationJob struct {
	Schema         string                       `json:"schema"`
	Version        int                          `json:"version"`
	RunID          string                       `json:"run_id"`
	FixtureID      string                       `json:"fixture_id"`
	EvidenceSHA256 string                       `json:"evidence_sha256"`
	Package        MacOSDetonationPackage       `json:"package"`
	ArtifactSHA256 string                       `json:"artifact_sha256"`
	ExpectedVM     MacOSDetonationVMRequirement `json:"expected_vm"`
	FixtureOnly    bool                         `json:"fixture_only"`
	CreatedAt      time.Time                    `json:"created_at"`
	TimeoutSeconds int                          `json:"timeout_seconds"`
	SafetyPolicy   MacOSDetonationSafetyPolicy  `json:"safety_policy"`
}

type MacOSDetonationVMRequirement struct {
	Provider string `json:"provider"`
	ImageID  string `json:"image_id"`
}

type MacOSDetonationVMIdentity struct {
	Provider   string `json:"provider"`
	ImageID    string `json:"image_id"`
	InstanceID string `json:"instance_id"`
}

type MacOSDetonationProcessSummary struct {
	Image    string                  `json:"image"`
	Behavior MacOSDetonationBehavior `json:"behavior"`
}

type MacOSDetonationFileSummary struct {
	Area      MacOSDetonationFileArea      `json:"area"`
	Name      string                       `json:"name"`
	Operation MacOSDetonationFileOperation `json:"operation"`
}

type MacOSDetonationNetworkSummary struct {
	Protocol MacOSDetonationNetworkProtocol `json:"protocol"`
	Host     string                         `json:"host"`
	Port     int                            `json:"port"`
	Outcome  MacOSDetonationNetworkOutcome  `json:"outcome"`
}

type MacOSDetonationPersistenceSummary struct {
	Mechanism MacOSDetonationPersistenceMechanism `json:"mechanism"`
	Target    string                              `json:"target"`
	Outcome   MacOSDetonationPersistenceOutcome   `json:"outcome"`
}

type MacOSDetonationCanarySummary struct {
	Name    string                       `json:"name"`
	Outcome MacOSDetonationCanaryOutcome `json:"outcome"`
}

type MacOSDetonationFinding struct {
	Code     string                         `json:"code"`
	Severity MacOSDetonationFindingSeverity `json:"severity"`
	Summary  string                         `json:"summary"`
}

type MacOSDetonationResult struct {
	Schema              string                              `json:"schema"`
	Version             int                                 `json:"version"`
	RunID               string                              `json:"run_id"`
	FixtureID           string                              `json:"fixture_id"`
	EvidenceSHA256      string                              `json:"evidence_sha256"`
	ArtifactSHA256      string                              `json:"artifact_sha256"`
	VM                  MacOSDetonationVMIdentity           `json:"vm"`
	FixtureOnly         bool                                `json:"fixture_only"`
	StartedAt           time.Time                           `json:"started_at"`
	FinishedAt          time.Time                           `json:"finished_at"`
	State               string                              `json:"state"`
	Processes           []MacOSDetonationProcessSummary     `json:"processes"`
	Files               []MacOSDetonationFileSummary        `json:"files"`
	Network             []MacOSDetonationNetworkSummary     `json:"network"`
	Persistence         []MacOSDetonationPersistenceSummary `json:"persistence"`
	Canaries            []MacOSDetonationCanarySummary      `json:"canaries"`
	Findings            []MacOSDetonationFinding            `json:"findings"`
	DestroyedOrReverted bool                                `json:"destroyed_or_reverted"`
}

var macOSDetonationIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

type macOSDetonationFixture struct {
	Package        MacOSDetonationPackage
	ArtifactSHA256 string
	ExpectedVM     MacOSDetonationVMRequirement
}

var macOSDetonationFixtures = map[string]macOSDetonationFixture{
	MacOSDetonationFixtureNPMBenignLifecycleV1: {
		Package: MacOSDetonationPackage{
			Ecosystem: "npm",
			Name:      "@fixture/example",
			Version:   "1.2.3",
		},
		ArtifactSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpectedVM: MacOSDetonationVMRequirement{
			Provider: "fixture-provider",
			ImageID:  "macos-15-fixture-v1",
		},
	},
}

func ParseMacOSDetonationJobJSON(body []byte) (MacOSDetonationJob, error) {
	var job MacOSDetonationJob
	if err := decodeMacOSDetonationJSON(body, &job); err != nil {
		return MacOSDetonationJob{}, err
	}
	if err := ValidateMacOSDetonationJob(job); err != nil {
		return MacOSDetonationJob{}, err
	}
	return job, nil
}

func ParseMacOSDetonationResultJSON(body []byte, job MacOSDetonationJob) (MacOSDetonationResult, error) {
	var result MacOSDetonationResult
	if err := decodeMacOSDetonationJSON(body, &result); err != nil {
		return MacOSDetonationResult{}, err
	}
	if err := ValidateMacOSDetonationResult(result, job); err != nil {
		return MacOSDetonationResult{}, err
	}
	return result, nil
}

func ValidateMacOSDetonationJob(job MacOSDetonationJob) error {
	if job.Schema != MacOSDetonationJobSchema {
		return fmt.Errorf("invalid macOS detonation job schema %q", job.Schema)
	}
	if job.Version != MacOSDetonationSchemaVersion {
		return fmt.Errorf("invalid macOS detonation job version %d", job.Version)
	}
	if err := validateMacOSDetonationIdentifier("run_id", job.RunID); err != nil {
		return err
	}
	fixture, ok := macOSDetonationFixtures[job.FixtureID]
	if !ok {
		return fmt.Errorf("unknown macOS detonation fixture_id %q", job.FixtureID)
	}
	if !isMacOSDetonationSHA256(job.EvidenceSHA256) {
		return fmt.Errorf("invalid evidence_sha256")
	}
	if !isMacOSDetonationSHA256(job.ArtifactSHA256) {
		return fmt.Errorf("invalid artifact_sha256")
	}
	if err := validateMacOSDetonationPackage(job.Package); err != nil {
		return err
	}
	if err := validateMacOSDetonationIdentifier("expected_vm.provider", job.ExpectedVM.Provider); err != nil {
		return err
	}
	if err := validateMacOSDetonationIdentifier("expected_vm.image_id", job.ExpectedVM.ImageID); err != nil {
		return err
	}
	if job.Package != fixture.Package || job.ArtifactSHA256 != fixture.ArtifactSHA256 || job.ExpectedVM != fixture.ExpectedVM {
		return fmt.Errorf("macOS detonation fixture identity does not match catalog")
	}
	if !job.FixtureOnly {
		return fmt.Errorf("macOS detonation job must be fixture-only")
	}
	if job.CreatedAt.IsZero() {
		return fmt.Errorf("created_at is required")
	}
	if job.TimeoutSeconds <= 0 || job.TimeoutSeconds > MacOSDetonationMaxTimeoutSeconds {
		return fmt.Errorf("timeout_seconds must be between 1 and %d", MacOSDetonationMaxTimeoutSeconds)
	}
	if !validMacOSDetonationSafetyPolicy(job.SafetyPolicy) {
		return fmt.Errorf("every macOS detonation safety invariant is required")
	}
	return nil
}

func ValidateMacOSDetonationResult(result MacOSDetonationResult, job MacOSDetonationJob) error {
	if err := ValidateMacOSDetonationJob(job); err != nil {
		return fmt.Errorf("invalid macOS detonation job: %w", err)
	}
	if result.Schema != MacOSDetonationResultSchema {
		return fmt.Errorf("invalid macOS detonation result schema %q", result.Schema)
	}
	if result.Version != MacOSDetonationSchemaVersion {
		return fmt.Errorf("invalid macOS detonation result version %d", result.Version)
	}
	if result.RunID != job.RunID || result.FixtureID != job.FixtureID || result.EvidenceSHA256 != job.EvidenceSHA256 || result.ArtifactSHA256 != job.ArtifactSHA256 {
		return fmt.Errorf("macOS detonation result identity does not match job")
	}
	if result.VM.Provider != job.ExpectedVM.Provider || result.VM.ImageID != job.ExpectedVM.ImageID {
		return fmt.Errorf("macOS detonation result VM does not match job")
	}
	for name, value := range map[string]string{
		"vm.provider":    result.VM.Provider,
		"vm.image_id":    result.VM.ImageID,
		"vm.instance_id": result.VM.InstanceID,
	} {
		if err := validateMacOSDetonationIdentifier(name, value); err != nil {
			return err
		}
	}
	if !result.FixtureOnly {
		return fmt.Errorf("macOS detonation result must be fixture-only")
	}
	if result.StartedAt.IsZero() || result.FinishedAt.IsZero() {
		return fmt.Errorf("terminal timestamps are required")
	}
	if result.StartedAt.Before(job.CreatedAt) {
		return fmt.Errorf("started_at precedes job creation")
	}
	if result.FinishedAt.Before(result.StartedAt) {
		return fmt.Errorf("finished_at precedes started_at")
	}
	if result.FinishedAt.Sub(result.StartedAt) > time.Duration(job.TimeoutSeconds)*time.Second {
		return fmt.Errorf("result exceeds job timeout")
	}
	switch result.State {
	case MacOSDetonationStateComplete, MacOSDetonationStateFailed, MacOSDetonationStateTimedOut:
	default:
		return fmt.Errorf("invalid terminal state %q", result.State)
	}
	if !result.DestroyedOrReverted {
		return fmt.Errorf("VM must be destroyed or reverted")
	}
	return validateMacOSDetonationEvidence(result)
}

func validMacOSDetonationSafetyPolicy(policy MacOSDetonationSafetyPolicy) bool {
	return policy.DisposableVM && policy.NoHostMounts && policy.NoSharedFolders && policy.NoClipboard &&
		policy.NoRealCredentials && policy.NoRealHome && policy.NoShellHistory && policy.NoAgentData &&
		policy.SyntheticHomeGenerated && policy.CanariesGeneratedInVM && policy.BoundedOutputs &&
		policy.DestroyOrRevertAfterRun
}

func isMacOSDetonationSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		return !('0' <= r && r <= '9') && !('a' <= r && r <= 'f')
	}) == -1
}

func validateMacOSDetonationPackage(pkg MacOSDetonationPackage) error {
	if err := validateMacOSDetonationIdentifier("package ecosystem", pkg.Ecosystem); err != nil {
		return err
	}
	name := strings.TrimSpace(pkg.Name)
	if name == "" || len(name) > MacOSDetonationMaxStringLength || strings.Contains(name, "://") ||
		strings.HasPrefix(name, "/") || strings.HasPrefix(name, "~") || strings.Contains(name, "\\") ||
		strings.Contains(name, "../") || strings.ContainsAny(name, "\r\n\t ") {
		return fmt.Errorf("invalid package name")
	}
	version := strings.TrimSpace(pkg.Version)
	lower := strings.ToLower(version)
	if version == "" || len(version) > MacOSDetonationMaxStringLength || strings.ContainsAny(version, "^~*<>=|, \t\r\n/\\") ||
		lower == "latest" || lower == "next" || lower == "dev" || lower == "nightly" ||
		!strings.ContainsAny(version, "0123456789") {
		return fmt.Errorf("package version must be exactly pinned")
	}
	return nil
}

func validateMacOSDetonationIdentifier(name, value string) error {
	if !validMacOSDetonationToken(value) {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}

func validateMacOSDetonationEvidence(result MacOSDetonationResult) error {
	counts := map[string]int{
		"processes": len(result.Processes), "files": len(result.Files), "network": len(result.Network),
		"persistence": len(result.Persistence), "canaries": len(result.Canaries), "findings": len(result.Findings),
	}
	for name, count := range counts {
		if count > MacOSDetonationMaxEventsPerSummary {
			return fmt.Errorf("%s exceeds evidence limit", name)
		}
	}
	for _, item := range result.Processes {
		if !validMacOSDetonationToken(item.Image) || item.Behavior != MacOSDetonationBehaviorSpawnedFixtureHelper {
			return fmt.Errorf("invalid process summary")
		}
	}
	for _, item := range result.Files {
		if item.Area != MacOSDetonationFileAreaSyntheticHome || !validMacOSDetonationToken(item.Name) || item.Operation != MacOSDetonationFileOperationCreated {
			return fmt.Errorf("invalid file summary")
		}
	}
	for _, item := range result.Network {
		if item.Protocol != MacOSDetonationNetworkProtocolTCP || !validMacOSDetonationHost(item.Host) || item.Outcome != MacOSDetonationNetworkOutcomeSinkholed {
			return fmt.Errorf("invalid network summary")
		}
		if item.Port < 1 || item.Port > 65535 {
			return fmt.Errorf("invalid network port %d", item.Port)
		}
	}
	for _, item := range result.Persistence {
		if item.Mechanism != MacOSDetonationPersistenceLaunchAgent || !validMacOSDetonationToken(item.Target) || item.Outcome != MacOSDetonationPersistenceOutcomeObserved {
			return fmt.Errorf("invalid persistence summary")
		}
	}
	for _, item := range result.Canaries {
		if !validMacOSDetonationToken(item.Name) || item.Outcome != MacOSDetonationCanaryOutcomeRead {
			return fmt.Errorf("invalid canary summary")
		}
	}
	for _, item := range result.Findings {
		if item.Code != MacOSDetonationFindingFixtureCanaryRead || item.Severity != MacOSDetonationFindingSeverityPrompt || item.Summary != MacOSDetonationFindingFixtureCanaryRead {
			return fmt.Errorf("invalid finding")
		}
	}
	return nil
}

func validMacOSDetonationToken(value string) bool {
	return macOSDetonationIdentifierPattern.MatchString(value) && !strings.Contains(value, "..") && !looksLikeMacOSDetonationEncodedBytes(value)
}

func validMacOSDetonationHost(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.ToLower(value) != value || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return !looksLikeMacOSDetonationEncodedBytes(strings.ReplaceAll(value, ".", ""))
}

func looksLikeMacOSDetonationEncodedBytes(value string) bool {
	if len(value) < 48 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func decodeMacOSDetonationJSON(body []byte, target any) error {
	if len(body) > MacOSDetonationMaxJSONBytes {
		return fmt.Errorf("macOS detonation JSON is too large: %d bytes exceeds %d", len(body), MacOSDetonationMaxJSONBytes)
	}
	if err := rejectMacOSDetonationDuplicateFields(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("macOS detonation JSON has trailing content")
	}
	return nil
}

func rejectMacOSDetonationDuplicateFields(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := inspectMacOSDetonationJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("macOS detonation JSON has trailing content")
		}
		return err
	}
	return nil
}

func inspectMacOSDetonationJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := inspectMacOSDetonationJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := inspectMacOSDetonationJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}
