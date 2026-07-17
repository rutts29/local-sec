package lsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	remoteSandboxPrepareSchema = "local-sec.remote_sandbox.prepare"
	remoteSandboxResultSchema  = "local-sec.remote_sandbox.result"

	RemoteSandboxStatusComplete = "complete"
)

type RemoteSandboxPrepareRequest struct {
	Schema         string         `json:"schema"`
	Version        int            `json:"version"`
	RunID          string         `json:"run_id"`
	EvidenceSHA256 string         `json:"evidence_sha256"`
	Evidence       EvidenceBundle `json:"evidence"`
	CreatedAt      time.Time      `json:"created_at"`
	Redacted       bool           `json:"redacted"`
}

type RemoteSandboxResult struct {
	Schema          string          `json:"schema"`
	Version         int             `json:"version"`
	RunID           string          `json:"run_id"`
	EvidenceSHA256  string          `json:"evidence_sha256"`
	Status          string          `json:"status"`
	Findings        []Finding       `json:"findings,omitempty"`
	SandboxEvidence SandboxEvidence `json:"sandbox_evidence,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

type remoteSandboxEvent struct {
	Schema         string    `json:"schema"`
	Version        int       `json:"version"`
	RunID          string    `json:"run_id"`
	EvidenceSHA256 string    `json:"evidence_sha256"`
	Status         string    `json:"status"`
	FindingCount   int       `json:"finding_count"`
	CreatedAt      time.Time `json:"created_at"`
	Redacted       bool      `json:"redacted"`
}

func appendRemoteSandboxResultEvent(store Store, result RemoteSandboxResult) error {
	event := remoteSandboxEvent{
		Schema:         remoteSandboxResultSchema,
		Version:        result.Version,
		RunID:          result.RunID,
		EvidenceSHA256: result.EvidenceSHA256,
		Status:         result.Status,
		FindingCount:   len(result.Findings),
		CreatedAt:      result.CreatedAt,
		Redacted:       true,
	}
	return store.AppendEvent("remote_sandbox", event)
}

func PrepareRemoteSandboxRequest(store Store, runID string, now time.Time) (RemoteSandboxPrepareRequest, error) {
	report, ok, err := store.LoadRunReport(runID)
	if err != nil {
		return RemoteSandboxPrepareRequest{}, err
	}
	if !ok {
		return RemoteSandboxPrepareRequest{}, fmt.Errorf("run %s not found", runID)
	}
	evidence := BuildRemoteSandboxEvidenceBundle(report)
	return RemoteSandboxPrepareRequest{
		Schema:         remoteSandboxPrepareSchema,
		Version:        1,
		RunID:          runID,
		EvidenceSHA256: evidence.EvidenceSHA256,
		Evidence:       evidence,
		CreatedAt:      now.UTC(),
		Redacted:       true,
	}, nil
}

func SubmitFakeRemoteSandbox(store Store, runID string, now time.Time) (RemoteSandboxResult, error) {
	request, err := PrepareRemoteSandboxRequest(store, runID, now)
	if err != nil {
		return RemoteSandboxResult{}, err
	}
	return RemoteSandboxResult{
		Schema:         remoteSandboxResultSchema,
		Version:        1,
		RunID:          request.RunID,
		EvidenceSHA256: request.EvidenceSHA256,
		Status:         RemoteSandboxStatusComplete,
		Findings:       nil,
		CreatedAt:      now.UTC(),
	}, nil
}

// SubmitRemoteSandboxResult ingests an external worker result with fail-closed policy:
// run_id and evidence_sha256 must match the prepared local evidence; findings may only escalate.
func SubmitRemoteSandboxResult(store Store, runID, resultPath string, now time.Time) (RemoteSandboxResult, error) {
	request, err := PrepareRemoteSandboxRequest(store, runID, now)
	if err != nil {
		return RemoteSandboxResult{}, err
	}
	body, err := os.ReadFile(filepath.Clean(resultPath))
	if err != nil {
		return RemoteSandboxResult{}, err
	}
	var result RemoteSandboxResult
	if err := json.Unmarshal(body, &result); err != nil {
		return RemoteSandboxResult{}, fmt.Errorf("invalid remote sandbox result: %w", err)
	}
	if err := validateRemoteSandboxResult(request, result); err != nil {
		return RemoteSandboxResult{}, err
	}
	result.Findings = sanitizeRemoteSandboxFindings(result.Findings)
	result.SandboxEvidence = redactSandboxEvidence(result.SandboxEvidence)
	if result.CreatedAt.IsZero() {
		result.CreatedAt = now.UTC()
	}
	if result.Status == "" {
		result.Status = RemoteSandboxStatusComplete
	}
	return result, nil
}

func validateRemoteSandboxResult(request RemoteSandboxPrepareRequest, result RemoteSandboxResult) error {
	if result.Schema != "" && result.Schema != remoteSandboxResultSchema {
		return fmt.Errorf("remote sandbox result schema %q is not supported", result.Schema)
	}
	if result.RunID == "" {
		return errors.New("remote sandbox result missing run_id")
	}
	if result.RunID != request.RunID {
		return fmt.Errorf("remote sandbox result run_id %q does not match %q", result.RunID, request.RunID)
	}
	if result.EvidenceSHA256 == "" {
		return errors.New("remote sandbox result missing evidence_sha256")
	}
	if !strings.EqualFold(result.EvidenceSHA256, request.EvidenceSHA256) {
		return errors.New("remote sandbox result evidence_sha256 does not match prepared evidence")
	}
	for _, finding := range result.Findings {
		if _, err := normalizeRemoteSandboxSeverity(finding.Severity); err != nil {
			return err
		}
	}
	return nil
}

func normalizeRemoteSandboxSeverity(severity string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "block", "critical", "high", "error", "malware":
		return "block", nil
	case "prompt", "medium", "low", "warning", "info":
		return "prompt", nil
	case "allow":
		return "", errors.New("remote sandbox findings may only escalate risk, not allow")
	case "":
		return "", errors.New("remote sandbox finding missing severity")
	default:
		return "", fmt.Errorf("remote sandbox finding severity %q is not supported", severity)
	}
}

func sanitizeRemoteSandboxFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		severity, err := normalizeRemoteSandboxSeverity(finding.Severity)
		if err != nil {
			// Validation should have rejected this; fail closed to block.
			severity = "block"
		}
		finding.Severity = severity
		finding.Message = redactEvidenceText(finding.Message)
		finding.Evidence = redactEvidenceText(finding.Evidence)
		finding.File = redactEvidencePath(finding.File)
		if finding.Code == "" {
			finding.Code = "remote_sandbox_finding"
		}
		out = append(out, finding)
	}
	return out
}

// ApplyRemoteSandboxResult merges remote findings into a report and re-evaluates policy.
// Deterministic blocks already present cannot be cleared by remote results.
func ApplyRemoteSandboxResult(report RunReport, result RemoteSandboxResult) RunReport {
	before := report.Decision.Verdict
	report.Findings = append(report.Findings, result.Findings...)
	if result.SandboxEvidence.Enabled || result.SandboxEvidence.Mode != "" {
		report.Sandbox = result.SandboxEvidence
		report.Sandbox.Enabled = true
	}
	report.Decision = DefaultPolicy().Evaluate(report.Analysis, report.Version, report.Findings, report.Advisories)
	if before == VerdictBlock {
		report.Decision.Verdict = VerdictBlock
		report.Decision.Lane = LaneBlock
		report.Decision.Reasons = uniqueStrings(append(report.Decision.Reasons, "deterministic local block retained after remote sandbox review"))
	}
	return report
}

func BuildRemoteSandboxEvidenceBundle(report RunReport) EvidenceBundle {
	bundle := BuildEvidenceBundle(report)
	bundle = redactRemoteSandboxTranscriptText(bundle)
	bundle.EvidenceSHA256 = remoteSandboxEvidenceHash(bundle)
	return bundle
}

func redactRemoteSandboxTranscriptText(bundle EvidenceBundle) EvidenceBundle {
	bundle.Analysis.RiskFlags = redactRemoteSandboxRiskFlags(bundle.Analysis.RiskFlags)
	bundle.Findings = redactRemoteSandboxFindings(bundle.Findings)
	bundle.Advisories = redactRemoteSandboxAdvisories(bundle.Advisories)
	bundle.Decision.Reasons = redactRemoteSandboxStrings(bundle.Decision.Reasons)
	return bundle
}

func redactRemoteSandboxRiskFlags(flags []RiskFlag) []RiskFlag {
	if len(flags) == 0 {
		return flags
	}
	redacted := append([]RiskFlag(nil), flags...)
	for i := range redacted {
		redacted[i].Message = redactRemoteSandboxTranscriptField(redacted[i].Message)
		redacted[i].Evidence = redactRemoteSandboxTranscriptField(redacted[i].Evidence)
	}
	return redacted
}

func redactRemoteSandboxFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}
	redacted := append([]Finding(nil), findings...)
	for i := range redacted {
		redacted[i].Message = redactRemoteSandboxTranscriptField(redacted[i].Message)
		redacted[i].Evidence = redactRemoteSandboxTranscriptField(redacted[i].Evidence)
	}
	return redacted
}

func redactRemoteSandboxAdvisories(advisories []Advisory) []Advisory {
	if len(advisories) == 0 {
		return advisories
	}
	redacted := append([]Advisory(nil), advisories...)
	for i := range redacted {
		redacted[i].Summary = redactRemoteSandboxTranscriptField(redacted[i].Summary)
	}
	return redacted
}

func redactRemoteSandboxStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	redacted := append([]string(nil), values...)
	for i := range redacted {
		redacted[i] = redactRemoteSandboxTranscriptField(redacted[i])
	}
	return redacted
}

func redactRemoteSandboxTranscriptField(value string) string {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "raw prompt") || strings.Contains(lower, "raw response") || strings.Contains(lower, "transcript") {
		return "[redacted-transcript]"
	}
	return value
}

func parseRemoteSandboxPathFlag(args []string, flag string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	if len(args) != 2 || args[0] != flag || strings.TrimSpace(args[1]) == "" {
		return "", fmt.Errorf("usage: %s PATH", flag)
	}
	path := args[1]
	if err := validateRemoteSandboxOutputPath(flag, path); err != nil {
		return "", err
	}
	return path, nil
}

func validateRemoteSandboxOutputPath(flag, path string) error {
	parent := filepath.Clean(filepath.Dir(path))
	if parent == "." || pathHasDotDot(parent) || pathHasDotDot(filepath.Dir(path)) {
		return fmt.Errorf("%s path must include a directory component without traversal", flag)
	}
	if remoteSandboxSharedAbsoluteParent(parent) {
		return fmt.Errorf("%s path must be inside a private directory, not directly under %s", flag, parent)
	}
	if base := filepath.Base(path); base == "." || base == ".." {
		return fmt.Errorf("%s path must name a file", flag)
	}
	return nil
}

func remoteSandboxSharedAbsoluteParent(parent string) bool {
	if !filepath.IsAbs(parent) {
		return false
	}
	switch filepath.Clean(parent) {
	case string(filepath.Separator),
		filepath.Join(string(filepath.Separator), "tmp"),
		filepath.Join(string(filepath.Separator), "var"),
		filepath.Join(string(filepath.Separator), "private"),
		filepath.Join(string(filepath.Separator), "private", "tmp"),
		filepath.Join(string(filepath.Separator), "private", "var"),
		filepath.Join(string(filepath.Separator), "Users"),
		filepath.Join(string(filepath.Separator), "home"):
		return true
	default:
		return false
	}
}

func pathHasDotDot(path string) bool {
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		if component == ".." {
			return true
		}
	}
	return false
}

func writeRemoteSandboxJSON(stdout io.Writer, out string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if out == "" {
		_, err = stdout.Write(body)
		return err
	}
	return writePrivateFileAtomic(out, body)
}

func writePrivateFileAtomic(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return os.Chmod(path, 0o600)
}

func ensurePrivateDir(dir string) error {
	if err := rejectSymlinkParentDirs(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s path parent must not be a symlink", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	info, err = os.Lstat(dir)
	if err != nil {
		return err
	}
	if got := info.Mode().Perm(); got != 0o700 {
		return fmt.Errorf("%s permissions are %o, want 0700", dir, got)
	}
	return nil
}

func rejectSymlinkParentDirs(dir string) error {
	clean := filepath.Clean(dir)
	if clean == "." {
		return nil
	}
	current := ""
	if filepath.IsAbs(clean) {
		current = string(filepath.Separator)
	}
	allowed := remoteSandboxSystemSymlinkPrefixes()
	for _, component := range strings.Split(filepath.ToSlash(clean), "/") {
		if component == "" || component == "." {
			continue
		}
		if current == "" {
			current = filepath.FromSlash(component)
		} else {
			current = filepath.Join(current, filepath.FromSlash(component))
		}
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if _, ok := allowed[current]; ok {
				continue
			}
			return fmt.Errorf("%s path parent must not be a symlink", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", current)
		}
	}
	return nil
}

func remoteSandboxSystemSymlinkPrefixes() map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, path := range []string{"/tmp", "/var"} {
		for _, prefix := range symlinkPrefixes(path) {
			allowed[prefix] = struct{}{}
		}
	}
	return allowed
}

func symlinkPrefixes(path string) []string {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return nil
	}
	current := string(filepath.Separator)
	var prefixes []string
	for _, component := range strings.Split(filepath.ToSlash(clean), "/") {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, filepath.FromSlash(component))
		info, err := os.Lstat(current)
		if err != nil {
			return prefixes
		}
		if info.Mode()&os.ModeSymlink != 0 {
			prefixes = append(prefixes, current)
		}
	}
	return prefixes
}

func remoteSandboxEvidenceHash(bundle EvidenceBundle) string {
	bundle.EvidenceSHA256 = ""
	body, err := json.Marshal(bundle)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
