package lsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

type EvidenceBundle struct {
	RunID          string          `json:"run_id"`
	EvidenceSHA256 string          `json:"evidence_sha256,omitempty"`
	Analysis       CommandAnalysis `json:"analysis"`
	Version        VersionInfo     `json:"version"`
	Artifacts      []Artifact      `json:"artifacts"`
	Findings       []Finding       `json:"findings"`
	Advisories     []Advisory      `json:"advisories"`
	Decision       Decision        `json:"decision"`
	Sandbox        SandboxEvidence `json:"sandbox,omitempty"`
}

type SandboxEvidence struct {
	Enabled         bool              `json:"enabled"`
	Mode            string            `json:"mode,omitempty"`
	ProcessEvents   []ProcessEvent    `json:"process_events,omitempty"`
	FileEvents      []FileEvent       `json:"file_events,omitempty"`
	NetworkEvents   []NetworkEvent    `json:"network_events,omitempty"`
	CanaryEvents    []CanaryEvent     `json:"canary_events,omitempty"`
	GeneratedFiles  []GeneratedFile   `json:"generated_files,omitempty"`
	FakeEnvironment map[string]string `json:"fake_environment,omitempty"`
}

type ProcessEvent struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args,omitempty"`
}

type FileEvent struct {
	Operation string `json:"operation"`
	Path      string `json:"path"`
}

type NetworkEvent struct {
	Protocol       string `json:"protocol"`
	Destination    string `json:"destination"`
	ContainsCanary bool   `json:"contains_canary,omitempty"`
}

type CanaryEvent struct {
	Kind        string `json:"kind"`
	Marker      string `json:"marker"`
	Path        string `json:"path,omitempty"`
	Destination string `json:"destination,omitempty"`
}

type GeneratedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
}

func (bundle EvidenceBundle) MarshalJSON() ([]byte, error) {
	type evidenceBundleJSON EvidenceBundle
	redacted := redactEvidenceBundle(bundle)
	return json.Marshal(evidenceBundleJSON(redacted))
}

func BuildEvidenceBundle(report RunReport) EvidenceBundle {
	bundle := EvidenceBundle{
		RunID: report.RunID, Analysis: report.Analysis, Version: report.Version,
		Artifacts: report.Artifacts, Findings: report.Findings, Advisories: report.Advisories,
		Decision: report.Decision, Sandbox: report.Sandbox,
	}
	bundle = redactEvidenceBundle(bundle)
	bundle.EvidenceSHA256 = evidenceBundleHash(bundle)
	return bundle
}

func (bundle EvidenceBundle) RunReport() RunReport {
	return RunReport{
		RunID: bundle.RunID, Analysis: bundle.Analysis, Version: bundle.Version,
		Artifacts: bundle.Artifacts, Findings: bundle.Findings, Advisories: bundle.Advisories,
		Decision: bundle.Decision, Sandbox: bundle.Sandbox,
	}
}

func sanitizeRunReportForPersistence(report RunReport) RunReport {
	bundle := redactEvidenceBundle(EvidenceBundle{
		RunID: report.RunID, Analysis: report.Analysis, Version: report.Version,
		Artifacts: report.Artifacts, Findings: report.Findings, Advisories: report.Advisories,
		Decision: report.Decision, Sandbox: report.Sandbox,
	})
	report.Analysis = bundle.Analysis
	report.Artifacts = bundle.Artifacts
	report.Findings = bundle.Findings
	report.Advisories = bundle.Advisories
	report.Decision = bundle.Decision
	report.Sandbox = bundle.Sandbox
	return report
}

func sanitizeEvidenceBundleForPersistence(bundle EvidenceBundle) EvidenceBundle {
	return redactEvidenceBundle(bundle)
}

func redactEvidenceBundle(bundle EvidenceBundle) EvidenceBundle {
	bundle.Analysis = redactEvidenceAnalysis(bundle.Analysis)
	bundle.Artifacts = redactEvidenceArtifacts(bundle.Artifacts)
	bundle.Findings = redactEvidenceFindings(bundle.Findings)
	bundle.Advisories = redactEvidenceAdvisories(bundle.Advisories)
	bundle.Decision = redactEvidenceDecision(bundle.Decision)
	bundle.Sandbox = redactSandboxEvidence(bundle.Sandbox)
	return bundle
}

func redactEvidenceAnalysis(analysis CommandAnalysis) CommandAnalysis {
	analysis.Raw = redactProcessArgs(analysis.Raw)
	analysis.RequirementFiles = redactEvidencePathList(analysis.RequirementFiles)
	analysis.LockfilePath = redactEvidencePath(analysis.LockfilePath)
	if len(analysis.PackageSpecs) > 0 {
		analysis.PackageSpecs = append([]PackageSpec(nil), analysis.PackageSpecs...)
		for i := range analysis.PackageSpecs {
			analysis.PackageSpecs[i].Raw = redactPackageSpecValue(analysis.PackageSpecs[i].Raw)
			analysis.PackageSpecs[i].Name = redactPackageSpecValue(analysis.PackageSpecs[i].Name)
			analysis.PackageSpecs[i].Version = redactPackageSpecValue(analysis.PackageSpecs[i].Version)
		}
	}
	if len(analysis.RiskFlags) > 0 {
		analysis.RiskFlags = append([]RiskFlag(nil), analysis.RiskFlags...)
		for i := range analysis.RiskFlags {
			analysis.RiskFlags[i].Message = redactEvidenceText(analysis.RiskFlags[i].Message)
			analysis.RiskFlags[i].Evidence = redactEvidenceText(analysis.RiskFlags[i].Evidence)
		}
	}
	return analysis
}

func redactPackageSpecValue(value string) string {
	if isLocalPackageSpecValue(value) {
		return "[redacted-local-package-spec]"
	}
	return redactEvidenceValue(value)
}

func isLocalPackageSpecValue(value string) bool {
	if value == "" {
		return false
	}
	return isLocalPathSpec(value) || filepath.IsAbs(value) || windowsUserPathPattern.MatchString(value) || isLocalArchivePackageSpecPath(value)
}

func isLocalArchivePackageSpecPath(value string) bool {
	lower := strings.ToLower(value)
	if !strings.ContainsAny(lower, `/\`) || strings.HasPrefix(value, "@") || strings.Contains(lower, "://") || isExplicitRemotePackageSpecPath(lower) {
		return false
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.Scheme != "" && len(parsed.Scheme) > 1 {
		return false
	}
	return isBareArchiveFileSpec(pathBase(lower))
}

func isExplicitRemotePackageSpecPath(lower string) bool {
	for _, prefix := range []string{"git+", "git://", "ssh://", "git@", "github:", "gitlab:", "bitbucket:", "gist:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, marker := range []string{"github.com/", "gitlab.com/", "bitbucket.org/"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func redactEvidenceArtifacts(artifacts []Artifact) []Artifact {
	if len(artifacts) == 0 {
		return artifacts
	}
	redacted := append([]Artifact(nil), artifacts...)
	for i := range redacted {
		redacted[i].Path = redactEvidencePath(redacted[i].Path)
		redacted[i].Dependencies = redactArtifactDependencies(redacted[i].Dependencies)
	}
	return redacted
}

func redactArtifactDependencies(dependencies []DependencyRef) []DependencyRef {
	if len(dependencies) == 0 {
		return dependencies
	}
	redacted := append([]DependencyRef(nil), dependencies...)
	for i := range redacted {
		redacted[i].Raw = redactEvidenceValue(redacted[i].Raw)
	}
	return redacted
}

func redactEvidenceFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}
	redacted := append([]Finding(nil), findings...)
	for i := range redacted {
		redacted[i].File = redactEvidencePath(redacted[i].File)
		redacted[i].Message = redactEvidenceText(redacted[i].Message)
		redacted[i].Evidence = redactEvidenceText(redacted[i].Evidence)
	}
	return redacted
}

func redactEvidenceAdvisories(advisories []Advisory) []Advisory {
	if len(advisories) == 0 {
		return advisories
	}
	redacted := append([]Advisory(nil), advisories...)
	for i := range redacted {
		redacted[i].Source = redactEvidenceValue(redacted[i].Source)
		redacted[i].ID = redactEvidenceValue(redacted[i].ID)
		redacted[i].Ecosystem = redactEvidenceValue(redacted[i].Ecosystem)
		redacted[i].Name = redactEvidenceValue(redacted[i].Name)
		redacted[i].Version = redactEvidenceValue(redacted[i].Version)
		redacted[i].Severity = redactEvidenceValue(redacted[i].Severity)
		redacted[i].Type = redactEvidenceValue(redacted[i].Type)
		redacted[i].Summary = redactEvidenceText(redacted[i].Summary)
		redacted[i].URL = redactEvidenceText(redacted[i].URL)
	}
	return redacted
}

func redactEvidenceDecision(decision Decision) Decision {
	decision.Reasons = redactEvidencePathList(decision.Reasons)
	return decision
}

func redactSandboxEvidence(sandbox SandboxEvidence) SandboxEvidence {
	sandbox.ProcessEvents = redactProcessEvents(sandbox.ProcessEvents)
	sandbox.FileEvents = redactFileEvents(sandbox.FileEvents)
	sandbox.NetworkEvents = redactNetworkEvents(sandbox.NetworkEvents)
	sandbox.CanaryEvents = redactCanaryEvents(sandbox.CanaryEvents)
	sandbox.GeneratedFiles = redactGeneratedFiles(sandbox.GeneratedFiles)
	sandbox.FakeEnvironment = redactFakeEnvironment(sandbox.FakeEnvironment)
	return sandbox
}

func redactProcessEvents(events []ProcessEvent) []ProcessEvent {
	if len(events) == 0 {
		return events
	}
	redacted := append([]ProcessEvent(nil), events...)
	for i := range redacted {
		redacted[i].Executable = redactEvidenceValue(redacted[i].Executable)
		redacted[i].Args = redactProcessArgs(redacted[i].Args)
	}
	return redacted
}

func redactProcessArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	redacted := redactEvidencePathList(args)
	for i := 0; i < len(args)-1; i++ {
		if splitSecretArgPattern.MatchString(args[i]) {
			redacted[i+1] = "[redacted-secret]"
			i++
		}
	}
	return redacted
}

func redactFileEvents(events []FileEvent) []FileEvent {
	if len(events) == 0 {
		return events
	}
	redacted := append([]FileEvent(nil), events...)
	for i := range redacted {
		redacted[i].Path = redactEvidencePath(redacted[i].Path)
	}
	return redacted
}

func redactNetworkEvents(events []NetworkEvent) []NetworkEvent {
	if len(events) == 0 {
		return events
	}
	redacted := append([]NetworkEvent(nil), events...)
	for i := range redacted {
		redacted[i].Destination = redactEvidenceText(redacted[i].Destination)
	}
	return redacted
}

func redactCanaryEvents(events []CanaryEvent) []CanaryEvent {
	if len(events) == 0 {
		return events
	}
	redacted := append([]CanaryEvent(nil), events...)
	for i := range redacted {
		redacted[i].Marker = redactEvidenceSecrets(redacted[i].Marker)
		redacted[i].Path = redactEvidencePath(redacted[i].Path)
		redacted[i].Destination = redactEvidenceText(redacted[i].Destination)
	}
	return redacted
}

func redactGeneratedFiles(files []GeneratedFile) []GeneratedFile {
	if len(files) == 0 {
		return files
	}
	redacted := append([]GeneratedFile(nil), files...)
	for i := range redacted {
		redacted[i].Path = redactEvidencePath(redacted[i].Path)
	}
	return redacted
}

func redactFakeEnvironment(env map[string]string) map[string]string {
	if len(env) == 0 {
		return env
	}
	redacted := make(map[string]string, len(env))
	for key, value := range env {
		redacted[key] = redactEvidenceValue(value)
	}
	return redacted
}

func redactEvidencePathList(values []string) []string {
	if len(values) == 0 {
		return values
	}
	redacted := append([]string(nil), values...)
	for i := range redacted {
		redacted[i] = redactEvidenceValue(redacted[i])
	}
	return redacted
}

func redactEvidenceValue(value string) string {
	if filepath.IsAbs(value) {
		return redactEvidencePath(value)
	}
	return redactEvidenceText(value)
}

func redactEvidencePath(value string) string {
	if _, path, ok := splitLocalPathURI(value); ok {
		return redactEvidenceText(pathBase(path))
	}
	if filepath.IsAbs(value) || windowsUserPathPattern.MatchString(value) {
		return redactEvidenceText(pathBase(value))
	}
	return value
}

var (
	genericUnixPathPattern  = regexp.MustCompile(`(^|[^A-Za-z0-9_:/.-])(/(?:[^\s"'<>/:]+/)+[^\s"'<>]+)`)
	localPathURIPattern     = regexp.MustCompile(`(?i)\b((?:file|path):(?:/{0,2}))(/(?:[^\s"'<>/?#]+/)+[^\s"'<>?#]+)`)
	urlPattern              = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>]+`)
	windowsUserPathPattern  = regexp.MustCompile(`(?i)[A-Z]:[\\/]+Users[\\/]+[^\s"'<>]+`)
	splitSecretArgPattern   = regexp.MustCompile(`(?i)^-{1,2}(?:[a-z0-9_-]*(?:token|secret|password|passwd)|api[-_]?key|auth[-_]?token)$`)
	tokenLikePattern        = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{16,})\b`)
	canarySecretPattern     = regexp.MustCompile(`\blsec-canary-[A-Za-z0-9-]+\b`)
	keyedSecretPattern      = regexp.MustCompile(`(?i)\b((?:[A-Z0-9_]*TOKEN|API[_-]?KEY|SECRET|PASSWORD|PASSWD|AUTH[_-]?TOKEN)\s*[=:]\s*)[^\s"'<>]+`)
	pathSeparatorCharacters = regexp.MustCompile(`[\\/]`)
)

func redactEvidenceText(value string) string {
	value = redactLocalPathURIs(value)
	value = redactEvidenceURLs(value)
	value = windowsUserPathPattern.ReplaceAllStringFunc(value, func(match string) string {
		return pathBase(match)
	})
	value = redactUnixPathsOutsideURLs(value)
	return redactEvidenceSecrets(value)
}

func redactLocalPathURIs(value string) string {
	return localPathURIPattern.ReplaceAllStringFunc(value, func(match string) string {
		prefix, path, ok := splitLocalPathURI(match)
		if !ok {
			return match
		}
		return prefix + pathBase(path)
	})
}

func redactEvidenceURLs(value string) string {
	return urlPattern.ReplaceAllStringFunc(value, func(match string) string {
		parsed, err := url.Parse(match)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return "[redacted-url]"
		}
		return parsed.Scheme + "://" + parsed.Host
	})
}

func splitLocalPathURI(value string) (string, string, bool) {
	parts := localPathURIPattern.FindStringSubmatch(value)
	if len(parts) != 3 || parts[0] != value {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func redactUnixPathsOutsideURLs(value string) string {
	matches := urlPattern.FindAllStringIndex(value, -1)
	if len(matches) == 0 {
		return redactUnixPathsInSegment(value)
	}
	var builder strings.Builder
	last := 0
	for _, match := range matches {
		builder.WriteString(redactUnixPathsInSegment(value[last:match[0]]))
		builder.WriteString(value[match[0]:match[1]])
		last = match[1]
	}
	builder.WriteString(redactUnixPathsInSegment(value[last:]))
	return builder.String()
}

func redactUnixPathsInSegment(value string) string {
	return genericUnixPathPattern.ReplaceAllStringFunc(value, func(match string) string {
		parts := genericUnixPathPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		return parts[1] + pathBase(parts[2])
	})
}

func redactEvidenceSecrets(value string) string {
	value = tokenLikePattern.ReplaceAllString(value, "[redacted-secret]")
	value = canarySecretPattern.ReplaceAllString(value, "[redacted-secret]")
	return keyedSecretPattern.ReplaceAllString(value, "${1}[redacted-secret]")
}

func pathBase(value string) string {
	parts := pathSeparatorCharacters.Split(value, -1)
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			return parts[i]
		}
	}
	return filepath.Base(filepath.Clean(value))
}

func evidenceBundleHash(bundle EvidenceBundle) string {
	bundle.EvidenceSHA256 = ""
	body, err := json.Marshal(bundle)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
