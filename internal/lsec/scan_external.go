package lsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	externalProviderTimeout     = 15 * time.Second
	externalProviderOutputLimit = 8 * 1024
)

const providerOutputTruncatedMarker = "[provider output truncated]"

func runOSVScannerProvider(ctx context.Context, runID string, roots []string) ([]ScanFinding, []ScanDiagnostic, ScanProviderSnapshot) {
	inputs := collectOSVScannerLockfiles(roots)
	if len(inputs.accepted) == 0 {
		return nil, nil, inputs.snapshot("osv-scanner", "not_applicable", 0, 0, "")
	}
	path, err := exec.LookPath("osv-scanner")
	if err != nil {
		return nil, nil, inputs.snapshot("osv-scanner", "not_available", 0, 0, "")
	}
	inputs.revalidate()
	if len(inputs.accepted) == 0 {
		return nil, nil, inputs.snapshot("osv-scanner", "not_applicable", 0, 0, "")
	}
	out, stderr, runErr := runOSVScanner(ctx, path, inputs.accepted)
	findings, parseErr := parseOSVScannerFindings(runID, out)
	if parseErr == nil {
		if runErr == nil || (isOSVScannerVulnerabilityExit(runErr) && len(findings) > 0) {
			return findings, nil, inputs.snapshot("osv-scanner", "ok", len(inputs.accepted), 0, "")
		}
		message := providerFailureMessage("osv-scanner", runErr, out, stderr, nil)
		snapshot := inputs.snapshot("osv-scanner", "error", len(inputs.accepted), len(inputs.accepted), providerSnapshotError(runErr, nil))
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "provider_failed", "osv-scanner", message)}, snapshot
	}
	message := providerFailureMessage("osv-scanner", runErr, out, stderr, parseErr)
	snapshot := inputs.snapshot("osv-scanner", "error", len(inputs.accepted), len(inputs.accepted), providerSnapshotError(runErr, parseErr))
	return nil, []ScanDiagnostic{scanDiagnostic(runID, "provider_failed", "osv-scanner", message)}, snapshot
}

func isOSVScannerVulnerabilityExit(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}

func runPipAuditProvider(ctx context.Context, runID string, roots []string) ([]ScanFinding, []ScanDiagnostic, ScanProviderSnapshot) {
	inputs := collectPipAuditRequirementsFiles(roots)
	if len(inputs.accepted) == 0 {
		return nil, nil, inputs.snapshot("pip-audit", "not_applicable", 0, 0, "")
	}
	path, err := exec.LookPath("pip-audit")
	if err != nil {
		return nil, nil, inputs.snapshot("pip-audit", "not_available", 0, 0, "")
	}
	var findings []ScanFinding
	queriedCount := 0
	for _, requirementsFile := range append([]string(nil), inputs.accepted...) {
		if !inputs.revalidatePath(requirementsFile) {
			continue
		}
		queriedCount++
		out, stderr, runErr := runPipAudit(ctx, path, requirementsFile)
		fileFindings, parseErr := parsePipAuditFindings(runID, requirementsFile, out)
		if parseErr == nil {
			if runErr != nil && len(fileFindings) == 0 {
				message := providerFailureMessage("pip-audit", runErr, out, stderr, nil)
				snapshot := inputs.snapshot("pip-audit", "error", queriedCount, 1, providerSnapshotError(runErr, nil))
				return findings, []ScanDiagnostic{scanDiagnostic(runID, "provider_failed", "pip-audit", message)}, snapshot
			}
			findings = append(findings, fileFindings...)
			continue
		}
		message := providerFailureMessage("pip-audit", runErr, out, stderr, parseErr)
		snapshot := inputs.snapshot("pip-audit", "error", queriedCount, 1, providerSnapshotError(runErr, parseErr))
		return findings, []ScanDiagnostic{scanDiagnostic(runID, "provider_failed", "pip-audit", message)}, snapshot
	}
	if queriedCount == 0 {
		return findings, nil, inputs.snapshot("pip-audit", "not_applicable", 0, 0, "")
	}
	return findings, nil, inputs.snapshot("pip-audit", "ok", queriedCount, 0, "")
}

func runGrypeProvider(ctx context.Context, runID string, observations []ScanObservation) ([]ScanFinding, []ScanDiagnostic, ScanProviderSnapshot) {
	inputs := grypeCycloneDXSBOMFilesFromObservations(observations)
	if len(inputs.accepted) == 0 {
		return nil, nil, inputs.snapshot("grype", "not_applicable", 0, 0, "")
	}
	path, err := exec.LookPath("grype")
	if err != nil {
		return nil, nil, inputs.snapshot("grype", "not_available", 0, 0, "")
	}
	var findings []ScanFinding
	queriedCount := 0
	for _, sbomFile := range append([]string(nil), inputs.accepted...) {
		if !inputs.revalidatePath(sbomFile) {
			continue
		}
		queriedCount++
		out, stderr, runErr := runGrype(ctx, path, sbomFile)
		fileFindings, parseErr := parseGrypeFindings(runID, sbomFile, out)
		if parseErr == nil && runErr == nil {
			findings = append(findings, fileFindings...)
			continue
		}
		message := providerFailureMessage("grype", runErr, out, stderr, parseErr)
		snapshot := inputs.snapshot("grype", "error", queriedCount, 1, providerSnapshotError(runErr, parseErr))
		return findings, []ScanDiagnostic{scanDiagnostic(runID, "provider_failed", "grype", message)}, snapshot
	}
	if queriedCount == 0 {
		return findings, nil, inputs.snapshot("grype", "not_applicable", 0, 0, "")
	}
	return findings, nil, inputs.snapshot("grype", "ok", queriedCount, 0, "")
}

type providerInputSelection struct {
	accepted       []string
	candidateCount int
	skipReasons    map[string]int
}

func (s providerInputSelection) snapshot(provider, status string, queriedCount, failedCount int, errorCategory string) ScanProviderSnapshot {
	return ScanProviderSnapshot{
		Provider: provider, Status: status, CandidateCount: s.candidateCount, AcceptedCount: len(s.accepted),
		SkippedCount: s.candidateCount - len(s.accepted), QueriedCount: queriedCount, FailedCount: failedCount,
		SkipReasons: s.skipReasons, Error: errorCategory,
	}
}

func (s *providerInputSelection) skip(reason string) {
	if s.skipReasons == nil {
		s.skipReasons = map[string]int{}
	}
	s.skipReasons[reason]++
}

func (s *providerInputSelection) revalidate() {
	for _, path := range append([]string(nil), s.accepted...) {
		s.revalidatePath(path)
	}
}

func (s *providerInputSelection) revalidatePath(path string) bool {
	reason := providerInputRejection(path)
	if reason == "" {
		return true
	}
	for i, accepted := range s.accepted {
		if accepted == path {
			s.accepted = append(s.accepted[:i], s.accepted[i+1:]...)
			break
		}
	}
	s.skip(reason)
	return false
}

func providerInputRejection(path string) string {
	info, err := os.Lstat(path)
	if err != nil {
		return "inaccessible"
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "symlink"
	}
	if !info.Mode().IsRegular() {
		return "non_regular"
	}
	return ""
}

func grypeCycloneDXSBOMFilesFromObservations(observations []ScanObservation) providerInputSelection {
	seen := map[string]bool{}
	var selection providerInputSelection
	for _, observation := range observations {
		if observation.SourceType != "cyclonedx_sbom" {
			continue
		}
		selection.candidateCount++
		if observation.SourcePath == "" {
			selection.skip("missing_path")
			continue
		}
		clean := filepath.Clean(observation.SourcePath)
		if seen[clean] {
			selection.skip("duplicate")
			continue
		}
		seen[clean] = true
		selection.accepted = append(selection.accepted, clean)
	}
	sort.Strings(selection.accepted)
	return selection
}

func collectOSVScannerLockfiles(roots []string) providerInputSelection {
	seen := map[string]bool{}
	var selection providerInputSelection
	for _, root := range roots {
		root = filepath.Clean(root)
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if isOSVScannerLockfile(path) && !seen[path] {
					seen[path] = true
					selection.candidateCount++
					selection.skip("inaccessible")
				}
				return nil
			}
			clean := filepath.Clean(path)
			if entry.Type()&os.ModeSymlink != 0 {
				if isOSVScannerLockfile(path) && !seen[clean] {
					seen[clean] = true
					selection.candidateCount++
					selection.skip("symlink")
				}
				return nil
			}
			if entry.IsDir() && entry.Name() == "node_modules" {
				return filepath.SkipDir
			}
			if entry.IsDir() {
				return nil
			}
			if !isOSVScannerLockfile(path) || seen[clean] {
				return nil
			}
			seen[clean] = true
			selection.candidateCount++
			info, err := entry.Info()
			if err != nil {
				selection.skip("inaccessible")
				return nil
			}
			if !info.Mode().IsRegular() {
				selection.skip("non_regular")
				return nil
			}
			selection.accepted = append(selection.accepted, clean)
			return nil
		})
	}
	sort.Strings(selection.accepted)
	return selection
}

func isOSVScannerLockfile(path string) bool {
	base := filepath.Base(path)
	return base == "package-lock.json" || base == "npm-shrinkwrap.json"
}

func collectPipAuditRequirementsFiles(roots []string) providerInputSelection {
	seen := map[string]bool{}
	var selection providerInputSelection
	for _, root := range roots {
		root = filepath.Clean(root)
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if filepath.Base(path) == "requirements.txt" && !seen[path] {
					seen[path] = true
					selection.candidateCount++
					selection.skip("inaccessible")
				}
				return nil
			}
			clean := filepath.Clean(path)
			if entry.Type()&os.ModeSymlink != 0 {
				if filepath.Base(path) == "requirements.txt" && !seen[clean] {
					seen[clean] = true
					selection.candidateCount++
					selection.skip("symlink")
				}
				return nil
			}
			if entry.IsDir() {
				if skipPipAuditDir(entry.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Base(path) != "requirements.txt" || seen[clean] {
				return nil
			}
			seen[clean] = true
			selection.candidateCount++
			info, err := entry.Info()
			if err != nil {
				selection.skip("inaccessible")
				return nil
			}
			if !info.Mode().IsRegular() {
				selection.skip("non_regular")
				return nil
			}
			specs, findings := ParseRequirementsFiles([]string{clean})
			if len(specs) == 0 || len(findings) > 0 {
				selection.skip("unsafe_requirements")
				return nil
			}
			selection.accepted = append(selection.accepted, clean)
			return nil
		})
	}
	sort.Strings(selection.accepted)
	return selection
}

func skipPipAuditDir(name string) bool {
	switch name {
	case "node_modules", ".venv", ".env", "venv", "env", "site-packages":
		return true
	default:
		return false
	}
}

func runOSVScanner(ctx context.Context, path string, lockfiles []string) ([]byte, []byte, error) {
	args := []string{"scan"}
	for _, lockfile := range lockfiles {
		args = append(args, "-L", lockfile)
	}
	args = append(args, "--format", "json")
	return runScanProviderCommand(ctx, path, args...)
}

func runPipAudit(ctx context.Context, path, requirementsFile string) ([]byte, []byte, error) {
	return runScanProviderCommand(ctx, path, "--format", "json", "--progress-spinner", "off", "--requirement", requirementsFile)
}

func runGrype(ctx context.Context, path, sbomFile string) ([]byte, []byte, error) {
	return runScanProviderCommand(ctx, path, "sbom:"+sbomFile, "-o", "json")
}

func runScanProviderCommand(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
	dir, err := os.MkdirTemp("", "lsec-scan-provider-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	home := filepath.Join(dir, "home")
	cacheHome := filepath.Join(dir, "cache")
	configHome := filepath.Join(dir, "config")
	for _, path := range []string{home, cacheHome, configHome} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, nil, err
		}
	}
	providerCtx, cancel := context.WithTimeout(ctx, externalProviderTimeout)
	defer cancel()
	cmd := exec.CommandContext(providerCtx, executable, args...)
	cmd.Dir = dir
	cmd.Env = scanProviderEnv(home, cacheHome, configHome)
	configureProviderProcess(cmd)
	cmd.Cancel = func() error {
		return killProviderProcessTree(cmd)
	}
	stdout := &boundedProviderOutput{limit: externalProviderOutputLimit}
	stderr := &boundedProviderOutput{limit: externalProviderOutputLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	if providerErr := providerCtx.Err(); providerErr != nil {
		if errors.Is(providerErr, context.DeadlineExceeded) {
			err = fmt.Errorf("provider timed out: %w", providerErr)
		} else {
			err = fmt.Errorf("provider canceled: %w", providerErr)
		}
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func scanProviderEnv(home, cacheHome, configHome string) []string {
	env := []string{
		"NO_COLOR=1",
		"HOME=" + home,
		"XDG_CACHE_HOME=" + cacheHome,
		"XDG_CONFIG_HOME=" + configHome,
	}
	if value, ok := os.LookupEnv("PATH"); ok {
		env = append(env, "PATH="+value)
	}
	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy"} {
		if value, ok := os.LookupEnv(key); ok {
			if safeProxyEnvValue(key, value) {
				env = append(env, key+"="+value)
			}
		}
	}
	return env
}

func safeProxyEnvValue(key, value string) bool {
	if hasControlCharacter(value) {
		return false
	}
	switch strings.ToUpper(key) {
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
		parsed, err := url.Parse(value)
		if err != nil {
			return false
		}
		if parsed.User == nil && parsed.Host == "" && strings.Contains(value, "@") {
			return false
		}
		return parsed.User == nil
	default:
		return true
	}
}

func hasControlCharacter(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

type boundedProviderOutput struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedProviderOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) <= remaining {
			_, _ = b.buf.Write(p)
			return len(p), nil
		}
		_, _ = b.buf.Write(p[:remaining])
	}
	if !b.truncated {
		if b.buf.Len() > 0 {
			_, _ = b.buf.WriteString("\n")
		}
		_, _ = b.buf.WriteString(providerOutputTruncatedMarker)
		b.truncated = true
	}
	return len(p), nil
}

func (b *boundedProviderOutput) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func providerFailureMessage(provider string, runErr error, stdout, stderr []byte, parseErr error) string {
	message := provider + " failed: " + providerSnapshotError(runErr, parseErr)
	if bytes.Contains(stdout, []byte(providerOutputTruncatedMarker)) || bytes.Contains(stderr, []byte(providerOutputTruncatedMarker)) {
		message += ": provider output truncated"
	}
	return message
}

func providerSnapshotError(runErr, parseErr error) string {
	if runErr != nil {
		message := strings.ToLower(runErr.Error())
		switch {
		case errors.Is(runErr, context.DeadlineExceeded), strings.Contains(message, "timed out"), strings.Contains(message, "deadline exceeded"):
			return "timeout"
		case errors.Is(runErr, context.Canceled), strings.Contains(message, "canceled"):
			return "canceled"
		default:
			return "execution_failed"
		}
	}
	if parseErr != nil {
		return "invalid_output"
	}
	return "provider_failed"
}

func parseOSVScannerFindings(runID string, body []byte) ([]ScanFinding, error) {
	var doc struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
					Version   string `json:"version"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID               string          `json:"id"`
					Summary          string          `json:"summary"`
					Details          string          `json:"details"`
					DatabaseSpecific json.RawMessage `json:"database_specific"`
					Aliases          []string        `json:"aliases"`
					Severity         []struct {
						Type  string `json:"type"`
						Score string `json:"score"`
					} `json:"severity"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(extractJSONPayload(body), &doc); err != nil {
		return nil, err
	}
	var findings []ScanFinding
	for _, result := range doc.Results {
		for _, pkg := range result.Packages {
			observation := componentObservation(runID, pkg.Package.Ecosystem, pkg.Package.Name, pkg.Package.Version, "declared", "npm_lockfile", result.Source.Path, "high", false)
			if observation.Ecosystem == "" || observation.Name == "" || observation.Version == "" {
				continue
			}
			for _, vuln := range pkg.Vulnerabilities {
				if vuln.ID == "" {
					continue
				}
				severity, _ := classifyOSVSignals(vuln.ID, vuln.Aliases, vuln.DatabaseSpecific, vuln.Severity)
				urgency := "review"
				if strings.EqualFold(severity, "critical") {
					urgency = "high"
				}
				findings = append(findings, ScanFinding{
					Type: "finding", RunID: runID, FindingID: findingID("osv-scanner", vuln.ID, observation),
					Provider: "osv-scanner", ProviderRecordID: vuln.ID, Class: "vulnerability", Severity: severity,
					Urgency: urgency, Confidence: "high", Presence: observation.Presence, Ecosystem: observation.Ecosystem,
					Name: observation.Name, Version: observation.Version, Title: nonEmpty(nonEmpty(vuln.Summary, vuln.Details), vuln.ID),
					SourcePath: observation.SourcePath,
				})
			}
		}
	}
	return findings, nil
}

func parseGrypeFindings(runID, sbomFile string, body []byte) ([]ScanFinding, error) {
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID          string `json:"id"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
			} `json:"vulnerability"`
			Artifact struct {
				PURL string `json:"purl"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(extractJSONPayload(body), &doc); err != nil {
		return nil, err
	}
	var findings []ScanFinding
	for _, match := range doc.Matches {
		if match.Vulnerability.ID == "" {
			continue
		}
		ecosystem, name, version, ok := grypeArtifactIdentity(match.Artifact.PURL)
		if !ok {
			continue
		}
		observation := componentObservation(runID, ecosystem, name, version, "configured", "cyclonedx_sbom", sbomFile, "high", false)
		severity := normalizeExternalSeverity(match.Vulnerability.Severity)
		if severity == "" {
			severity = "unknown"
		}
		urgency := "review"
		if strings.EqualFold(severity, "critical") {
			urgency = "high"
		}
		findings = append(findings, ScanFinding{
			Type: "finding", RunID: runID, FindingID: findingID("grype", match.Vulnerability.ID, observation),
			Provider: "grype", ProviderRecordID: match.Vulnerability.ID, Class: "vulnerability", Severity: severity,
			Urgency: urgency, Confidence: "high", Presence: observation.Presence, Ecosystem: observation.Ecosystem,
			Name: observation.Name, Version: observation.Version, Title: nonEmpty(match.Vulnerability.Description, match.Vulnerability.ID),
			SourcePath: sbomFile,
		})
	}
	return findings, nil
}

func grypeArtifactIdentity(purl string) (string, string, string, bool) {
	if purl == "" {
		return "", "", "", false
	}
	return scanIdentityFromPackageURL(purl)
}

func parsePipAuditFindings(runID, requirementsFile string, body []byte) ([]ScanFinding, error) {
	var doc struct {
		Dependencies []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Vulns   []struct {
				ID          string          `json:"id"`
				Description string          `json:"description"`
				Title       string          `json:"title"`
				Summary     string          `json:"summary"`
				Severity    string          `json:"severity"`
				Aliases     []string        `json:"aliases"`
				Raw         json.RawMessage `json:"-"`
			} `json:"vulns"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(extractJSONPayload(body), &doc); err != nil {
		return nil, err
	}
	var findings []ScanFinding
	for _, dep := range doc.Dependencies {
		observation := componentObservation(runID, "PyPI", dep.Name, dep.Version, "declared", "requirements_file", requirementsFile, "high", false)
		if observation.Name == "" || observation.Version == "" {
			continue
		}
		for _, vuln := range dep.Vulns {
			if vuln.ID == "" {
				continue
			}
			severity := normalizeExternalSeverity(vuln.Severity)
			if severity == "" {
				severity = "unknown"
			}
			findings = append(findings, ScanFinding{
				Type: "finding", RunID: runID, FindingID: findingID("pip-audit", vuln.ID, observation),
				Provider: "pip-audit", ProviderRecordID: vuln.ID, Class: "vulnerability", Severity: severity,
				Urgency: "review", Confidence: "high", Presence: observation.Presence, Ecosystem: observation.Ecosystem,
				Name: observation.Name, Version: observation.Version, Title: nonEmpty(nonEmpty(vuln.Title, vuln.Summary), nonEmpty(vuln.Description, vuln.ID)),
				SourcePath: requirementsFile,
			})
		}
	}
	return findings, nil
}
