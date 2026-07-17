package lsec

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

const (
	externalProviderTimeout     = 15 * time.Second
	externalProviderOutputLimit = 8 * 1024
)

const providerOutputTruncatedMarker = "[provider output truncated]"

var errNoProviderInputs = errors.New("no provider inputs")

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
	out, stderr, copies, runErr := runOSVScanner(ctx, path, &inputs)
	if errors.Is(runErr, errNoProviderInputs) {
		return nil, nil, inputs.snapshot("osv-scanner", "not_applicable", 0, 0, "")
	}
	findings, parseErr := parseOSVScannerFindings(runID, out, providerSourcePathMap(copies))
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
		out, stderr, runErr := runPipAudit(ctx, path, requirementsFile, &inputs)
		if errors.Is(runErr, errNoProviderInputs) {
			continue
		}
		queriedCount++
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
		out, stderr, runErr := runGrype(ctx, path, sbomFile, &inputs)
		if errors.Is(runErr, errNoProviderInputs) {
			continue
		}
		queriedCount++
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
