package lsec

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Optional Phase 7 evidence providers. Missing tools report not_available; present tools
// enrich scan findings only (never replace core policy). Outside testing installs the CLIs.

func runSyftProvider(ctx context.Context, runID string, roots []string) ([]ScanFinding, []ScanDiagnostic, ScanProviderSnapshot) {
	inputs := collectSyftScanRoots(roots)
	if len(inputs.accepted) == 0 {
		return nil, nil, inputs.snapshot("syft", "not_applicable", 0, 0, "")
	}
	path, err := exec.LookPath("syft")
	if err != nil {
		return nil, nil, inputs.snapshot("syft", "not_available", 0, 0, "")
	}
	var findings []ScanFinding
	queried := 0
	for _, root := range append([]string(nil), inputs.accepted...) {
		if !inputs.revalidatePath(root) {
			continue
		}
		out, stderr, runErr := runScanProviderCommand(ctx, path, root, "-o", "cyclonedx-json")
		queried++
		if runErr != nil {
			message := providerFailureMessage("syft", runErr, out, stderr, nil)
			return findings, []ScanDiagnostic{scanDiagnostic(runID, "provider_failed", "syft", message)}, inputs.snapshot("syft", "error", queried, 1, providerSnapshotError(runErr, nil))
		}
		// Prefer inventory-style findings for packages with no version metadata rather than failing closed.
		parsed, parseErr := parseSyftCycloneDXFindings(runID, root, out)
		if parseErr != nil {
			message := providerFailureMessage("syft", nil, out, stderr, parseErr)
			return findings, []ScanDiagnostic{scanDiagnostic(runID, "provider_failed", "syft", message)}, inputs.snapshot("syft", "error", queried, 1, providerSnapshotError(nil, parseErr))
		}
		findings = append(findings, parsed...)
	}
	return findings, nil, inputs.snapshot("syft", "ok", queried, 0, "")
}

func collectSyftScanRoots(roots []string) providerInputSelection {
	var selection providerInputSelection
	seen := map[string]bool{}
	for _, root := range roots {
		root = filepath.Clean(root)
		selection.candidateCount++
		if seen[root] {
			selection.skip("duplicate")
			continue
		}
		seen[root] = true
		info, err := os.Lstat(root)
		if err != nil {
			selection.skip("inaccessible")
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			selection.skip("non_directory")
			continue
		}
		// Only accept roots that already look like software projects we inventory.
		if !syftRootLooksScannable(root) {
			selection.skip("no_manifest")
			continue
		}
		selection.accepted = append(selection.accepted, root)
	}
	return selection
}

func syftRootLooksScannable(root string) bool {
	for _, name := range []string{"package.json", "package-lock.json", "go.mod", "Cargo.toml", "Cargo.lock", "requirements.txt", "pyproject.toml"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			return true
		}
	}
	return false
}

func parseSyftCycloneDXFindings(runID, root string, body []byte) ([]ScanFinding, error) {
	// Reuse CycloneDX component parsing; emit low-severity informational findings for inventory enrichment.
	observations, diagnostics := scanCycloneDXSBOMBytes(runID, root, body)
	if len(diagnostics) > 0 {
		// Keep provider soft-fail: return no findings rather than hard error for partial docs.
		for _, d := range diagnostics {
			if d.Code == "parse_error" {
				return nil, errSyftParse
			}
		}
	}
	findings := make([]ScanFinding, 0, len(observations))
	for _, obs := range observations {
		findings = append(findings, ScanFinding{
			Type: "finding", RunID: runID, FindingID: "syft:" + obs.Ecosystem + ":" + obs.Name + ":" + obs.Version,
			Provider: "syft", ProviderRecordID: obs.PURL, Class: "inventory", Severity: "info", Urgency: "low",
			Confidence: obs.Confidence, Presence: obs.Presence, Ecosystem: obs.Ecosystem, Name: obs.Name,
			Version: obs.Version, Title: "syft inventory observation", SourcePath: root,
		})
	}
	return findings, nil
}

var errSyftParse = errProviderParse("syft")

func errProviderParse(provider string) error {
	return &providerParseError{provider: provider}
}

type providerParseError struct{ provider string }

func (e *providerParseError) Error() string { return e.provider + " output parse failed" }

func runCargoVetProvider(ctx context.Context, runID string, roots []string) ([]ScanFinding, []ScanDiagnostic, ScanProviderSnapshot) {
	inputs := collectCargoVetRoots(roots)
	if len(inputs.accepted) == 0 {
		return nil, nil, inputs.snapshot("cargo-vet", "not_applicable", 0, 0, "")
	}
	path, err := exec.LookPath("cargo")
	if err != nil {
		return nil, nil, inputs.snapshot("cargo-vet", "not_available", 0, 0, "")
	}
	// cargo vet is a cargo subcommand; absence of plugin still yields provider error, not crash.
	var findings []ScanFinding
	queried := 0
	for _, root := range append([]string(nil), inputs.accepted...) {
		if !inputs.revalidatePath(root) {
			continue
		}
		out, stderr, runErr := runScanProviderCommand(ctx, path, "vet", "--manifest-path", filepath.Join(root, "Cargo.toml"), "--output-format=json")
		queried++
		if runErr != nil {
			// Many machines have cargo without vet; treat as not_available rather than scan failure.
			if strings.Contains(strings.ToLower(string(stderr)+runErr.Error()), "no such subcommand") ||
				strings.Contains(strings.ToLower(string(stderr)), "unrecognized subcommand") {
				return nil, nil, inputs.snapshot("cargo-vet", "not_available", 0, 0, "")
			}
			message := providerFailureMessage("cargo-vet", runErr, out, stderr, nil)
			return findings, []ScanDiagnostic{scanDiagnostic(runID, "provider_failed", "cargo-vet", message)}, inputs.snapshot("cargo-vet", "error", queried, 1, providerSnapshotError(runErr, nil))
		}
		parsed, parseErr := parseCargoVetFindings(runID, root, out)
		if parseErr != nil {
			message := providerFailureMessage("cargo-vet", nil, out, stderr, parseErr)
			return findings, []ScanDiagnostic{scanDiagnostic(runID, "provider_failed", "cargo-vet", message)}, inputs.snapshot("cargo-vet", "error", queried, 1, providerSnapshotError(nil, parseErr))
		}
		findings = append(findings, parsed...)
	}
	return findings, nil, inputs.snapshot("cargo-vet", "ok", queried, 0, "")
}

func collectCargoVetRoots(roots []string) providerInputSelection {
	var selection providerInputSelection
	seen := map[string]bool{}
	for _, root := range roots {
		root = filepath.Clean(root)
		manifest := filepath.Join(root, "Cargo.toml")
		selection.candidateCount++
		if seen[manifest] {
			selection.skip("duplicate")
			continue
		}
		seen[manifest] = true
		if reason := providerInputRejection(manifest); reason != "" {
			// also accept if only lock exists
			lock := filepath.Join(root, "Cargo.lock")
			if reason2 := providerInputRejection(lock); reason2 != "" {
				selection.skip(reason)
				continue
			}
		}
		info, err := os.Lstat(root)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			selection.skip("non_directory")
			continue
		}
		selection.accepted = append(selection.accepted, root)
	}
	return selection
}

func parseCargoVetFindings(runID, root string, body []byte) ([]ScanFinding, error) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, nil
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	// cargo-vet JSON shapes vary; emit a single informational finding that audit ran cleanly when JSON parses.
	return []ScanFinding{{
		Type: "finding", RunID: runID, FindingID: "cargo-vet:" + root, Provider: "cargo-vet",
		ProviderRecordID: root, Class: "audit", Severity: "info", Urgency: "low", Confidence: "medium",
		Presence: "declared", Title: "cargo vet audit completed", SourcePath: root,
	}}, nil
}

func runBumblebeeProvider(ctx context.Context, runID string, roots []string) ([]ScanFinding, []ScanDiagnostic, ScanProviderSnapshot) {
	path, err := exec.LookPath("bumblebee")
	if err != nil {
		return nil, nil, providerInputSelection{}.snapshot("bumblebee", "not_available", 0, 0, "")
	}
	if len(roots) == 0 {
		return nil, nil, providerInputSelection{}.snapshot("bumblebee", "not_applicable", 0, 0, "")
	}
	// Bumblebee CLI contracts vary by install; run a version probe only and report detection.
	// Full endpoint correlation remains operator-configured outside local-sec.
	out, stderr, runErr := runScanProviderCommand(ctx, path, "--version")
	if runErr != nil {
		message := providerFailureMessage("bumblebee", runErr, out, stderr, nil)
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "provider_failed", "bumblebee", message)}, providerInputSelection{candidateCount: 1}.snapshot("bumblebee", "error", 1, 1, providerSnapshotError(runErr, nil))
	}
	return []ScanFinding{{
		Type: "finding", RunID: runID, FindingID: "bumblebee:detected", Provider: "bumblebee",
		Class: "endpoint", Severity: "info", Urgency: "low", Confidence: "low", Presence: "configured",
		Title: "bumblebee CLI detected; endpoint correlation available for outside integration",
	}}, nil, providerInputSelection{candidateCount: 1, accepted: []string{path}}.snapshot("bumblebee", "ok", 1, 0, "")
}

// scanCycloneDXSBOMBytes reuses SBOM parsing for provider output without requiring a file on disk.
func scanCycloneDXSBOMBytes(runID, sourcePath string, body []byte) ([]ScanObservation, []ScanDiagnostic) {
	var envelope struct {
		BomFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", sourcePath, err.Error())}
	}
	if envelope.BomFormat != "CycloneDX" {
		return nil, nil
	}
	var doc cyclonedxSBOM
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", sourcePath, err.Error())}
	}
	var observations []ScanObservation
	for _, component := range doc.Components {
		ecosystem, name, version, ok := cyclonedxComponentIdentity(component)
		if !ok {
			continue
		}
		observations = append(observations, componentObservation(runID, ecosystem, name, version, "configured", "cyclonedx_sbom", sourcePath, "medium", false))
	}
	return observations, nil
}
