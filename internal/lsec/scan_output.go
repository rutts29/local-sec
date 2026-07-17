package lsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func writeScanBundle(paths Paths, runID string, observations []ScanObservation, findings []ScanFinding, diagnostics []ScanDiagnostic, summary ScanSummary, providerSnapshots []ScanProviderSnapshot, catalogSnapshots []ScanCatalogSnapshot) error {
	dir := filepath.Join(paths.Scans, runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeNDJSONFile(filepath.Join(dir, "inventory.ndjson"), observations); err != nil {
		return err
	}
	if err := writeNDJSONFile(filepath.Join(dir, "findings.ndjson"), findings); err != nil {
		return err
	}
	if err := writeNDJSONFile(filepath.Join(dir, "diagnostics.ndjson"), diagnostics); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "provider-snapshots.json"), providerSnapshots); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "catalog-snapshots.json"), catalogSnapshots); err != nil {
		return err
	}
	body, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "summary.json"), body, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "report.txt"), []byte(scanReportText(summary)), 0o600)
}

func writeJSONFile(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(body, '\n'), 0o600)
}

func writeNDJSONFile[T any](path string, records []T) error {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	return writeFileAtomic(path, buf.Bytes(), 0o600)
}

func writeScanOutput(stdout io.Writer, options scanOptions, observations []ScanObservation, findings []ScanFinding, diagnostics []ScanDiagnostic, summary ScanSummary) error {
	outputObservations := redactScanObservations(observations, options.RedactPaths)
	if options.FindingsOnly {
		outputObservations = nil
	}
	outputFindings := redactScanFindings(findings, options.RedactPaths)
	outputDiagnostics := redactScanDiagnostics(diagnostics, options.RedactPaths)
	switch options.Format {
	case "ndjson":
		encoder := json.NewEncoder(stdout)
		for _, observation := range outputObservations {
			if err := encoder.Encode(observation); err != nil {
				return err
			}
		}
		for _, finding := range outputFindings {
			if err := encoder.Encode(finding); err != nil {
				return err
			}
		}
		for _, diagnostic := range outputDiagnostics {
			if err := encoder.Encode(diagnostic); err != nil {
				return err
			}
		}
		return encoder.Encode(summary)
	case "json":
		body := struct {
			Observations []ScanObservation `json:"observations"`
			Findings     []ScanFinding     `json:"findings"`
			Diagnostics  []ScanDiagnostic  `json:"diagnostics"`
			Summary      ScanSummary       `json:"summary"`
		}{Observations: outputObservations, Findings: outputFindings, Diagnostics: outputDiagnostics, Summary: summary}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(body)
	default:
		for _, finding := range outputFindings {
			fmt.Fprintf(stdout, "%s\t%s\t%s:%s@%s\t%s\t%s\n", finding.Urgency, finding.Class, finding.Ecosystem, finding.Name, finding.Version, finding.ProviderRecordID, finding.Title)
		}
		for _, observation := range outputObservations {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n", observation.Presence, observation.Ecosystem, observation.Name, observation.Version, observation.SourceType, observation.SourcePath)
		}
		fmt.Fprintf(stdout, "summary\t%s\tinventory=%d\tfindings=%d\tdiagnostics=%d\n", summary.Status, summary.InventoryCount, summary.FindingCount, summary.DiagnosticCount)
		return nil
	}
}

func redactScanObservations(observations []ScanObservation, mode string) []ScanObservation {
	if mode == "" {
		return observations
	}
	redacted := make([]ScanObservation, len(observations))
	copy(redacted, observations)
	for i := range redacted {
		redacted[i].SourcePath = redactPath(redacted[i].SourcePath, mode)
	}
	return redacted
}

func redactScanFindings(findings []ScanFinding, mode string) []ScanFinding {
	if mode == "" {
		return findings
	}
	redacted := make([]ScanFinding, len(findings))
	copy(redacted, findings)
	for i := range redacted {
		redacted[i].SourcePath = redactPath(redacted[i].SourcePath, mode)
	}
	return redacted
}

func redactScanDiagnostics(diagnostics []ScanDiagnostic, mode string) []ScanDiagnostic {
	if mode == "" {
		return diagnostics
	}
	redacted := make([]ScanDiagnostic, len(diagnostics))
	copy(redacted, diagnostics)
	for i := range redacted {
		redacted[i].Path = redactPath(redacted[i].Path, mode)
		redacted[i].Message = redactScanText(redacted[i].Message, mode)
	}
	return redacted
}

func redactScanProviderSnapshots(snapshots []ScanProviderSnapshot, mode string) []ScanProviderSnapshot {
	if mode == "" {
		return snapshots
	}
	redacted := make([]ScanProviderSnapshot, len(snapshots))
	copy(redacted, snapshots)
	for i := range redacted {
		redacted[i].Error = redactScanText(redacted[i].Error, mode)
	}
	return redacted
}

func redactScanText(value, mode string) string {
	if value == "" || mode == "" {
		return value
	}
	if filepath.IsAbs(value) {
		return redactPath(value, mode)
	}
	return redactEvidenceText(value)
}

func redactPath(path, mode string) string {
	if path == "" || mode == "" {
		return path
	}
	switch mode {
	case "all":
		return "[redacted]"
	case "hash":
		sum := sha256.Sum256([]byte(path))
		return "sha256:" + fmt.Sprintf("%x", sum[:])
	case "home":
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return path
		}
		cleanPath := filepath.Clean(path)
		cleanHome := filepath.Clean(home)
		if cleanPath == cleanHome {
			return "~"
		}
		if strings.HasPrefix(cleanPath, cleanHome+string(os.PathSeparator)) {
			return "~" + strings.TrimPrefix(cleanPath, cleanHome)
		}
	}
	return path
}

func scanReportText(summary ScanSummary) string {
	return fmt.Sprintf("local-sec scan %s\nstatus: %s\ninventory: %d\nfindings: %d\ndiagnostics: %d\n", summary.RunID, summary.Status, summary.InventoryCount, summary.FindingCount, summary.DiagnosticCount)
}
