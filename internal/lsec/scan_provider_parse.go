package lsec

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

func parseOSVScannerFindings(runID string, body []byte, sourcePaths map[string]string) ([]ScanFinding, error) {
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
			sourcePath := result.Source.Path
			if original, ok := sourcePaths[filepath.Clean(sourcePath)]; ok {
				sourcePath = original
			}
			observation := componentObservation(runID, pkg.Package.Ecosystem, pkg.Package.Name, pkg.Package.Version, "declared", "npm_lockfile", sourcePath, "high", false)
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
