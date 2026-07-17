package lsec

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type scanCatalog struct {
	Entries []scanCatalogEntry `json:"entries"`
}

type scanCatalogEntry struct {
	ID            string `json:"id"`
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	KnownFilePath string `json:"known_file_path"`
	Class         string `json:"class"`
	Severity      string `json:"severity"`
	Urgency       string `json:"urgency"`
	Title         string `json:"title"`
}

func matchScanCatalogs(runID string, observations []ScanObservation, roots []string, catalogs []string, loadedAt time.Time) ([]ScanFinding, []ScanDiagnostic, []ScanCatalogSnapshot) {
	var findings []ScanFinding
	var diagnostics []ScanDiagnostic
	var snapshots []ScanCatalogSnapshot
	builtinEntries := builtinScanCatalogEntries()
	findings = append(findings, matchScanCatalogEntries(runID, observations, roots, builtinEntries)...)
	builtinBody, _ := json.Marshal(builtinEntries)
	snapshots = append(snapshots, ScanCatalogSnapshot{
		CatalogID: "builtin-host-ioc", Source: "builtin", SHA256: hashBytesHex(builtinBody),
		SignatureStatus: "compiled-in", EntryCount: len(builtinEntries), LoadedAt: loadedAt.Format(time.RFC3339Nano),
	})
	for _, path := range catalogs {
		body, err := os.ReadFile(path)
		if err != nil {
			diagnostics = append(diagnostics, scanDiagnostic(runID, "catalog_unreadable", path, err.Error()))
			continue
		}
		var catalog scanCatalog
		if err := json.Unmarshal(body, &catalog); err != nil {
			diagnostics = append(diagnostics, scanDiagnostic(runID, "catalog_parse_error", path, err.Error()))
			continue
		}
		findings = append(findings, matchScanCatalogEntries(runID, observations, roots, catalog.Entries)...)
		snapshots = append(snapshots, ScanCatalogSnapshot{
			CatalogID: filepath.Base(path), Source: path, SHA256: hashBytesHex(body),
			SignatureStatus: "unsigned-explicit", EntryCount: len(catalog.Entries), LoadedAt: loadedAt.Format(time.RFC3339Nano),
		})
	}
	return findings, diagnostics, snapshots
}

func builtinScanCatalogEntries() []scanCatalogEntry {
	return []scanCatalogEntry{
		{ID: "BUILTIN-AGENT-SETUP-MJS", KnownFilePath: ".claude/setup.mjs", Class: "host_ioc", Severity: "critical", Urgency: "critical-immediate", Title: "agent setup.mjs persistence indicator"},
		{ID: "BUILTIN-AGENT-ROUTER-RUNTIME", KnownFilePath: ".claude/router_runtime.js", Class: "host_ioc", Severity: "critical", Urgency: "critical-immediate", Title: "agent router runtime persistence indicator"},
		{ID: "BUILTIN-VSCODE-SETUP-MJS", KnownFilePath: ".vscode/setup.mjs", Class: "host_ioc", Severity: "critical", Urgency: "critical-immediate", Title: "VS Code setup.mjs persistence indicator"},
	}
}

func matchScanCatalogEntries(runID string, observations []ScanObservation, roots []string, entries []scanCatalogEntry) []ScanFinding {
	var findings []ScanFinding
	for _, observation := range observations {
		for _, entry := range entries {
			if !catalogEntryMatchesObservation(entry, observation) {
				continue
			}
			findings = append(findings, ScanFinding{
				Type: "finding", RunID: runID, FindingID: findingID("catalog", entry.ID, observation),
				Provider: "local_catalog", ProviderRecordID: entry.ID, Class: nonEmpty(entry.Class, "malicious_package"),
				Severity: nonEmpty(entry.Severity, "critical"), Urgency: nonEmpty(entry.Urgency, "critical-immediate"),
				Confidence: "high", Presence: observation.Presence, Ecosystem: observation.Ecosystem,
				Name: observation.Name, Version: observation.Version, Title: nonEmpty(entry.Title, entry.ID), SourcePath: observation.SourcePath,
			})
		}
	}
	for _, entry := range entries {
		if entry.KnownFilePath == "" {
			continue
		}
		for _, root := range roots {
			candidate := filepath.Join(root, filepath.FromSlash(entry.KnownFilePath))
			info, err := os.Lstat(candidate)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			findings = append(findings, ScanFinding{
				Type: "finding", RunID: runID, FindingID: "catalog:" + entry.ID + ":host_ioc:" + candidate,
				Provider: "local_catalog", ProviderRecordID: entry.ID, Class: nonEmpty(entry.Class, "host_ioc"),
				Severity: nonEmpty(entry.Severity, "critical"), Urgency: nonEmpty(entry.Urgency, "critical-immediate"),
				Confidence: "high", Presence: "installed", Title: nonEmpty(entry.Title, entry.ID), SourcePath: candidate,
			})
		}
	}
	return findings
}

func catalogEntryMatchesObservation(entry scanCatalogEntry, observation ScanObservation) bool {
	if entry.Ecosystem == "" || entry.Name == "" || entry.Version == "" {
		return false
	}
	return strings.EqualFold(entry.Ecosystem, observation.Ecosystem) &&
		normalizeComponentName(observation.Ecosystem, entry.Name) == observation.Normalized &&
		entry.Version == observation.Version
}

func hashBytesHex(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:])
}
