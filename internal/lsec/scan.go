package lsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type ScanObservation struct {
	Type           string `json:"type"`
	RunID          string `json:"run_id"`
	Ecosystem      string `json:"ecosystem"`
	Name           string `json:"name"`
	Normalized     string `json:"normalized_name,omitempty"`
	Version        string `json:"version,omitempty"`
	PURL           string `json:"purl,omitempty"`
	Presence       string `json:"presence"`
	SourceType     string `json:"source_type"`
	SourcePath     string `json:"source_path"`
	Direct         bool   `json:"direct,omitempty"`
	Development    bool   `json:"development,omitempty"`
	Installer      string `json:"installer,omitempty"`
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
	Confidence     string `json:"confidence"`
}

type ScanDiagnostic struct {
	Type    string `json:"type"`
	RunID   string `json:"run_id"`
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

type ScanFinding struct {
	Type             string `json:"type"`
	RunID            string `json:"run_id"`
	FindingID        string `json:"finding_id"`
	Provider         string `json:"provider"`
	ProviderRecordID string `json:"provider_record_id"`
	Class            string `json:"class"`
	Severity         string `json:"severity"`
	Urgency          string `json:"urgency"`
	Confidence       string `json:"confidence"`
	Presence         string `json:"presence"`
	Ecosystem        string `json:"ecosystem"`
	Name             string `json:"name"`
	Version          string `json:"version,omitempty"`
	Title            string `json:"title"`
	SourcePath       string `json:"source_path,omitempty"`
}

type ScanSummary struct {
	Type            string    `json:"type"`
	RunID           string    `json:"run_id"`
	Profile         string    `json:"profile"`
	Backend         string    `json:"backend"`
	NetworkMode     string    `json:"network_mode"`
	Status          string    `json:"status"`
	InventoryCount  int       `json:"inventory_count"`
	FindingCount    int       `json:"finding_count"`
	DiagnosticCount int       `json:"diagnostic_count"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
}

type ScanProviderSnapshot struct {
	Provider       string         `json:"provider"`
	Status         string         `json:"status"`
	FetchedAt      string         `json:"fetched_at,omitempty"`
	CachedCount    int            `json:"cached_count,omitempty"`
	CandidateCount int            `json:"candidate_count"`
	AcceptedCount  int            `json:"accepted_count"`
	SkippedCount   int            `json:"skipped_count"`
	QueriedCount   int            `json:"queried_count"`
	FailedCount    int            `json:"failed_count"`
	SkipReasons    map[string]int `json:"skip_reasons,omitempty"`
	Error          string         `json:"error,omitempty"`
}

type ScanCatalogSnapshot struct {
	CatalogID       string `json:"catalog_id"`
	Source          string `json:"source"`
	SHA256          string `json:"sha256"`
	SignatureStatus string `json:"signature_status"`
	EntryCount      int    `json:"entry_count"`
	LoadedAt        string `json:"loaded_at"`
}

type scanOptions struct {
	Profile      string
	Roots        []string
	Network      string
	Format       string
	Backend      string
	Catalogs     []string
	FindingsOnly bool
	RedactPaths  string
}

func runScan(args []string, stdout io.Writer, paths Paths, store Store) error {
	options, err := parseScanOptions(args)
	if err != nil {
		return err
	}
	started := time.Now().UTC()
	runID := NewRunID(started)
	observations, diagnostics := scanMetadataRoots(runID, options.Roots)
	findings, catalogDiagnostics, catalogSnapshots := matchScanCatalogs(runID, observations, options.Roots, options.Catalogs, started)
	diagnostics = append(diagnostics, catalogDiagnostics...)
	providerSnapshots := []ScanProviderSnapshot{{Provider: "osv", Status: "disabled"}}
	if options.Network == "advisories" {
		advisoryFindings, advisoryDiagnostics, snapshots := queryScanAdvisories(context.Background(), store, runID, observations)
		findings = append(findings, advisoryFindings...)
		diagnostics = append(diagnostics, advisoryDiagnostics...)
		providerSnapshots = snapshots
		scannerFindings, scannerDiagnostics, scannerSnapshot := runOSVScannerProvider(context.Background(), runID, options.Roots)
		findings = append(findings, scannerFindings...)
		diagnostics = append(diagnostics, scannerDiagnostics...)
		providerSnapshots = append(providerSnapshots, scannerSnapshot)
		pipAuditFindings, pipAuditDiagnostics, pipAuditSnapshot := runPipAuditProvider(context.Background(), runID, options.Roots)
		findings = append(findings, pipAuditFindings...)
		diagnostics = append(diagnostics, pipAuditDiagnostics...)
		providerSnapshots = append(providerSnapshots, pipAuditSnapshot)
		grypeFindings, grypeDiagnostics, grypeSnapshot := runGrypeProvider(context.Background(), runID, observations)
		findings = append(findings, grypeFindings...)
		diagnostics = append(diagnostics, grypeDiagnostics...)
		providerSnapshots = append(providerSnapshots, grypeSnapshot)
		syftFindings, syftDiagnostics, syftSnapshot := runSyftProvider(context.Background(), runID, options.Roots)
		findings = append(findings, syftFindings...)
		diagnostics = append(diagnostics, syftDiagnostics...)
		providerSnapshots = append(providerSnapshots, syftSnapshot)
		cargoVetFindings, cargoVetDiagnostics, cargoVetSnapshot := runCargoVetProvider(context.Background(), runID, options.Roots)
		findings = append(findings, cargoVetFindings...)
		diagnostics = append(diagnostics, cargoVetDiagnostics...)
		providerSnapshots = append(providerSnapshots, cargoVetSnapshot)
		bumblebeeFindings, bumblebeeDiagnostics, bumblebeeSnapshot := runBumblebeeProvider(context.Background(), runID, options.Roots)
		findings = append(findings, bumblebeeFindings...)
		diagnostics = append(diagnostics, bumblebeeDiagnostics...)
		providerSnapshots = append(providerSnapshots, bumblebeeSnapshot)
	}
	status := "complete"
	if len(diagnostics) > 0 {
		status = "partial"
	}
	summary := ScanSummary{
		Type: "scan_summary", RunID: runID, Profile: options.Profile, Backend: options.Backend, NetworkMode: options.Network,
		Status: status, InventoryCount: len(observations), FindingCount: len(findings), DiagnosticCount: len(diagnostics),
		StartedAt: started, FinishedAt: time.Now().UTC(),
	}
	bundleObservations := redactScanObservations(observations, options.RedactPaths)
	bundleFindings := redactScanFindings(findings, options.RedactPaths)
	bundleDiagnostics := redactScanDiagnostics(diagnostics, options.RedactPaths)
	bundleProviderSnapshots := redactScanProviderSnapshots(providerSnapshots, options.RedactPaths)
	if err := writeScanBundle(paths, runID, bundleObservations, bundleFindings, bundleDiagnostics, summary, bundleProviderSnapshots, catalogSnapshots); err != nil {
		return err
	}
	if err := store.AppendEvent("scan", summary); err != nil {
		return err
	}
	return writeScanOutput(stdout, options, observations, findings, diagnostics, summary)
}

func parseScanOptions(args []string) (scanOptions, error) {
	options := scanOptions{Profile: "baseline", Network: "advisories", Format: "table", Backend: "builtin"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--profile":
			i++
			if i >= len(args) {
				return options, errors.New("scan --profile requires a value")
			}
			options.Profile = args[i]
		case "--root":
			i++
			if i >= len(args) {
				return options, errors.New("scan --root requires a path")
			}
			options.Roots = append(options.Roots, filepath.Clean(args[i]))
		case "--network":
			i++
			if i >= len(args) {
				return options, errors.New("scan --network requires off or advisories")
			}
			options.Network = args[i]
		case "--format":
			i++
			if i >= len(args) {
				return options, errors.New("scan --format requires table, json, or ndjson")
			}
			options.Format = args[i]
		case "--backend":
			i++
			if i >= len(args) {
				return options, errors.New("scan --backend requires builtin")
			}
			options.Backend = args[i]
		case "--catalog":
			i++
			if i >= len(args) {
				return options, errors.New("scan --catalog requires a path")
			}
			options.Catalogs = append(options.Catalogs, filepath.Clean(args[i]))
		case "--findings-only":
			options.FindingsOnly = true
		case "--redact-paths":
			i++
			if i >= len(args) {
				return options, errors.New("scan --redact-paths requires home, all, or hash")
			}
			options.RedactPaths = args[i]
		default:
			return options, fmt.Errorf("unknown scan option %q", args[i])
		}
	}
	if options.Profile != "baseline" && options.Profile != "project" && options.Profile != "deep" {
		return options, errors.New("scan profile must be baseline, project, or deep")
	}
	if options.Network != "off" && options.Network != "advisories" {
		return options, errors.New("scan network must be off or advisories")
	}
	if options.Format != "table" && options.Format != "json" && options.Format != "ndjson" {
		return options, errors.New("scan format must be table, json, or ndjson")
	}
	if options.Backend != "builtin" {
		return options, errors.New("only builtin scan backend is currently implemented")
	}
	if options.RedactPaths != "" && options.RedactPaths != "home" && options.RedactPaths != "all" && options.RedactPaths != "hash" {
		return options, errors.New("scan --redact-paths must be home, all, or hash")
	}
	if len(options.Roots) == 0 {
		wd, err := os.Getwd()
		if err != nil {
			return options, err
		}
		options.Roots = []string{wd}
	}
	return options, nil
}
