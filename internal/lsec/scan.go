package lsec

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

func scanMetadataRoots(runID string, roots []string) ([]ScanObservation, []ScanDiagnostic) {
	var observations []ScanObservation
	var diagnostics []ScanDiagnostic
	for _, root := range roots {
		root = filepath.Clean(root)
		info, err := os.Lstat(root)
		if err != nil {
			diagnostics = append(diagnostics, scanDiagnostic(runID, "root_unreadable", root, err.Error()))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			diagnostics = append(diagnostics, scanDiagnostic(runID, "root_symlink_skipped", root, "scan roots must not be symlinks"))
			continue
		}
		err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				diagnostics = append(diagnostics, scanDiagnostic(runID, "walk_error", path, walkErr.Error()))
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				diagnostics = append(diagnostics, scanDiagnostic(runID, "stat_error", path, err.Error()))
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			found, foundDiagnostics := scanMetadataFile(runID, path, info.Size())
			observations = append(observations, found...)
			diagnostics = append(diagnostics, foundDiagnostics...)
			return nil
		})
		if err != nil {
			diagnostics = append(diagnostics, scanDiagnostic(runID, "walk_failed", root, err.Error()))
		}
	}
	sort.SliceStable(observations, func(i, j int) bool {
		return observations[i].SourcePath < observations[j].SourcePath
	})
	return observations, diagnostics
}

func scanMetadataFile(runID, path string, size int64) ([]ScanObservation, []ScanDiagnostic) {
	if size > 4*1024*1024 {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "metadata_file_too_large", path, "metadata file exceeds 4 MiB")}
	}
	base := filepath.Base(path)
	switch {
	case base == "package-lock.json" || base == "npm-shrinkwrap.json" || base == ".package-lock.json":
		return scanNPMLockMetadata(runID, path)
	case isCycloneDXSBOMFilename(base):
		return scanCycloneDXSBOM(runID, path)
	case base == "INSTALL_RECEIPT.json":
		return scanHomebrewReceipt(runID, path)
	case base == "package.json" && isEditorExtensionManifest(path):
		return scanEditorExtensionManifest(runID, path)
	case base == "METADATA" && strings.HasSuffix(filepath.Base(filepath.Dir(path)), ".dist-info"):
		return scanPythonMetadata(runID, path, "python_dist_info")
	case base == "PKG-INFO" && strings.HasSuffix(filepath.Base(filepath.Dir(path)), ".egg-info"):
		return scanPythonMetadata(runID, path, "python_egg_info")
	case base == ".mcp.json":
		return scanMCPConfig(runID, path)
	default:
		return nil, nil
	}
}

func scanNPMLockMetadata(runID, path string) ([]ScanObservation, []ScanDiagnostic) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "read_error", path, err.Error())}
	}
	var doc struct {
		Packages map[string]struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
			Dev      bool   `json:"dev"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", path, err.Error())}
	}
	var observations []ScanObservation
	for packagePath, pkg := range doc.Packages {
		if packagePath == "" || pkg.Version == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = npmNameFromNodeModulesPath(packagePath)
		}
		if name == "" {
			continue
		}
		observations = append(observations, componentObservation(runID, "npm", name, pkg.Version, "declared", "npm_lockfile", path, "high", pkg.Dev))
	}
	return observations, nil
}

func scanHomebrewReceipt(runID, path string) ([]ScanObservation, []ScanDiagnostic) {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := 0; i+3 < len(parts); i++ {
		if parts[i] != "Cellar" {
			continue
		}
		name := parts[i+1]
		version := parts[i+2]
		if name == "" || version == "" {
			break
		}
		return []ScanObservation{componentObservation(runID, "Homebrew", name, version, "installed", "homebrew_receipt", path, "high", false)}, nil
	}
	return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", path, "homebrew receipt path did not include Cellar/name/version")}
}

func scanEditorExtensionManifest(runID, path string) ([]ScanObservation, []ScanDiagnostic) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "read_error", path, err.Error())}
	}
	var doc struct {
		Publisher string `json:"publisher"`
		Name      string `json:"name"`
		Version   string `json:"version"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", path, err.Error())}
	}
	if doc.Publisher == "" || doc.Name == "" || doc.Version == "" {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", path, "extension manifest missing publisher, name, or version")}
	}
	name := doc.Publisher + "." + doc.Name
	return []ScanObservation{componentObservation(runID, "vscode-extension", name, doc.Version, "configured", "editor_extension_manifest", path, "high", false)}, nil
}

func scanPythonMetadata(runID, path, sourceType string) ([]ScanObservation, []ScanDiagnostic) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "read_error", path, err.Error())}
	}
	headers := parseSimpleMetadataHeaders(body)
	name := headers["name"]
	version := headers["version"]
	if name == "" || version == "" {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", path, "python metadata missing name or version")}
	}
	return []ScanObservation{componentObservation(runID, "PyPI", name, version, "installed", sourceType, path, "high", false)}, nil
}

func scanMCPConfig(runID, path string) ([]ScanObservation, []ScanDiagnostic) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "read_error", path, err.Error())}
	}
	var doc struct {
		Servers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", path, err.Error())}
	}
	var observations []ScanObservation
	for _, server := range doc.Servers {
		if filepath.Base(server.Command) != "npx" {
			continue
		}
		for _, arg := range server.Args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			spec := ParsePackageSpec(arg)
			if spec.Name == "" || spec.DirectURL || spec.VCS || spec.LocalPath {
				continue
			}
			observations = append(observations, componentObservation(runID, "npm", spec.Name, spec.Version, "configured", "mcp_config", path, "medium", false))
			break
		}
	}
	return observations, nil
}

func componentObservation(runID, ecosystem, name, version, presence, sourceType, sourcePath, confidence string, development bool) ScanObservation {
	normalized := normalizeComponentName(ecosystem, name)
	return ScanObservation{
		Type: "observation", RunID: runID, Ecosystem: ecosystem, Name: name, Normalized: normalized,
		Version: version, PURL: packageURL(ecosystem, normalized, version), Presence: presence,
		SourceType: sourceType, SourcePath: sourcePath, Development: development, Confidence: confidence,
	}
}

func scanDiagnostic(runID, code, path, message string) ScanDiagnostic {
	return ScanDiagnostic{Type: "diagnostic", RunID: runID, Code: code, Path: path, Message: message}
}

func isEditorExtensionManifest(path string) bool {
	clean := filepath.ToSlash(path)
	if !strings.Contains(clean, "/extensions/") {
		return false
	}
	for _, marker := range []string{
		"/.vscode/extensions/",
		"/.vscode-insiders/extensions/",
		"/.cursor/extensions/",
		"/.windsurf/extensions/",
		"/.vscodium/extensions/",
		"/Code/User/extensions/",
		"/Code - Insiders/User/extensions/",
		"/Cursor/User/extensions/",
		"/Windsurf/User/extensions/",
		"/VSCodium/User/extensions/",
	} {
		if strings.Contains(clean, marker) {
			return true
		}
	}
	return false
}

func npmNameFromNodeModulesPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := 0; i < len(parts); i++ {
		if parts[i] != "node_modules" || i+1 >= len(parts) {
			continue
		}
		if strings.HasPrefix(parts[i+1], "@") && i+2 < len(parts) {
			return parts[i+1] + "/" + parts[i+2]
		}
		return parts[i+1]
	}
	return ""
}

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

func queryScanAdvisories(ctx context.Context, store Store, runID string, observations []ScanObservation) ([]ScanFinding, []ScanDiagnostic, []ScanProviderSnapshot) {
	components := exactScanComponents(observations)
	if len(components) == 0 {
		return nil, nil, []ScanProviderSnapshot{{Provider: "osv", Status: "not_applicable"}}
	}
	results := make([][]Advisory, len(components))
	var uncached []ScanObservation
	var uncachedIndexes []int
	cachedCount := 0
	for i, component := range components {
		if entry, ok := store.FreshAdvisoryCache(component.Ecosystem, component.Name, component.Version, 30*time.Minute); ok {
			results[i] = entry.Advisories
			cachedCount++
			continue
		}
		uncached = append(uncached, component)
		uncachedIndexes = append(uncachedIndexes, i)
	}
	if len(uncached) > 0 {
		fetched, err := QueryOSVBatchChecked(ctx, uncached)
		if err != nil {
			snapshot := ScanProviderSnapshot{Provider: "osv", Status: "error", CachedCount: cachedCount, QueriedCount: len(uncached), Error: err.Error()}
			return scanFindingsFromAdvisories(runID, components, results), []ScanDiagnostic{scanDiagnostic(runID, "provider_unavailable", "osv", err.Error())}, []ScanProviderSnapshot{snapshot}
		}
		now := time.Now().UTC()
		for i, advisories := range fetched {
			if i >= len(uncachedIndexes) {
				break
			}
			component := uncached[i]
			results[uncachedIndexes[i]] = advisories
			entry := AdvisoryCacheEntry{Ecosystem: component.Ecosystem, Name: component.Name, Version: component.Version, CheckedAt: now, Advisories: advisories}
			_ = store.PutAdvisoryCache(entry)
			_ = store.RecordAdvisoryChecks(entry)
		}
		snapshot := ScanProviderSnapshot{Provider: "osv", Status: "ok", FetchedAt: now.Format(time.RFC3339Nano), CachedCount: cachedCount, QueriedCount: len(uncached)}
		return scanFindingsFromAdvisories(runID, components, results), nil, []ScanProviderSnapshot{snapshot}
	}
	snapshot := ScanProviderSnapshot{Provider: "osv", Status: "cache_only", CachedCount: cachedCount}
	return scanFindingsFromAdvisories(runID, components, results), nil, []ScanProviderSnapshot{snapshot}
}

func scanFindingsFromAdvisories(runID string, components []ScanObservation, results [][]Advisory) []ScanFinding {
	var findings []ScanFinding
	for i, result := range results {
		if i >= len(components) {
			break
		}
		component := components[i]
		for _, advisory := range result {
			class := "vulnerability"
			urgency := "review"
			if strings.EqualFold(advisory.Type, "malware") {
				class = "malicious_package"
				urgency = "critical-immediate"
			} else if strings.EqualFold(advisory.Severity, "critical") {
				urgency = "high"
			}
			findings = append(findings, ScanFinding{
				Type: "finding", RunID: runID, FindingID: findingID("osv", advisory.ID, component),
				Provider: "osv", ProviderRecordID: advisory.ID, Class: class, Severity: advisory.Severity,
				Urgency: urgency, Confidence: "high", Presence: component.Presence, Ecosystem: component.Ecosystem,
				Name: component.Name, Version: component.Version, Title: nonEmpty(advisory.Summary, advisory.ID), SourcePath: component.SourcePath,
			})
		}
	}
	return findings
}

func exactScanComponents(observations []ScanObservation) []ScanObservation {
	seen := map[string]bool{}
	var components []ScanObservation
	for _, observation := range observations {
		if observation.Ecosystem == "" || observation.Name == "" || observation.Version == "" {
			continue
		}
		switch observation.Ecosystem {
		case "npm", "PyPI":
		default:
			continue
		}
		key := dependencyKey(observation.Ecosystem, observation.Normalized, observation.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		components = append(components, observation)
	}
	return components
}

func findingID(provider, id string, observation ScanObservation) string {
	return provider + ":" + id + ":" + observation.Ecosystem + ":" + observation.Normalized + ":" + observation.Version + ":" + observation.Presence
}

func nonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func parseSimpleMetadataHeaders(body []byte) map[string]string {
	headers := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			break
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return headers
}

func normalizeComponentName(ecosystem, name string) string {
	switch ecosystem {
	case "PyPI":
		return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(name))
	default:
		return strings.ToLower(name)
	}
}

func packageURL(ecosystem, name, version string) string {
	if name == "" || version == "" {
		return ""
	}
	switch ecosystem {
	case "npm":
		return "pkg:npm/" + name + "@" + version
	case "PyPI":
		return "pkg:pypi/" + name + "@" + version
	case "Homebrew":
		return "pkg:brew/" + name + "@" + version
	case "vscode-extension":
		return "pkg:vscode/" + name + "@" + version
	default:
		return ""
	}
}

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

func hashBytesHex(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:])
}

func scanReportText(summary ScanSummary) string {
	return fmt.Sprintf("local-sec scan %s\nstatus: %s\ninventory: %d\nfindings: %d\ndiagnostics: %d\n", summary.RunID, summary.Status, summary.InventoryCount, summary.FindingCount, summary.DiagnosticCount)
}
