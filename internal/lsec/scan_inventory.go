package lsec

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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
	// Inventory uses identity-only extraction so declared packages still appear even
	// when integrity/resolved fields would fail closed for install-guard validation.
	locked, findings := inventoryNPMLockfilePackages(path, body)
	for _, finding := range findings {
		if finding.Code == "npm_lockfile_parse_failed" {
			return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", path, finding.Evidence)}
		}
	}
	observations := make([]ScanObservation, 0, len(locked))
	for _, pkg := range locked {
		observations = append(observations, componentObservation(runID, "npm", pkg.Name, pkg.Version, "declared", "npm_lockfile", path, "high", false))
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
