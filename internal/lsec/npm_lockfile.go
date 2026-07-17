package lsec

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type npmLockedPackage struct {
	Name      string
	Version   string
	Resolved  string
	Integrity string
}

type npmLockfilePackage struct {
	Path      string
	Name      string
	Version   string
	Resolved  string
	Integrity string
	Link      bool
}

type npmLockfileJSONEntry struct {
	Name         string                          `json:"name"`
	Version      string                          `json:"version"`
	Integrity    string                          `json:"integrity"`
	Resolved     string                          `json:"resolved"`
	Link         bool                            `json:"link"`
	Dependencies map[string]npmLockfileJSONEntry `json:"dependencies"`
}

type npmLockfileDocument struct {
	Packages     map[string]npmLockfileJSONEntry `json:"packages"`
	Dependencies map[string]npmLockfileJSONEntry `json:"dependencies"`
}

func ParseNPMLockfile(path string) ([]PackageSpec, []Finding) {
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, []Finding{{Code: "npm_lockfile_missing", Severity: "block", File: path, Message: "npm install without package specs requires package-lock.json", Evidence: err.Error()}}
	}
	locked, findings := parseNPMLockfileDocument(path, body)
	specs := make([]PackageSpec, 0, len(locked))
	for _, pkg := range locked {
		specs = append(specs, PackageSpec{Raw: pkg.Name + "@" + pkg.Version, Name: pkg.Name, Version: pkg.Version})
	}
	return specs, findings
}

func parseNPMLockfileDocument(file string, body []byte) ([]npmLockedPackage, []Finding) {
	entries, err := parseNPMLockfilePackages(body)
	if err != nil {
		return nil, []Finding{{Code: "npm_lockfile_parse_failed", Severity: "block", File: file, Message: "could not parse package-lock.json", Evidence: err.Error()}}
	}

	var packages []npmLockedPackage
	var findings []Finding
	for _, entry := range entries {
		if entry.Link {
			findings = append(findings, linkedNPMLockfileFinding(file, entry.Path))
			continue
		}
		name, ok := packageNameFromNodeModulesPath(entry.Path)
		if !ok {
			findings = append(findings, unverifiedNPMLockfilePackagePathFinding(file, entry.Path))
			continue
		}
		pkg, packageFindings := lockedNPMRegistryPackage(file, name, entry)
		if pkg.Name != "" {
			packages = append(packages, pkg)
		}
		findings = append(findings, packageFindings...)
	}

	sort.SliceStable(packages, func(i, j int) bool {
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		if packages[i].Version != packages[j].Version {
			return packages[i].Version < packages[j].Version
		}
		if packages[i].Resolved != packages[j].Resolved {
			return packages[i].Resolved < packages[j].Resolved
		}
		return packages[i].Integrity < packages[j].Integrity
	})
	deduplicated, duplicateFindings := deduplicateNPMLockedPackages(file, packages)
	return deduplicated, append(findings, duplicateFindings...)
}

// inventoryNPMLockfilePackages extracts declared package identities for scan inventory.
// Unlike parseNPMLockfileDocument, it does not require integrity or registry-resolved URLs.
func inventoryNPMLockfilePackages(file string, body []byte) ([]npmLockedPackage, []Finding) {
	entries, err := parseNPMLockfilePackages(body)
	if err != nil {
		return nil, []Finding{{Code: "npm_lockfile_parse_failed", Severity: "block", File: file, Message: "could not parse package-lock.json", Evidence: err.Error()}}
	}
	var packages []npmLockedPackage
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.Link {
			continue
		}
		name, ok := packageNameFromNodeModulesPath(entry.Path)
		if !ok {
			if entry.Name != "" {
				name = entry.Name
			} else {
				continue
			}
		}
		if name == "" || entry.Version == "" {
			continue
		}
		key := name + "\x00" + entry.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		packages = append(packages, npmLockedPackage{Name: name, Version: entry.Version, Resolved: entry.Resolved, Integrity: entry.Integrity})
	}
	sort.SliceStable(packages, func(i, j int) bool {
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		return packages[i].Version < packages[j].Version
	})
	return packages, nil
}

func parseNPMLockfilePackages(body []byte) ([]npmLockfilePackage, error) {
	var doc npmLockfileDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	var packages []npmLockfilePackage
	if len(doc.Packages) > 0 {
		for path, entry := range doc.Packages {
			if path == "" {
				continue
			}
			packages = append(packages, npmLockfilePackageFromJSON(path, "", entry))
		}
	} else {
		walkNPMLockfileDependencies("", doc.Dependencies, &packages)
	}
	sort.SliceStable(packages, func(i, j int) bool {
		if packages[i].Path != packages[j].Path {
			return packages[i].Path < packages[j].Path
		}
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		if packages[i].Version != packages[j].Version {
			return packages[i].Version < packages[j].Version
		}
		if packages[i].Resolved != packages[j].Resolved {
			return packages[i].Resolved < packages[j].Resolved
		}
		if packages[i].Integrity != packages[j].Integrity {
			return packages[i].Integrity < packages[j].Integrity
		}
		return !packages[i].Link && packages[j].Link
	})
	return packages, nil
}

func walkNPMLockfileDependencies(parentPath string, dependencies map[string]npmLockfileJSONEntry, packages *[]npmLockfilePackage) {
	for _, name := range sortedNPMLockfileKeys(dependencies) {
		entry := dependencies[name]
		path := "node_modules/" + name
		if parentPath != "" {
			path = parentPath + "/node_modules/" + name
		}
		*packages = append(*packages, npmLockfilePackageFromJSON(path, name, entry))
		walkNPMLockfileDependencies(path, entry.Dependencies, packages)
	}
}

func npmLockfilePackageFromJSON(path, fallbackName string, entry npmLockfileJSONEntry) npmLockfilePackage {
	name := entry.Name
	if name == "" {
		name = fallbackName
	}
	if name == "" {
		name, _ = packageNameFromNodeModulesPath(path)
	}
	return npmLockfilePackage{
		Path:      path,
		Name:      name,
		Version:   entry.Version,
		Resolved:  entry.Resolved,
		Integrity: entry.Integrity,
		Link:      entry.Link,
	}
}

func deduplicateNPMLockedPackages(file string, packages []npmLockedPackage) ([]npmLockedPackage, []Finding) {
	deduplicated := make([]npmLockedPackage, 0, len(packages))
	var findings []Finding
	for start := 0; start < len(packages); {
		end := start + 1
		for end < len(packages) && packages[end].Name == packages[start].Name && packages[end].Version == packages[start].Version {
			end++
		}
		conflicting := false
		for i := start + 1; i < end; i++ {
			if packages[i].Resolved != packages[start].Resolved || packages[i].Integrity != packages[start].Integrity {
				conflicting = true
				break
			}
		}
		if conflicting {
			findings = append(findings, Finding{
				Code:     "npm_lockfile_conflicting_duplicate",
				Severity: "block",
				File:     file,
				Message:  "package-lock contains conflicting entries for the same package name and version",
				Evidence: packages[start].Name + "@" + packages[start].Version,
			})
		} else {
			deduplicated = append(deduplicated, packages[start])
		}
		start = end
	}
	return deduplicated, findings
}

func sortedNPMLockfileKeys[T any](entries map[string]T) []string {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func lockedNPMRegistryPackage(file, name string, entry npmLockfilePackage) (npmLockedPackage, []Finding) {
	if name == "" || entry.Version == "" {
		return npmLockedPackage{}, []Finding{{Code: "npm_lockfile_missing_version", Severity: "block", File: file, Message: "package-lock entry is missing an exact version", Evidence: name}}
	}
	var findings []Finding
	if entry.Integrity == "" {
		findings = append(findings, Finding{Code: "npm_lockfile_missing_integrity", Severity: "block", File: file, Message: "package-lock entry is missing integrity", Evidence: name + "@" + entry.Version})
	}
	findings = append(findings, npmLockfileResolvedFindings(file, name, entry.Version, entry.Resolved)...)
	if len(findings) > 0 {
		return npmLockedPackage{}, findings
	}
	return npmLockedPackage{Name: name, Version: entry.Version, Resolved: entry.Resolved, Integrity: entry.Integrity}, nil
}

func unverifiedNPMLockfilePackagePathFinding(file, evidence string) Finding {
	return Finding{
		Code:     "npm_lockfile_unverified_package_path",
		Severity: "block",
		File:     file,
		Message:  "package-lock entry is not a registry node_modules package path and cannot be verified from registry bytes",
		Evidence: evidence,
	}
}

func linkedNPMLockfileFinding(file, evidence string) Finding {
	return Finding{
		Code:     "npm_lockfile_linked_package",
		Severity: "block",
		File:     file,
		Message:  "package-lock entry is a local link, path, or workspace package and cannot be verified from registry bytes",
		Evidence: evidence,
	}
}

func npmLockfileResolvedFindings(file, name, version, resolved string) []Finding {
	evidence := name + "@" + version
	if resolved == "" {
		return []Finding{{Code: "npm_lockfile_missing_resolved", Severity: "block", File: file, Message: "package-lock entry is missing a resolved tarball URL", Evidence: evidence}}
	}
	if strings.HasPrefix(strings.ToLower(resolved), "git+") {
		return []Finding{{Code: "npm_lockfile_vcs_source", Severity: "block", File: file, Message: "package-lock entry resolves to a VCS source", Evidence: evidence + " " + resolved}}
	}
	if !isAllowedNPMRegistryResolvedURL(resolved) {
		return []Finding{{Code: "npm_lockfile_external_source", Severity: "block", File: file, Message: "package-lock entry resolves outside the npm registry", Evidence: evidence + " " + resolved}}
	}
	if !npmResolvedURLMatchesPackage(resolved, name, version) {
		return []Finding{{Code: "npm_lockfile_resolved_mismatch", Severity: "block", File: file, Message: "package-lock entry resolved URL does not match the locked package name and version", Evidence: evidence + " " + resolved}}
	}
	return nil
}

func isAllowedNPMRegistryResolvedURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return false
	}
	if u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return strings.EqualFold(u.Hostname(), "registry.npmjs.org")
}

func npmResolvedURLMatchesPackage(raw, name, version string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path, err := url.PathUnescape(u.EscapedPath())
	if err != nil {
		return false
	}
	pkgBase := name
	if slash := strings.LastIndex(pkgBase, "/"); slash >= 0 {
		pkgBase = pkgBase[slash+1:]
	}
	return path == "/"+name+"/-/"+pkgBase+"-"+version+".tgz"
}

func packageNameFromNodeModulesPath(pkgPath string) (string, bool) {
	parts := strings.Split(filepath.ToSlash(pkgPath), "/")
	for i := len(parts) - 2; i >= 0; i-- {
		if parts[i] != "node_modules" || i+1 >= len(parts) {
			continue
		}
		name := parts[i+1]
		end := i + 2
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, "@") {
			if i+2 >= len(parts) || parts[i+2] == "" {
				continue
			}
			name += "/" + parts[i+2]
			end++
		}
		if end != len(parts) {
			continue
		}
		return name, true
	}
	return "", false
}
