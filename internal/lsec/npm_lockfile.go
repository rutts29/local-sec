package lsec

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func ParseNPMLockfile(path string) ([]PackageSpec, []Finding) {
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, []Finding{{Code: "npm_lockfile_missing", Severity: "block", File: path, Message: "npm install without package specs requires package-lock.json", Evidence: err.Error()}}
	}
	var doc struct {
		Packages map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
			Resolved  string `json:"resolved"`
			Link      bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version      string         `json:"version"`
			Integrity    string         `json:"integrity"`
			Resolved     string         `json:"resolved"`
			Dependencies map[string]any `json:"dependencies"`
			Requires     map[string]any `json:"requires"`
			Link         bool           `json:"link"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, []Finding{{Code: "npm_lockfile_parse_failed", Severity: "block", File: path, Message: "could not parse package-lock.json", Evidence: err.Error()}}
	}
	var specs []PackageSpec
	var findings []Finding
	if len(doc.Packages) > 0 {
		for pkgPath, pkg := range doc.Packages {
			if pkgPath == "" {
				continue
			}
			if pkg.Link {
				findings = append(findings, linkedNPMLockfileFinding(path, pkgPath))
				continue
			}
			name, ok := packageNameFromNodeModulesPath(pkgPath)
			if !ok {
				findings = append(findings, unverifiedNPMLockfilePackagePathFinding(path, pkgPath))
				continue
			}
			spec, packageFindings := lockedNPMPackageSpec(path, name, pkg.Version, pkg.Integrity, pkg.Resolved)
			if spec.Name != "" {
				specs = append(specs, spec)
			}
			findings = append(findings, packageFindings...)
		}
	} else {
		for name, dep := range doc.Dependencies {
			if dep.Link {
				findings = append(findings, linkedNPMLockfileFinding(path, name))
				continue
			}
			spec, depFindings := lockedNPMPackageSpec(path, name, dep.Version, dep.Integrity, dep.Resolved)
			if spec.Name != "" {
				specs = append(specs, spec)
			}
			findings = append(findings, depFindings...)
		}
	}
	sort.SliceStable(specs, func(i, j int) bool {
		return specs[i].Name < specs[j].Name
	})
	return specs, findings
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

func lockedNPMPackageSpec(file, name, version, integrity, resolved string) (PackageSpec, []Finding) {
	if name == "" || version == "" {
		return PackageSpec{}, []Finding{{Code: "npm_lockfile_missing_version", Severity: "block", File: file, Message: "package-lock entry is missing an exact version", Evidence: name}}
	}
	var findings []Finding
	if integrity == "" {
		findings = append(findings, Finding{Code: "npm_lockfile_missing_integrity", Severity: "block", File: file, Message: "package-lock entry is missing integrity", Evidence: name + "@" + version})
	}
	findings = append(findings, npmLockfileResolvedFindings(file, name, version, resolved)...)
	if len(findings) > 0 {
		return PackageSpec{}, findings
	}
	return PackageSpec{Raw: name + "@" + version, Name: name, Version: version}, nil
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
	if err != nil || u.Scheme == "" {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "registry.npmjs.org"
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
		if strings.HasPrefix(name, "@") && i+2 < len(parts) {
			name += "/" + parts[i+2]
		}
		return name, true
	}
	return "", false
}
