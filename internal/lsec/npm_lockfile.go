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
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, []Finding{{Code: "npm_lockfile_parse_failed", Severity: "block", File: path, Message: "could not parse package-lock.json", Evidence: err.Error()}}
	}
	var specs []PackageSpec
	var findings []Finding
	if len(doc.Packages) > 0 {
		for pkgPath, pkg := range doc.Packages {
			if pkgPath == "" || pkg.Link {
				continue
			}
			name, ok := packageNameFromNodeModulesPath(pkgPath)
			if !ok {
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

func lockedNPMPackageSpec(file, name, version, integrity, resolved string) (PackageSpec, []Finding) {
	if name == "" || version == "" {
		return PackageSpec{}, []Finding{{Code: "npm_lockfile_missing_version", Severity: "block", File: file, Message: "package-lock entry is missing an exact version", Evidence: name}}
	}
	if integrity == "" {
		return PackageSpec{}, []Finding{{Code: "npm_lockfile_missing_integrity", Severity: "block", File: file, Message: "package-lock entry is missing integrity", Evidence: name + "@" + version}}
	}
	if strings.HasPrefix(strings.ToLower(resolved), "git+") {
		return PackageSpec{}, []Finding{{Code: "npm_lockfile_vcs_source", Severity: "block", File: file, Message: "package-lock entry resolves to a VCS source", Evidence: name + " " + resolved}}
	}
	if resolved != "" && !isAllowedNPMRegistryResolvedURL(resolved) {
		return PackageSpec{}, []Finding{{Code: "npm_lockfile_external_source", Severity: "block", File: file, Message: "package-lock entry resolves outside the npm registry", Evidence: name + " " + resolved}}
	}
	return PackageSpec{Raw: name + "@" + version, Name: name, Version: version}, nil
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

func packageNameFromNodeModulesPath(pkgPath string) (string, bool) {
	parts := strings.Split(filepath.ToSlash(pkgPath), "/")
	for i := 0; i < len(parts); i++ {
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
