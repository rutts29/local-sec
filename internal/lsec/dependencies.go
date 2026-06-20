package lsec

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var exactVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9A-Za-z][0-9A-Za-z.-]*)*$`)

func ExtractDependencyRefs(root, ecosystem string) ([]DependencyRef, []Finding, error) {
	var deps []DependencyRef
	var findings []Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		switch {
		case ecosystem == "npm" && filepath.Base(path) == "package.json":
			found, prompts := extractNPMDependencyRefs(path, rel)
			deps = append(deps, found...)
			findings = append(findings, prompts...)
		case ecosystem == "PyPI" && filepath.Base(path) == "METADATA" && strings.Contains(filepath.ToSlash(rel), ".dist-info/"):
			found, prompts := extractWheelDependencyRefs(path, rel)
			deps = append(deps, found...)
			findings = append(findings, prompts...)
		}
		return nil
	})
	sort.SliceStable(deps, func(i, j int) bool {
		if deps[i].Exact != deps[j].Exact {
			return deps[i].Exact
		}
		if deps[i].Name == deps[j].Name {
			return deps[i].Raw < deps[j].Raw
		}
		return deps[i].Name < deps[j].Name
	})
	return deps, findings, err
}

func ExtractArtifactIdentity(root, ecosystem string) (string, string, error) {
	var name string
	var version string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || name != "" && version != "" {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		switch {
		case ecosystem == "npm" && filepath.Base(path) == "package.json":
			name, version = extractNPMIdentity(path)
		case ecosystem == "PyPI" && filepath.Base(path) == "METADATA" && strings.Contains(filepath.ToSlash(rel), ".dist-info/"):
			name, version = extractWheelIdentity(path)
		}
		return nil
	})
	return name, version, err
}

func extractNPMIdentity(path string) (string, string) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return "", ""
	}
	return pkg.Name, pkg.Version
}

func extractWheelIdentity(path string) (string, string) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var name string
	var version string
	for _, line := range strings.Split(string(body), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			name = strings.TrimSpace(value)
		case "version":
			version = strings.TrimSpace(value)
		}
	}
	return name, version
}

func extractNPMDependencyRefs(path, rel string) ([]DependencyRef, []Finding) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return nil, nil
	}
	var deps []DependencyRef
	var findings []Finding
	for name, raw := range mergeStringMaps(pkg.Dependencies, pkg.OptionalDependencies) {
		dep := dependencyRef("npm", name, raw)
		deps = append(deps, dep)
		if !dep.Exact {
			findings = append(findings, unresolvedDependencyFinding(rel, dep))
		}
	}
	return deps, findings
}

func extractWheelDependencyRefs(path, rel string) ([]DependencyRef, []Finding) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var deps []DependencyRef
	var findings []Finding
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(strings.ToLower(line), "requires-dist:") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, "Requires-Dist:"))
		name, version := parseRequiresDist(raw)
		if name == "" {
			continue
		}
		dep := DependencyRef{Ecosystem: "PyPI", Name: name, Version: version, Raw: raw, Exact: version != ""}
		deps = append(deps, dep)
	}
	return deps, findings
}

func dependencyRef(ecosystem, name, raw string) DependencyRef {
	version := strings.TrimPrefix(raw, "v")
	exact := exactVersionPattern.MatchString(version)
	if !exact {
		version = ""
	}
	return DependencyRef{Ecosystem: ecosystem, Name: name, Version: version, Raw: raw, Exact: exact}
}

func parseRequiresDist(raw string) (string, string) {
	name := strings.TrimSpace(raw)
	if idx := strings.IndexAny(name, " (<>=!~;["); idx >= 0 {
		name = strings.TrimSpace(name[:idx])
	}
	version := ""
	if idx := strings.Index(raw, "=="); idx >= 0 {
		rest := raw[idx+2:]
		rest = strings.TrimLeft(rest, " (")
		for i, r := range rest {
			if !(r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				rest = rest[:i]
				break
			}
		}
		version = strings.TrimSpace(rest)
	}
	return name, version
}

func unresolvedDependencyFinding(rel string, dep DependencyRef) Finding {
	return Finding{
		Code: "dependency_version_unresolved", Severity: "prompt", File: rel,
		Message:  "dependency version is not exact, so advisory coverage is incomplete",
		Evidence: dep.Name + " " + dep.Raw,
	}
}

func mergeStringMaps(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
