package lsec

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"unicode"
)

type cyclonedxSBOM struct {
	BomFormat  string               `json:"bomFormat"`
	Components []cyclonedxComponent `json:"components"`
}

type cyclonedxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

func isCycloneDXSBOMFilename(base string) bool {
	return base == "bom.json" || base == "sbom.json" || strings.HasSuffix(base, ".cdx.json")
}

func validCycloneDXSBOMFile(path string) bool {
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var envelope struct {
		BomFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return false
	}
	if envelope.BomFormat != "CycloneDX" {
		return false
	}
	var doc cyclonedxSBOM
	return json.Unmarshal(body, &doc) == nil
}

func scanCycloneDXSBOM(runID, path string) ([]ScanObservation, []ScanDiagnostic) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "read_error", path, err.Error())}
	}
	var envelope struct {
		BomFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", path, err.Error())}
	}
	if envelope.BomFormat != "CycloneDX" {
		return nil, nil
	}
	var doc cyclonedxSBOM
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, []ScanDiagnostic{scanDiagnostic(runID, "parse_error", path, err.Error())}
	}
	var observations []ScanObservation
	for _, component := range doc.Components {
		ecosystem, name, version, ok := cyclonedxComponentIdentity(component)
		if !ok {
			continue
		}
		observations = append(observations, componentObservation(runID, ecosystem, name, version, "configured", "cyclonedx_sbom", path, "high", false))
	}
	return observations, nil
}

func cyclonedxComponentIdentity(component cyclonedxComponent) (string, string, string, bool) {
	if component.PURL == "" {
		return "", "", "", false
	}
	return scanIdentityFromPackageURL(component.PURL)
}

func scanIdentityFromPackageURL(purl string) (string, string, string, bool) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", "", "", false
	}
	pkgType, rest, ok := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	if !ok || pkgType == "" || rest == "" {
		return "", "", "", false
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	versionAt := strings.LastIndex(rest, "@")
	if versionAt <= 0 || versionAt == len(rest)-1 {
		return "", "", "", false
	}
	name, err := url.PathUnescape(rest[:versionAt])
	if err != nil {
		return "", "", "", false
	}
	version, err := url.PathUnescape(rest[versionAt+1:])
	if err != nil {
		return "", "", "", false
	}
	ecosystem, ok := packageURLEcosystem(pkgType)
	if !ok || !safePackageURLIdentity(ecosystem, name, version) {
		return "", "", "", false
	}
	return ecosystem, name, version, true
}

func packageURLEcosystem(pkgType string) (string, bool) {
	switch strings.ToLower(pkgType) {
	case "npm":
		return "npm", true
	case "pypi":
		return "PyPI", true
	case "brew", "homebrew":
		return "Homebrew", true
	default:
		return "", false
	}
}

func safePackageURLIdentity(ecosystem, name, version string) bool {
	if !safePackageURLValue(name) || !safePackageURLValue(version) {
		return false
	}
	if packageSpecLooksLocalOrRemote(name) || packageSpecLooksLocalOrRemote(version) {
		return false
	}
	if strings.ContainsAny(version, `/\`) {
		return false
	}
	if ecosystem == "npm" && strings.HasPrefix(name, "@") {
		parts := strings.Split(name, "/")
		return len(parts) == 2 && parts[0] != "@" && parts[1] != ""
	}
	return !strings.ContainsAny(name, `/\`)
}

func safePackageURLValue(value string) bool {
	return value != "" &&
		!strings.Contains(value, "..") &&
		!strings.ContainsAny(value, "\x00\r\n\t?#") &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func packageSpecLooksLocalOrRemote(value string) bool {
	spec := ParsePackageSpec(value)
	return spec.LocalPath || spec.DirectURL || spec.VCS
}
