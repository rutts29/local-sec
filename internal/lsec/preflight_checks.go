package lsec

import (
	"context"
	"strings"
	"time"
)

func packageSpecsAsDependencyRefs(ecosystem string, specs []PackageSpec) []DependencyRef {
	refs := make([]DependencyRef, 0, len(specs))
	for _, spec := range specs {
		if spec.Name == "" || spec.Version == "" {
			continue
		}
		refs = append(refs, DependencyRef{Ecosystem: ecosystem, Name: spec.Name, Version: spec.Version, Raw: spec.Raw, Exact: true})
	}
	return refs
}

func checkPackageSpecs(ctx context.Context, store Store, ecosystem string, specs []PackageSpec) ([]Advisory, []Finding) {
	findings := CheckPackageSpecMaturity(ctx, ecosystem, specs, DefaultPolicy().MaturityDays)
	advisories, advisoryFindings := RefreshPackageSpecAdvisories(ctx, store, ecosystem, specs, 30*time.Minute)
	findings = append(findings, advisoryFindings...)
	externalAdvisories, externalFindings := RefreshExternalAdvisories(ctx, packageSpecsAsDependencyRefs(ecosystem, specs))
	advisories = append(advisories, externalAdvisories...)
	findings = append(findings, externalFindings...)
	return advisories, findings
}

func CheckNPMStagedExecutionSupport(analysis CommandAnalysis, version VersionInfo, artifacts []Artifact) []Finding {
	if analysis.Manager != "npm" {
		return nil
	}
	var tarballs []string
	for _, artifact := range artifacts {
		if artifact.Kind != "tar" || artifact.Ecosystem != "npm" {
			continue
		}
		label := artifact.Name
		if label != "" && artifact.Version != "" {
			label += "@" + artifact.Version
		}
		if label == "" {
			label = artifact.Path
		}
		tarballs = append(tarballs, label)
	}
	if len(tarballs) == 0 {
		return nil
	}
	if _, ok := stagedNPMInstallArtifact(analysis, version, artifacts); ok {
		return nil
	}
	code := "npm_staged_execution_unsupported"
	message := "npm staged artifacts cannot yet be promoted into this final npm execution; this run is blocked so approved bytes are not replaced by a registry fetch"
	if analysis.Action == "install" {
		code = "npm_staged_dependency_install_unsupported"
		message = "recursive npm dependencies were scanned, but exact-byte final install is not implemented yet; this run is blocked pending npm cache/store promotion support"
	}
	return []Finding{{
		Code:     code,
		Severity: "block",
		Message:  message,
		Evidence: strings.Join(tarballs, ", "),
	}}
}

func stagedNPMInstallArtifact(analysis CommandAnalysis, version VersionInfo, artifacts []Artifact) (Artifact, bool) {
	if analysis.Manager != "npm" || analysis.Action != "install" || !version.Found || version.Selected.Version == "" || len(artifacts) != 1 || len(analysis.PackageSpecs) == 0 {
		return Artifact{}, false
	}
	if analysis.PackageSpecs[0].Name == "" {
		return Artifact{}, false
	}
	artifact := artifacts[0]
	if artifact.Kind != "tar" || artifact.Ecosystem != "npm" {
		return Artifact{}, false
	}
	if artifact.Name != analysis.PackageSpecs[0].Name || artifact.Version != version.Selected.Version {
		return Artifact{}, false
	}
	return artifact, true
}

func CheckFirstSeenPackages(store Store, ecosystem string, specs []PackageSpec, artifacts []Artifact) []Finding {
	previous, err := store.LoadPackageSummaries(0)
	if err != nil {
		return []Finding{{
			Code:     "package_history_unavailable",
			Severity: "prompt",
			Message:  "local package history could not be checked",
			Evidence: err.Error(),
		}}
	}
	seen := map[string]bool{}
	for _, pkg := range previous {
		seen[dependencyKey(pkg.Ecosystem, pkg.Name, "without-version")] = true
	}
	current := map[string]string{}
	for _, spec := range specs {
		if ecosystem == "" || spec.Name == "" {
			continue
		}
		current[dependencyKey(ecosystem, spec.Name, "without-version")] = ecosystem + " " + spec.Name
	}
	for _, artifact := range artifacts {
		if artifact.Ecosystem == "" || artifact.Name == "" {
			continue
		}
		current[dependencyKey(artifact.Ecosystem, artifact.Name, "without-version")] = artifact.Ecosystem + " " + artifact.Name
	}
	var findings []Finding
	for key, evidence := range current {
		if seen[key] {
			continue
		}
		findings = append(findings, Finding{
			Code:     "first_seen_package",
			Severity: "prompt",
			Message:  "package has not been seen in local-sec history before",
			Evidence: evidence,
		})
	}
	return findings
}

func CheckFirstSeenMaintainers(store Store, ecosystem, name string, current []string) []Finding {
	if ecosystem == "" || name == "" || len(current) == 0 {
		return nil
	}
	previous, err := store.LoadSeenMaintainers(ecosystem, name)
	if err != nil {
		return []Finding{{
			Code:     "maintainer_history_unavailable",
			Severity: "prompt",
			Message:  "local maintainer history could not be checked",
			Evidence: err.Error(),
		}}
	}
	if len(previous) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, maintainer := range previous {
		seen[strings.ToLower(strings.TrimSpace(maintainer))] = true
	}
	var findings []Finding
	for _, maintainer := range current {
		normalized := strings.ToLower(strings.TrimSpace(maintainer))
		if normalized == "" || seen[normalized] {
			continue
		}
		findings = append(findings, Finding{
			Code:     "first_seen_maintainer",
			Severity: "prompt",
			Message:  "package maintainer has not been seen in local-sec history before",
			Evidence: ecosystem + " " + name + " " + normalized,
		})
	}
	return findings
}

func CheckPackageSpecMaturity(ctx context.Context, ecosystem string, specs []PackageSpec, maturityDays int) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	now := time.Now().UTC()
	for _, spec := range specs {
		if ecosystem == "" || spec.Name == "" || spec.Version == "" {
			continue
		}
		key := dependencyKey(ecosystem, spec.Name, spec.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		version, ok := resolvePinnedEcosystemVersion(ctx, ecosystem, spec.Name, spec.Version)
		if !ok || version.PublishedAt.IsZero() {
			findings = append(findings, Finding{
				Code:     "package_publish_time_unverified",
				Severity: "prompt",
				Message:  "package publish time could not be verified",
				Evidence: ecosystem + " " + spec.Name + " " + spec.Version,
			})
			continue
		}
		if version.Yanked || version.Deprecated {
			findings = append(findings, Finding{
				Code:     "package_version_removed",
				Severity: "block",
				Message:  "package version is yanked or deprecated",
				Evidence: ecosystem + " " + spec.Name + " " + spec.Version,
			})
			continue
		}
		if now.Sub(version.PublishedAt) < time.Duration(maturityDays)*24*time.Hour {
			findings = append(findings, Finding{
				Code:     "package_version_inside_maturity_window",
				Severity: "prompt",
				Message:  "package version is inside maturity window",
				Evidence: ecosystem + " " + spec.Name + " " + spec.Version,
			})
		}
	}
	return findings
}

func CheckArtifactMaturity(ctx context.Context, artifacts []Artifact, maturityDays int, skip map[string]bool) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	now := time.Now().UTC()
	for _, artifact := range artifacts {
		if artifact.Ecosystem == "" || artifact.Name == "" || artifact.Version == "" {
			continue
		}
		key := dependencyKey(artifact.Ecosystem, artifact.Name, artifact.Version)
		if skip[key] || seen[key] {
			continue
		}
		seen[key] = true
		version, ok := resolvePinnedEcosystemVersion(ctx, artifact.Ecosystem, artifact.Name, artifact.Version)
		if !ok || version.PublishedAt.IsZero() {
			findings = append(findings, Finding{
				Code:     "artifact_publish_time_unverified",
				Severity: "prompt",
				File:     artifact.Path,
				Message:  "staged artifact publish time could not be verified",
				Evidence: artifact.Ecosystem + " " + artifact.Name + " " + artifact.Version,
			})
			continue
		}
		if version.Yanked || version.Deprecated {
			findings = append(findings, Finding{
				Code:     "artifact_version_removed",
				Severity: "block",
				File:     artifact.Path,
				Message:  "staged artifact version is yanked or deprecated",
				Evidence: artifact.Ecosystem + " " + artifact.Name + " " + artifact.Version,
			})
			continue
		}
		if now.Sub(version.PublishedAt) < time.Duration(maturityDays)*24*time.Hour {
			findings = append(findings, Finding{
				Code:     "artifact_version_inside_maturity_window",
				Severity: "prompt",
				File:     artifact.Path,
				Message:  "staged artifact version is inside maturity window",
				Evidence: artifact.Ecosystem + " " + artifact.Name + " " + artifact.Version,
			})
		}
	}
	return findings
}

func resolvePinnedEcosystemVersion(ctx context.Context, ecosystem, name, requestedVersion string) (RegistryVersion, bool) {
	var versions []RegistryVersion
	var err error
	switch ecosystem {
	case "npm":
		versions, _, err = fetchNPMVersions(ctx, name)
	case "PyPI":
		versions, _, err = fetchPyPIVersions(ctx, name)
	default:
		return RegistryVersion{}, false
	}
	if err != nil {
		return RegistryVersion{}, false
	}
	for _, version := range versions {
		if version.Version == requestedVersion {
			return version, true
		}
	}
	return RegistryVersion{}, false
}

func RefreshArtifactAdvisories(ctx context.Context, store Store, artifacts []Artifact, cacheTTL time.Duration, skip map[string]bool) ([]Advisory, []Finding) {
	var advisories []Advisory
	var findings []Finding
	seen := map[string]bool{}
	for _, artifact := range artifacts {
		if artifact.Ecosystem == "" || artifact.Name == "" || artifact.Version == "" {
			continue
		}
		key := dependencyKey(artifact.Ecosystem, artifact.Name, artifact.Version)
		if skip[key] || seen[key] {
			continue
		}
		seen[key] = true
		found, artifactFindings := RefreshAdvisories(ctx, store, artifact.Ecosystem, artifact.Name, artifact.Version, cacheTTL)
		advisories = append(advisories, found...)
		findings = append(findings, artifactFindings...)
		externalAdvisories, externalFindings := RefreshExternalAdvisories(ctx, []DependencyRef{{
			Ecosystem: artifact.Ecosystem,
			Name:      artifact.Name,
			Version:   artifact.Version,
			Raw:       artifact.Version,
			Exact:     true,
		}})
		advisories = append(advisories, externalAdvisories...)
		findings = append(findings, externalFindings...)
	}
	return advisories, findings
}

func RefreshPackageSpecAdvisories(ctx context.Context, store Store, ecosystem string, specs []PackageSpec, cacheTTL time.Duration) ([]Advisory, []Finding) {
	var advisories []Advisory
	var findings []Finding
	seen := map[string]bool{}
	for _, spec := range specs {
		if spec.Name == "" || spec.Version == "" {
			continue
		}
		key := dependencyKey(ecosystem, spec.Name, spec.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		found, specFindings := RefreshAdvisories(ctx, store, ecosystem, spec.Name, spec.Version, cacheTTL)
		advisories = append(advisories, found...)
		findings = append(findings, specFindings...)
	}
	return advisories, findings
}

func RefreshDependencyAdvisories(ctx context.Context, store Store, artifacts []Artifact, cacheTTL time.Duration) ([]Advisory, []Finding) {
	var advisories []Advisory
	var findings []Finding
	seen := map[string]bool{}
	for _, artifact := range artifacts {
		for _, dep := range artifact.Dependencies {
			if !dep.Exact {
				continue
			}
			key := dependencyKey(dep.Ecosystem, dep.Name, dep.Version)
			if seen[key] {
				continue
			}
			seen[key] = true
			found, depFindings := RefreshAdvisories(ctx, store, dep.Ecosystem, dep.Name, dep.Version, cacheTTL)
			advisories = append(advisories, found...)
			findings = append(findings, depFindings...)
			externalAdvisories, externalFindings := RefreshExternalAdvisories(ctx, []DependencyRef{dep})
			advisories = append(advisories, externalAdvisories...)
			findings = append(findings, externalFindings...)
		}
	}
	return advisories, findings
}

func dependencyKey(ecosystem, name, version string) string {
	return ecosystem + "\x00" + name + "\x00" + version
}

func hasBlockingRiskFlag(analysis CommandAnalysis) bool {
	for _, flag := range analysis.RiskFlags {
		if flag.Severity == "block" {
			return true
		}
	}
	return false
}

func hasBlockingFinding(findings []Finding) bool {
	for _, finding := range findings {
		if finding.Severity == "block" {
			return true
		}
	}
	return false
}

func hasBlockingAdvisory(advisories []Advisory) bool {
	for _, advisory := range advisories {
		if strings.EqualFold(advisory.Type, "malware") || strings.EqualFold(advisory.Severity, "critical") {
			return true
		}
	}
	return false
}
