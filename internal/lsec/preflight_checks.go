package lsec

import (
	"context"
	"path/filepath"
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
	tarballs := npmStagedTarballs(artifacts)
	if len(tarballs) == 0 {
		return nil
	}
	if canPromoteNPMStagedInstall(analysis, version, artifacts) {
		return nil
	}
	labels := make([]string, 0, len(tarballs))
	for _, artifact := range tarballs {
		label := artifact.Name
		if label != "" && artifact.Version != "" {
			label += "@" + artifact.Version
		}
		if label == "" {
			label = artifact.Path
		}
		labels = append(labels, label)
	}
	code := "npm_staged_execution_unsupported"
	message := "npm staged artifacts cannot be promoted into this final npm execution; this run is blocked so approved bytes are not replaced by a registry fetch"
	if analysis.Action == "install" {
		code = "npm_staged_dependency_install_unsupported"
		message = "staged npm tarballs cannot be promoted into an exact-byte offline install for this command"
	}
	return []Finding{{
		Code:     code,
		Severity: "block",
		Message:  message,
		Evidence: strings.Join(labels, ", "),
	}}
}

func canPromoteNPMStagedInstall(analysis CommandAnalysis, version VersionInfo, artifacts []Artifact) bool {
	if !npmActionSupportsExactBytePromotion(analysis) || !version.Found || version.Selected.Version == "" || len(analysis.PackageSpecs) == 0 {
		return false
	}
	selectedName := analysis.PackageSpecs[0].Name
	if selectedName == "" {
		return false
	}
	tarballs := npmStagedTarballs(artifacts)
	if len(tarballs) == 0 {
		return false
	}
	if _, ok := npmStagingDirFromArtifacts(artifacts); !ok {
		return false
	}
	for _, artifact := range tarballs {
		if artifact.Name == selectedName && artifact.Version == version.Selected.Version {
			return true
		}
	}
	return false
}

func npmActionSupportsExactBytePromotion(analysis CommandAnalysis) bool {
	switch analysis.Manager {
	case "npm":
		switch analysis.Action {
		case "install", "exec", "init":
			return true
		}
	case "npx":
		return analysis.Action == "exec" || analysis.OneShot
	}
	return false
}

func stagedNPMInstallArtifact(analysis CommandAnalysis, version VersionInfo, artifacts []Artifact) (Artifact, bool) {
	if !canPromoteNPMStagedInstall(analysis, version, artifacts) {
		return Artifact{}, false
	}
	// Single-tarball file install is only safe for classic npm install roots.
	if analysis.Manager != "npm" || analysis.Action != "install" {
		return Artifact{}, false
	}
	tarballs := npmStagedTarballs(artifacts)
	if len(tarballs) != 1 {
		return Artifact{}, false
	}
	return tarballs[0], true
}

func npmStagedTarballs(artifacts []Artifact) []Artifact {
	out := make([]Artifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Kind != "tar" || artifact.Ecosystem != "npm" || artifact.Name == "" || artifact.Version == "" || artifact.Path == "" {
			continue
		}
		out = append(out, artifact)
	}
	return out
}

func npmStagingDirFromArtifacts(artifacts []Artifact) (string, bool) {
	tarballs := npmStagedTarballs(artifacts)
	if len(tarballs) == 0 {
		return "", false
	}
	dir := filepath.Dir(tarballs[0].Path)
	if dir == "." || dir == "" {
		return "", false
	}
	for _, artifact := range tarballs {
		if filepath.Dir(artifact.Path) != dir {
			return "", false
		}
	}
	return dir, true
}

func npmOfflineCacheDir(artifacts []Artifact) (string, bool) {
	dir, ok := npmStagingDirFromArtifacts(artifacts)
	if !ok {
		return "", false
	}
	return filepath.Join(dir, "npm-offline-cache"), true
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
