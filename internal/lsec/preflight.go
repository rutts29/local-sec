package lsec

import (
	"context"
	"path/filepath"
	"time"
)

type preflightStatus struct {
	analysis   *CommandAnalysis
	findings   *[]Finding
	advisories *[]Advisory
}

func (s preflightStatus) noBlockingRisk() bool {
	return !hasBlockingRiskFlag(*s.analysis)
}

func (s preflightStatus) noBlockingRiskOrFinding() bool {
	return s.noBlockingRisk() && !hasBlockingFinding(*s.findings)
}

func (s preflightStatus) noBlockingRiskFindingOrAdvisory() bool {
	return s.noBlockingRiskOrFinding() && !hasBlockingAdvisory(*s.advisories)
}

func preflight(command []string, paths Paths, store Store) (RunReport, error) {
	now := time.Now().UTC()
	runID := NewRunID(now)
	analysis := Classify(command)
	var findings []Finding
	var advisories []Advisory
	status := preflightStatus{analysis: &analysis, findings: &findings, advisories: &advisories}

	if status.noBlockingRisk() && analysis.RequirementsFile {
		specs, requirementFindings := ParseRequirementsFiles(analysis.RequirementFiles)
		analysis.PackageSpecs = specs
		findings = append(findings, requirementFindings...)
	}
	if status.noBlockingRisk() && analysis.LockfileInstall {
		specs, lockfileFindings := ParseNPMLockfile(analysis.LockfilePath)
		analysis.PackageSpecs = specs
		findings = append(findings, lockfileFindings...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()

	var version VersionInfo
	if status.noBlockingRiskOrFinding() && !analysis.RequirementsFile && !analysis.LockfileInstall {
		version = ResolveVersion(ctx, analysis, DefaultPolicy().MaturityDays)
	}
	ecosystem := ecosystemForManager(analysis.Manager)
	topLevelAdvisoryChecked := false
	packageSpecsAdvisoryChecked := false
	if status.noBlockingRiskOrFinding() && !analysis.RequirementsFile && !analysis.LockfileInstall && len(analysis.PackageSpecs) > 0 && version.Selected.Version != "" {
		var versionAdvisories []Advisory
		var versionFindings []Finding
		version, versionAdvisories, versionFindings = FollowAdvisoryCleanCandidate(ctx, store, ecosystem, analysis.PackageSpecs[0].Name, version, 30*time.Minute, DefaultPolicy().MaturityDays)
		version.Maintainers = FetchPackageMaintainers(ctx, ecosystem, analysis.PackageSpecs[0].Name)
		advisories = append(advisories, versionAdvisories...)
		findings = append(findings, versionFindings...)
		topLevelAdvisoryChecked = true
	}
	if status.noBlockingRiskFindingOrAdvisory() && (analysis.RequirementsFile || analysis.LockfileInstall) {
		specAdvisories, specFindings := checkPackageSpecs(ctx, store, ecosystem, analysis.PackageSpecs)
		advisories = append(advisories, specAdvisories...)
		findings = append(findings, specFindings...)
		packageSpecsAdvisoryChecked = true
	}
	staging := filepath.Join(paths.Staging, runID)
	var artifacts []Artifact
	if status.noBlockingRiskFindingOrAdvisory() && !analysis.LockfileInstall {
		var stageFindings []Finding
		artifacts, stageFindings = StageArtifacts(ctx, staging, analysis, version)
		findings = append(findings, stageFindings...)
	}
	if status.noBlockingRiskOrFinding() && len(artifacts) > 0 {
		skip := map[string]bool{}
		if topLevelAdvisoryChecked && len(analysis.PackageSpecs) > 0 && version.Selected.Version != "" {
			skip[dependencyKey(ecosystem, analysis.PackageSpecs[0].Name, version.Selected.Version)] = true
		}
		findings = append(findings, CheckArtifactMaturity(ctx, artifacts, DefaultPolicy().MaturityDays, skip)...)
		artifactAdvisories, artifactFindings := RefreshArtifactAdvisories(ctx, store, artifacts, 30*time.Minute, skip)
		advisories = append(advisories, artifactAdvisories...)
		findings = append(findings, artifactFindings...)
	}
	if status.noBlockingRisk() && !analysis.RequirementsFile && !analysis.LockfileInstall && len(artifacts) > 0 {
		dependencyAdvisories, dependencyFindings := RefreshDependencyAdvisories(ctx, store, artifacts, 30*time.Minute)
		advisories = append(advisories, dependencyAdvisories...)
		findings = append(findings, dependencyFindings...)
	}
	if status.noBlockingRiskOrFinding() && (analysis.RequirementsFile || analysis.LockfileInstall) {
		if !packageSpecsAdvisoryChecked {
			specAdvisories, specFindings := checkPackageSpecs(ctx, store, ecosystem, analysis.PackageSpecs)
			advisories = append(advisories, specAdvisories...)
			findings = append(findings, specFindings...)
		}
		if len(artifacts) > 0 {
			dependencyAdvisories, dependencyFindings := RefreshDependencyAdvisories(ctx, store, artifacts, 30*time.Minute)
			advisories = append(advisories, dependencyAdvisories...)
			findings = append(findings, dependencyFindings...)
		}
	} else if !topLevelAdvisoryChecked && status.noBlockingRiskOrFinding() && len(analysis.PackageSpecs) > 0 && version.Selected.Version != "" {
		topLevelAdvisories, advisoryFindings := RefreshAdvisories(ctx, store, ecosystem, analysis.PackageSpecs[0].Name, version.Selected.Version, 30*time.Minute)
		advisories = append(advisories, topLevelAdvisories...)
		findings = append(findings, advisoryFindings...)
		externalAdvisories, externalFindings := RefreshExternalAdvisories(ctx, []DependencyRef{{Ecosystem: ecosystem, Name: analysis.PackageSpecs[0].Name, Version: version.Selected.Version, Raw: version.Selected.Version, Exact: true}})
		advisories = append(advisories, externalAdvisories...)
		findings = append(findings, externalFindings...)
		dependencyAdvisories, dependencyFindings := RefreshDependencyAdvisories(ctx, store, artifacts, 30*time.Minute)
		advisories = append(advisories, dependencyAdvisories...)
		findings = append(findings, dependencyFindings...)
	}
	if status.noBlockingRiskFindingOrAdvisory() {
		findings = append(findings, CheckLocalReputation(store, ecosystem, analysis, version, artifacts)...)
	}
	findings = append(findings, CheckNPMStagedExecutionSupport(analysis, version, artifacts)...)
	decision := DefaultPolicy().Evaluate(analysis, version, findings, advisories)
	if decision.Verdict != VerdictBlock && len(artifacts) > 0 {
		approvals, err := store.LoadApprovals()
		if err == nil && ArtifactsApproved(approvals, artifacts) {
			decision = decisionWithLane(VerdictAllow, []string{"all staged artifact package/version/hash records are allowlisted"})
		}
	}
	return RunReport{
		RunID: runID, Analysis: analysis, Version: version, Artifacts: artifacts,
		Findings: findings, Advisories: advisories, Decision: decision, CreatedAt: now,
	}, nil
}
