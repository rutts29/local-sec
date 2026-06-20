package lsec

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}
	if args[0] == "version" || args[0] == "--version" || args[0] == "-v" {
		PrintVersion(stdout)
		return nil
	}
	paths, err := DefaultPaths()
	if err != nil {
		return err
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		return err
	}

	switch args[0] {
	case "guard":
		if len(args) < 2 {
			return errors.New("guard requires a command")
		}
		return runGuard(args[1:], stdin, stdout, stderr, paths, store)
	case "preflight":
		if len(args) < 2 {
			return errors.New("preflight requires a command")
		}
		report, err := preflight(args[1:], paths, store)
		if err != nil {
			return err
		}
		writeReport(stdout, report)
		return store.AppendEvent("preflight", report)
	case "evidence":
		if len(args) < 2 {
			return errors.New("evidence requires a command")
		}
		report, err := preflight(args[1:], paths, store)
		if err != nil {
			return err
		}
		bundle := BuildEvidenceBundle(report)
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(bundle); err != nil {
			return err
		}
		return store.AppendEvent("evidence", bundle)
	case "install-shims":
		return InstallShims(paths, stdout)
	case "doctor":
		return Doctor(paths, stdout)
	case "scan":
		return runScan(args[1:], stdout, paths, store)
	case "status":
		return runStatus(args[1:], stdout, store)
	case "approvals":
		return runApprovals(args[1:], stdout, store)
	case "history":
		return runHistory(args[1:], stdout, store)
	case "packages":
		return runPackages(args[1:], stdout, store)
	case "show":
		return runShow(args[1:], stdout, store)
	default:
		printUsage(stdout)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runGuard(command []string, stdin io.Reader, stdout, stderr io.Writer, paths Paths, store Store) error {
	report, err := preflight(command, paths, store)
	if err != nil {
		return err
	}
	reportOutput := stdout
	if isDownloader(report.Analysis) {
		reportOutput = stderr
	}
	writeReport(reportOutput, report)
	if err := store.AppendEvent("guard_preflight", report); err != nil {
		return err
	}
	if report.Decision.Verdict == VerdictBlock {
		return errors.New("blocked by local-sec policy")
	}
	if isDownloader(report.Analysis) && !stdoutIsTerminalFunc() {
		return errors.New("blocked downloader output to non-terminal; use preflight and download to a file instead")
	}
	approved := false
	if report.Decision.Verdict == VerdictPrompt {
		approved = promptApproval(stdin, reportOutput)
		if !approved {
			return errors.New("not approved")
		}
	}
	if isDownloader(report.Analysis) {
		return streamStagedDownloaderArtifact(report, stdout)
	}
	finalCommand := rewriteCommandForSelectedVersion(command, report)
	return executeRealCommand(finalCommand, stdin, stdout, stderr)
}

func preflight(command []string, paths Paths, store Store) (RunReport, error) {
	now := time.Now().UTC()
	runID := NewRunID(now)
	analysis := Classify(command)
	var findings []Finding
	if !hasBlockingRiskFlag(analysis) && analysis.RequirementsFile {
		specs, requirementFindings := ParseRequirementsFiles(analysis.RequirementFiles)
		analysis.PackageSpecs = specs
		findings = append(findings, requirementFindings...)
	}
	if !hasBlockingRiskFlag(analysis) && analysis.LockfileInstall {
		specs, lockfileFindings := ParseNPMLockfile(analysis.LockfilePath)
		analysis.PackageSpecs = specs
		findings = append(findings, lockfileFindings...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()

	var version VersionInfo
	if !hasBlockingRiskFlag(analysis) && !hasBlockingFinding(findings) && !analysis.RequirementsFile && !analysis.LockfileInstall {
		version = ResolveVersion(ctx, analysis, DefaultPolicy().MaturityDays)
	}
	ecosystem := ecosystemForManager(analysis.Manager)
	var advisories []Advisory
	topLevelAdvisoryChecked := false
	packageSpecsAdvisoryChecked := false
	if !hasBlockingRiskFlag(analysis) && !hasBlockingFinding(findings) && !analysis.RequirementsFile && !analysis.LockfileInstall && len(analysis.PackageSpecs) > 0 && version.Selected.Version != "" {
		var versionAdvisories []Advisory
		var versionFindings []Finding
		version, versionAdvisories, versionFindings = FollowAdvisoryCleanCandidate(ctx, store, ecosystem, analysis.PackageSpecs[0].Name, version, 30*time.Minute, DefaultPolicy().MaturityDays)
		version.Maintainers = FetchPackageMaintainers(ctx, ecosystem, analysis.PackageSpecs[0].Name)
		advisories = append(advisories, versionAdvisories...)
		findings = append(findings, versionFindings...)
		topLevelAdvisoryChecked = true
	}
	if !hasBlockingRiskFlag(analysis) && !hasBlockingFinding(findings) && !hasBlockingAdvisory(advisories) && (analysis.RequirementsFile || analysis.LockfileInstall) {
		findings = append(findings, CheckPackageSpecMaturity(ctx, ecosystem, analysis.PackageSpecs, DefaultPolicy().MaturityDays)...)
		specAdvisories, specFindings := RefreshPackageSpecAdvisories(ctx, store, ecosystem, analysis.PackageSpecs, 30*time.Minute)
		advisories = append(advisories, specAdvisories...)
		findings = append(findings, specFindings...)
		externalAdvisories, externalFindings := RefreshExternalAdvisories(ctx, packageSpecsAsDependencyRefs(ecosystem, analysis.PackageSpecs))
		advisories = append(advisories, externalAdvisories...)
		findings = append(findings, externalFindings...)
		packageSpecsAdvisoryChecked = true
	}
	staging := filepath.Join(paths.Staging, runID)
	var artifacts []Artifact
	if !hasBlockingRiskFlag(analysis) && !hasBlockingFinding(findings) && !hasBlockingAdvisory(advisories) && !analysis.LockfileInstall {
		var stageFindings []Finding
		artifacts, stageFindings = StageArtifacts(ctx, staging, analysis, version)
		findings = append(findings, stageFindings...)
	}
	if !hasBlockingRiskFlag(analysis) && !hasBlockingFinding(findings) && len(artifacts) > 0 {
		skip := map[string]bool{}
		if topLevelAdvisoryChecked && len(analysis.PackageSpecs) > 0 && version.Selected.Version != "" {
			skip[dependencyKey(ecosystem, analysis.PackageSpecs[0].Name, version.Selected.Version)] = true
		}
		findings = append(findings, CheckArtifactMaturity(ctx, artifacts, DefaultPolicy().MaturityDays, skip)...)
		artifactAdvisories, artifactFindings := RefreshArtifactAdvisories(ctx, store, artifacts, 30*time.Minute, skip)
		advisories = append(advisories, artifactAdvisories...)
		findings = append(findings, artifactFindings...)
	}
	if !hasBlockingRiskFlag(analysis) && !analysis.RequirementsFile && !analysis.LockfileInstall && len(artifacts) > 0 {
		dependencyAdvisories, dependencyFindings := RefreshDependencyAdvisories(ctx, store, artifacts, 30*time.Minute)
		advisories = append(advisories, dependencyAdvisories...)
		findings = append(findings, dependencyFindings...)
	}
	if !hasBlockingRiskFlag(analysis) && !hasBlockingFinding(findings) && (analysis.RequirementsFile || analysis.LockfileInstall) {
		if !packageSpecsAdvisoryChecked {
			findings = append(findings, CheckPackageSpecMaturity(ctx, ecosystem, analysis.PackageSpecs, DefaultPolicy().MaturityDays)...)
			specAdvisories, specFindings := RefreshPackageSpecAdvisories(ctx, store, ecosystem, analysis.PackageSpecs, 30*time.Minute)
			advisories = append(advisories, specAdvisories...)
			findings = append(findings, specFindings...)
			externalAdvisories, externalFindings := RefreshExternalAdvisories(ctx, packageSpecsAsDependencyRefs(ecosystem, analysis.PackageSpecs))
			advisories = append(advisories, externalAdvisories...)
			findings = append(findings, externalFindings...)
		}
		if len(artifacts) > 0 {
			dependencyAdvisories, dependencyFindings := RefreshDependencyAdvisories(ctx, store, artifacts, 30*time.Minute)
			advisories = append(advisories, dependencyAdvisories...)
			findings = append(findings, dependencyFindings...)
		}
	} else if !topLevelAdvisoryChecked && !hasBlockingRiskFlag(analysis) && !hasBlockingFinding(findings) && len(analysis.PackageSpecs) > 0 && version.Selected.Version != "" {
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
	if !hasBlockingRiskFlag(analysis) && !hasBlockingFinding(findings) && !hasBlockingAdvisory(advisories) {
		findings = append(findings, CheckFirstSeenPackages(store, ecosystem, analysis.PackageSpecs, artifacts)...)
		if len(analysis.PackageSpecs) > 0 {
			findings = append(findings, CheckFirstSeenMaintainers(store, ecosystem, analysis.PackageSpecs[0].Name, version.Maintainers)...)
		}
	}
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

func isDownloader(analysis CommandAnalysis) bool {
	return analysis.Manager == "curl" || analysis.Manager == "wget"
}

func streamStagedDownloaderArtifact(report RunReport, stdout io.Writer) error {
	if len(report.Artifacts) != 1 {
		return errors.New("downloader guard requires exactly one staged artifact")
	}
	f, err := os.Open(report.Artifacts[0].Path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(stdout, f)
	return err
}

func rewriteCommandForSelectedVersion(command []string, report RunReport) []string {
	if report.Analysis.LockfileInstall {
		return []string{command[0], "ci", "--ignore-scripts"}
	}
	if report.Analysis.Manager == "npm" && report.Analysis.Action == "init" {
		if rewritten, ok := rewriteNPMInitCommand(command, report); ok {
			return rewritten
		}
	}
	if report.Analysis.RequirementsFile {
		if rewritten, ok := rewritePipRequirementsCommand(command, report); ok {
			return rewritten
		}
	}
	if !report.Version.Found || report.Version.Selected.Version == "" || len(report.Analysis.PackageSpecs) == 0 {
		return command
	}
	selected := report.Analysis.PackageSpecs[0].Name
	if selected == "" {
		return command
	}
	if staged, ok := stagedInstallSpec(report); ok {
		selected = staged
	} else {
		switch report.Analysis.Manager {
		case "npm", "npx":
			selected += "@" + report.Version.Selected.Version
		case "pip", "pip3", "uv", "uvx", "pipx":
			selected += "==" + report.Version.Selected.Version
		default:
			return command
		}
	}
	out := append([]string(nil), command...)
	for i, arg := range out {
		if arg == report.Analysis.PackageSpecs[0].Raw {
			out[i] = selected
			break
		}
		if strings.HasPrefix(arg, "--package=") && strings.TrimPrefix(arg, "--package=") == report.Analysis.PackageSpecs[0].Raw {
			out[i] = "--package=" + selected
			break
		}
		if strings.HasPrefix(arg, "--from=") && strings.TrimPrefix(arg, "--from=") == report.Analysis.PackageSpecs[0].Raw {
			out[i] = "--from=" + selected
			break
		}
		if strings.HasPrefix(arg, "--spec=") && strings.TrimPrefix(arg, "--spec=") == report.Analysis.PackageSpecs[0].Raw {
			out[i] = "--spec=" + selected
			break
		}
	}
	if report.Analysis.Manager == "npm" && report.Analysis.Action == "install" {
		out = appendIfMissing(out, "--ignore-scripts")
	}
	if (report.Analysis.Manager == "pip" || report.Analysis.Manager == "pip3") && report.Analysis.Action == "install" {
		if dir, ok := pipWheelhouseDir(report); ok && len(report.Artifacts) > 1 {
			out = insertPipInstallFlags(out, report.Analysis, []string{"--no-index", "--find-links", dir})
		} else {
			out = insertPipInstallFlags(out, report.Analysis, []string{"--no-index", "--no-deps"})
		}
	}
	return out
}

func appendIfMissing(args []string, value string) []string {
	if stringSliceHas(args, value) {
		return args
	}
	return append(args, value)
}

func stringSliceHas(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func rewriteNPMInitCommand(command []string, report RunReport) ([]string, bool) {
	if !report.Version.Found || report.Version.Selected.Version == "" || len(report.Analysis.PackageSpecs) == 0 {
		return nil, false
	}
	selected := report.Analysis.PackageSpecs[0].Name
	if selected == "" {
		return nil, false
	}
	selected += "@" + report.Version.Selected.Version
	out := []string{command[0], "exec", selected}
	for i := 2; i < len(command); i++ {
		if command[i] == report.Analysis.PackageSpecs[0].Raw {
			out = append(out, command[i+1:]...)
			return out, true
		}
	}
	return nil, false
}

func rewritePipRequirementsCommand(command []string, report RunReport) ([]string, bool) {
	if report.Analysis.Manager != "pip" && report.Analysis.Manager != "pip3" {
		return nil, false
	}
	if len(report.Artifacts) == 0 {
		return nil, false
	}
	dir := filepath.Dir(report.Artifacts[0].Path)
	if dir == "." || dir == "" {
		return nil, false
	}
	out := append([]string(nil), command...)
	insert := pipInstallArgIndex(out, report.Analysis)
	if insert < 0 {
		return nil, false
	}
	flags := []string{"--require-hashes", "--no-index", "--find-links", dir}
	out = append(out[:insert], append(flags, out[insert:]...)...)
	return out, true
}

func insertPipInstallFlags(command []string, analysis CommandAnalysis, flags []string) []string {
	insert := pipInstallArgIndex(command, analysis)
	if insert < 0 {
		return command
	}
	out := append([]string(nil), command...)
	for i := len(flags) - 1; i >= 0; i-- {
		if stringSliceHas(out, flags[i]) {
			continue
		}
		out = append(out[:insert], append([]string{flags[i]}, out[insert:]...)...)
	}
	return out
}

func pipInstallArgIndex(command []string, analysis CommandAnalysis) int {
	if analysis.PythonModulePip || isPythonPip(command) {
		for i := 0; i < len(command); i++ {
			if command[i] == "install" {
				return i + 1
			}
		}
		return -1
	}
	if len(command) >= 2 && command[1] == "install" {
		return 2
	}
	return -1
}

func stagedInstallSpec(report RunReport) (string, bool) {
	if len(report.Artifacts) != 1 {
		return "", false
	}
	artifact := report.Artifacts[0]
	switch report.Analysis.Manager {
	case "npm":
		if artifact.Kind == "tar" {
			return artifact.Path, true
		}
	case "pip", "pip3":
		if artifact.Kind == "wheel" {
			return artifact.Path, true
		}
	}
	return "", false
}

func pipWheelhouseDir(report RunReport) (string, bool) {
	if len(report.Artifacts) == 0 {
		return "", false
	}
	dir := filepath.Dir(report.Artifacts[0].Path)
	if dir == "." || dir == "" {
		return "", false
	}
	for _, artifact := range report.Artifacts {
		if artifact.Kind != "wheel" || filepath.Dir(artifact.Path) != dir {
			return "", false
		}
	}
	return dir, true
}

func executeRealCommand(command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(command) == 0 {
		return errors.New("empty command")
	}
	realPath, err := findRealExecutable(command[0])
	if err != nil {
		return err
	}
	cmd := exec.Command(realPath, command[1:]...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func findRealExecutable(name string) (string, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return name, nil
	}
	shimDir := os.Getenv("LSEC_SHIM_DIR")
	if shimDir == "" {
		if paths, err := DefaultPaths(); err == nil {
			shimDir = paths.Bin
		}
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if shimDir != "" && filepath.Clean(dir) == filepath.Clean(shimDir) {
			continue
		}
		candidate := filepath.Join(dir, name)
		if pointsIntoShimDir(candidate, shimDir) {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("real executable for %s not found after excluding shim dir", name)
}

func pointsIntoShimDir(candidate, shimDir string) bool {
	if shimDir == "" {
		return false
	}
	info, err := os.Lstat(candidate)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return false
	}
	cleanShimDir, err := filepath.EvalSymlinks(shimDir)
	if err != nil {
		cleanShimDir = filepath.Clean(shimDir)
	}
	rel, err := filepath.Rel(filepath.Clean(cleanShimDir), filepath.Clean(target))
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != "..")
}

func promptApproval(stdin io.Reader, stdout io.Writer) bool {
	fmt.Fprintln(stdout, "Type 'yes' to approve this run once:")
	scanner := bufio.NewScanner(stdin)
	if !scanner.Scan() {
		return false
	}
	return strings.TrimSpace(scanner.Text()) == "yes"
}

func writeReport(w io.Writer, report RunReport) {
	fmt.Fprintf(w, "local-sec run %s\n", report.RunID)
	fmt.Fprintf(w, "command: %s\n", strings.Join(report.Analysis.Raw, " "))
	fmt.Fprintf(w, "verdict: %s\n", report.Decision.Verdict)
	fmt.Fprintf(w, "lane: %s\n", report.Decision.Lane)
	for _, reason := range report.Decision.Reasons {
		fmt.Fprintf(w, "- %s\n", reason)
	}
	if report.Version.Found {
		fmt.Fprintf(w, "selected version: %s\n", report.Version.Selected.Version)
		if report.Version.MatureCandidateSelected {
			fmt.Fprintf(w, "latest skipped: %s\n", report.Version.Latest.Version)
		}
		for _, skipped := range report.Version.Skipped {
			fmt.Fprintf(w, "skipped version: %s (%s", skipped.Version, skipped.Reason)
			if len(skipped.AdvisoryIDs) > 0 {
				fmt.Fprintf(w, ": %s", strings.Join(skipped.AdvisoryIDs, ","))
			}
			fmt.Fprintln(w, ")")
		}
	}
	for _, artifact := range report.Artifacts {
		fmt.Fprintf(w, "artifact[%s]: %s %s\n", artifact.Kind, artifact.SHA256, artifact.Path)
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "finding[%s]: %s %s\n", finding.Severity, finding.Code, finding.File)
	}
}

func runApprovals(args []string, stdout io.Writer, store Store) error {
	if len(args) == 0 {
		return errors.New("approvals requires list, add, or revoke")
	}
	switch args[0] {
	case "list":
		approvals, err := store.LoadApprovals()
		if err != nil {
			return err
		}
		body, _ := json.MarshalIndent(approvals, "", "  ")
		fmt.Fprintln(stdout, string(body))
		return nil
	case "add":
		if len(args) < 5 {
			return errors.New("approvals add requires ecosystem name version sha256 [reason]")
		}
		if strings.TrimSpace(args[4]) == "" {
			return errors.New("approvals add requires a non-empty sha256")
		}
		if !validSHA256Hex(args[4]) {
			return errors.New("approvals add requires a 64-character lowercase hex sha256")
		}
		reason := "manual approval"
		if len(args) > 5 {
			reason = strings.Join(args[5:], " ")
		}
		return store.AddApproval(Approval{Ecosystem: args[1], Name: args[2], Version: args[3], Hash: args[4], Reason: reason})
	case "revoke":
		if len(args) != 4 && len(args) != 5 {
			return errors.New("approvals revoke requires ecosystem name version [sha256]")
		}
		hash := ""
		if len(args) == 5 {
			if !validSHA256Hex(args[4]) {
				return errors.New("approvals revoke requires a 64-character lowercase hex sha256 when hash is provided")
			}
			hash = args[4]
		}
		return store.RevokeApproval(args[1], args[2], args[3], hash)
	case "suggest":
		if len(args) != 2 {
			return errors.New("approvals suggest requires run_id")
		}
		return runApprovalSuggestions(args[1], stdout, store)
	default:
		return fmt.Errorf("unknown approvals command %q", args[0])
	}
}

func runApprovalSuggestions(runID string, stdout io.Writer, store Store) error {
	report, ok, err := store.LoadRunReport(runID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("run %q not found", runID)
	}
	if report.Decision.Verdict == VerdictBlock {
		return fmt.Errorf("run %q is blocked and cannot be approved", runID)
	}
	wrote := false
	for _, artifact := range report.Artifacts {
		if artifact.Ecosystem == "" || artifact.Name == "" || artifact.Version == "" || artifact.SHA256 == "" {
			continue
		}
		fmt.Fprintf(stdout, "lsec approvals add %s %s %s %s reviewed-%s\n", artifact.Ecosystem, artifact.Name, artifact.Version, artifact.SHA256, runID)
		wrote = true
	}
	if !wrote {
		return fmt.Errorf("run %q has no exact approvable artifacts", runID)
	}
	return nil
}

func runHistory(args []string, stdout io.Writer, store Store) error {
	limit := 20
	if len(args) > 1 {
		return errors.New("history accepts optional limit")
	}
	if len(args) == 1 {
		var parsed int
		if _, err := fmt.Sscanf(args[0], "%d", &parsed); err != nil || parsed < 1 {
			return errors.New("history limit must be a positive integer")
		}
		limit = parsed
	}
	events, err := store.LoadEventSummaries(limit)
	if err != nil {
		return err
	}
	for _, event := range events {
		created := ""
		if !event.CreatedAt.IsZero() {
			created = event.CreatedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n", created, event.Kind, event.RunID, event.Verdict, event.Lane, event.Command)
	}
	return nil
}

func runStatus(args []string, stdout io.Writer, store Store) error {
	if len(args) != 0 {
		return errors.New("status does not accept arguments")
	}
	status, err := store.LoadStatus()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "runs: %d\n", status.Runs)
	fmt.Fprintf(stdout, "packages: %d\n", status.Packages)
	fmt.Fprintf(stdout, "approvals: %d\n", status.Approvals)
	fmt.Fprintf(stdout, "approved_packages: %d\n", status.ApprovedPackages)
	for _, verdict := range []Verdict{VerdictAllow, VerdictPrompt, VerdictBlock} {
		fmt.Fprintf(stdout, "verdict[%s]: %d\n", verdict, status.Verdicts[verdict])
	}
	for _, lane := range []RiskLane{LaneTrusted, LaneRisky, LaneBlock} {
		fmt.Fprintf(stdout, "lane[%s]: %d\n", lane, status.Lanes[lane])
	}
	return nil
}

func runPackages(args []string, stdout io.Writer, store Store) error {
	limit := 50
	if len(args) > 1 {
		return errors.New("packages accepts optional limit")
	}
	if len(args) == 1 {
		var parsed int
		if _, err := fmt.Sscanf(args[0], "%d", &parsed); err != nil || parsed < 1 {
			return errors.New("packages limit must be a positive integer")
		}
		limit = parsed
	}
	packages, err := store.LoadPackageSummaries(limit)
	if err != nil {
		return err
	}
	for _, pkg := range packages {
		status := "unapproved"
		if pkg.Approved {
			status = "approved"
		}
		seen := ""
		if !pkg.SeenAt.IsZero() {
			seen = pkg.SeenAt.Format(time.RFC3339)
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", seen, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Hash, pkg.Verdict, pkg.Lane, status, pkg.RunID)
	}
	return nil
}

func runShow(args []string, stdout io.Writer, store Store) error {
	if len(args) != 1 {
		return errors.New("show requires run_id")
	}
	report, ok, err := store.LoadRunReport(args[0])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("run %q not found", args[0])
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  lsec guard <command> ...")
	fmt.Fprintln(w, "  lsec preflight <command> ...")
	fmt.Fprintln(w, "  lsec evidence <command> ...")
	fmt.Fprintln(w, "  lsec status")
	fmt.Fprintln(w, "  lsec history [limit]")
	fmt.Fprintln(w, "  lsec packages [limit]")
	fmt.Fprintln(w, "  lsec show <run_id>")
	fmt.Fprintln(w, "  lsec scan --profile baseline|project|deep [--root PATH] [--network off|advisories] [--format table|json|ndjson] [--findings-only] [--redact-paths home|all|hash]")
	fmt.Fprintln(w, "  lsec install-shims")
	fmt.Fprintln(w, "  lsec doctor")
	fmt.Fprintln(w, "  lsec approvals list|add|revoke|suggest")
	fmt.Fprintln(w, "  lsec version")
}

func stdoutIsTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

var stdoutIsTerminalFunc = stdoutIsTerminal
