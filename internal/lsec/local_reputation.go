package lsec

import (
	"sort"
	"strings"
)

type localReputationTarget struct {
	Ecosystem   string
	Name        string
	Versions    map[string]bool
	Hashes      map[string]map[string]bool
	Maintainers []string
}

func CheckLocalReputation(store Store, ecosystem string, analysis CommandAnalysis, version VersionInfo, artifacts []Artifact) []Finding {
	targets := localReputationTargets(ecosystem, analysis, version, artifacts)
	var findings []Finding
	emitted := map[string]bool{}
	for _, target := range targets {
		history, err := store.LoadLocalPackageHistory(target.Ecosystem, target.Name)
		if err != nil {
			appendUniqueFinding(&findings, emitted, Finding{
				Code:     "package_history_unavailable",
				Severity: "prompt",
				Message:  "local package history could not be checked",
				Evidence: packageEvidence(target.Ecosystem, target.Name, ""),
			})
			continue
		}
		if !history.PackageSeen {
			appendUniqueFinding(&findings, emitted, Finding{
				Code:     "first_seen_package",
				Severity: "prompt",
				Message:  "package has not been seen in local-sec history before",
				Evidence: packageEvidence(target.Ecosystem, target.Name, ""),
			})
			continue
		}
		for currentVersion := range target.Versions {
			if currentVersion == "" || history.VersionSeen(currentVersion) {
				continue
			}
			appendUniqueFinding(&findings, emitted, Finding{
				Code:     "first_seen_package_version",
				Severity: "prompt",
				Message:  "package version has not been seen in local-sec history before",
				Evidence: packageEvidence(target.Ecosystem, target.Name, currentVersion),
			})
		}
		for currentVersion, hashes := range target.Hashes {
			if currentVersion == "" || !history.VersionSeen(currentVersion) || len(history.HashesForVersion(currentVersion)) == 0 {
				continue
			}
			for hash := range hashes {
				if hash == "" || history.HashSeen(currentVersion, hash) {
					continue
				}
				appendUniqueFinding(&findings, emitted, Finding{
					Code:     "artifact_hash_drift",
					Severity: "prompt",
					Message:  "staged artifact hash differs from local-sec history for this package version",
					Evidence: packageEvidence(target.Ecosystem, target.Name, currentVersion) + " " + hash,
				})
			}
		}
		findings = append(findings, localMaintainerReputationFindings(target, history, emitted)...)
	}
	return findings
}

func localMaintainerReputationFindings(target localReputationTarget, history LocalPackageHistory, emitted map[string]bool) []Finding {
	if len(target.Maintainers) == 0 || len(history.Maintainers) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, maintainer := range history.Maintainers {
		seen[normalizeMaintainer(maintainer)] = true
	}
	var newMaintainers []string
	var findings []Finding
	for _, maintainer := range target.Maintainers {
		normalized := normalizeMaintainer(maintainer)
		if normalized == "" || seen[normalized] {
			continue
		}
		newMaintainers = append(newMaintainers, normalized)
		appendUniqueFinding(&findings, emitted, Finding{
			Code:     "first_seen_maintainer",
			Severity: "prompt",
			Message:  "package maintainer has not been seen in local-sec history before",
			Evidence: packageEvidence(target.Ecosystem, target.Name, "") + " " + normalized,
		})
	}
	if len(newMaintainers) == 0 {
		return findings
	}
	sort.Strings(newMaintainers)
	appendUniqueFinding(&findings, emitted, Finding{
		Code:     "ownership_drift",
		Severity: "prompt",
		Message:  "package ownership differs from local-sec history",
		Evidence: packageEvidence(target.Ecosystem, target.Name, "") + " new=" + strings.Join(newMaintainers, ",") + " previous=" + strings.Join(history.Maintainers, ","),
	})
	return findings
}

func localReputationTargets(ecosystem string, analysis CommandAnalysis, version VersionInfo, artifacts []Artifact) []localReputationTarget {
	targetsByKey := map[string]*localReputationTarget{}
	for i, spec := range analysis.PackageSpecs {
		if ecosystem == "" || spec.Name == "" {
			continue
		}
		currentVersion := spec.Version
		if currentVersion == "" && i == 0 {
			currentVersion = version.Selected.Version
		}
		target := ensureLocalReputationTarget(targetsByKey, ecosystem, spec.Name)
		if currentVersion != "" {
			target.Versions[currentVersion] = true
		}
		if i == 0 {
			target.Maintainers = append(target.Maintainers, version.Maintainers...)
		}
	}
	for _, artifact := range artifacts {
		if artifact.Ecosystem == "" || artifact.Name == "" {
			continue
		}
		target := ensureLocalReputationTarget(targetsByKey, artifact.Ecosystem, artifact.Name)
		if artifact.Version != "" {
			target.Versions[artifact.Version] = true
			if target.Hashes[artifact.Version] == nil {
				target.Hashes[artifact.Version] = map[string]bool{}
			}
			if artifact.SHA256 != "" {
				target.Hashes[artifact.Version][artifact.SHA256] = true
			}
		}
	}
	var targets []localReputationTarget
	for _, target := range targetsByKey {
		target.Maintainers = uniqueNormalizedStrings(target.Maintainers)
		targets = append(targets, *target)
	}
	sort.Slice(targets, func(i, j int) bool {
		return packageEvidence(targets[i].Ecosystem, targets[i].Name, "") < packageEvidence(targets[j].Ecosystem, targets[j].Name, "")
	})
	return targets
}

func ensureLocalReputationTarget(targets map[string]*localReputationTarget, ecosystem, name string) *localReputationTarget {
	key := dependencyKey(ecosystem, name, "")
	target := targets[key]
	if target == nil {
		target = &localReputationTarget{
			Ecosystem: ecosystem,
			Name:      name,
			Versions:  map[string]bool{},
			Hashes:    map[string]map[string]bool{},
		}
		targets[key] = target
	}
	return target
}

func appendUniqueFinding(findings *[]Finding, emitted map[string]bool, finding Finding) {
	key := finding.Code + "\x00" + finding.Evidence
	if emitted[key] {
		return
	}
	emitted[key] = true
	*findings = append(*findings, finding)
}

func uniqueNormalizedStrings(values []string) []string {
	seen := map[string]bool{}
	var unique []string
	for _, value := range values {
		normalized := normalizeMaintainer(value)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		unique = append(unique, normalized)
	}
	sort.Strings(unique)
	return unique
}

func packageEvidence(ecosystem, name, version string) string {
	if version == "" {
		return ecosystem + " " + name
	}
	return ecosystem + " " + name + " " + version
}
