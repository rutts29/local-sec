package lsec

import (
	"sort"
	"strings"
	"time"
)

type LocalPackageHistory struct {
	Ecosystem    string
	Name         string
	PackageSeen  bool
	Versions     map[string]LocalVersionHistory
	FirstSeen    time.Time
	LastSeen     time.Time
	InstallCount int
	Maintainers  []string
}

type LocalVersionHistory struct {
	Version      string
	Hashes       []string
	FirstSeen    time.Time
	LastSeen     time.Time
	InstallCount int
}

func (h LocalPackageHistory) VersionSeen(version string) bool {
	_, ok := h.Versions[version]
	return ok
}

func (h LocalPackageHistory) HashSeen(version, hash string) bool {
	versionHistory, ok := h.Versions[version]
	if !ok {
		return false
	}
	for _, seenHash := range versionHistory.Hashes {
		if seenHash == hash {
			return true
		}
	}
	return false
}

func (h LocalPackageHistory) HashesForVersion(version string) []string {
	versionHistory, ok := h.Versions[version]
	if !ok {
		return nil
	}
	return versionHistory.Hashes
}

func (s Store) LoadLocalPackageHistory(ecosystem, name string) (LocalPackageHistory, error) {
	history := LocalPackageHistory{
		Ecosystem: ecosystem,
		Name:      name,
		Versions:  map[string]LocalVersionHistory{},
	}
	maintainers := map[string]bool{}
	versionHashes := map[string]map[string]bool{}
	err := s.eventLog().forEach(func(line []byte) error {
		report, createdAt, ok := parseEventRunReportWithCreatedAt(line)
		if !ok {
			return nil
		}
		if !report.CreatedAt.IsZero() {
			createdAt = report.CreatedAt
		}
		observedVersions, matched, matchedSpec := localHistoryObservations(report, ecosystem, name)
		if !matched {
			return nil
		}
		history.PackageSeen = true
		history.InstallCount++
		updateHistoryWindow(&history.FirstSeen, &history.LastSeen, createdAt)
		for version, hashes := range observedVersions {
			if version == "" {
				continue
			}
			versionHistory := history.Versions[version]
			if versionHistory.Version == "" {
				versionHistory.Version = version
			}
			versionHistory.InstallCount++
			updateHistoryWindow(&versionHistory.FirstSeen, &versionHistory.LastSeen, createdAt)
			if versionHashes[version] == nil {
				versionHashes[version] = map[string]bool{}
			}
			for hash := range hashes {
				if hash != "" {
					versionHashes[version][hash] = true
				}
			}
			history.Versions[version] = versionHistory
		}
		if matchedSpec {
			for _, maintainer := range report.Version.Maintainers {
				normalized := normalizeMaintainer(maintainer)
				if normalized != "" {
					maintainers[normalized] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return LocalPackageHistory{}, err
	}
	for version, hashes := range versionHashes {
		versionHistory := history.Versions[version]
		for hash := range hashes {
			versionHistory.Hashes = append(versionHistory.Hashes, hash)
		}
		sort.Strings(versionHistory.Hashes)
		history.Versions[version] = versionHistory
	}
	for maintainer := range maintainers {
		history.Maintainers = append(history.Maintainers, maintainer)
	}
	sort.Strings(history.Maintainers)
	return history, nil
}

func localHistoryObservations(report RunReport, ecosystem, name string) (map[string]map[string]bool, bool, bool) {
	versions := map[string]map[string]bool{}
	matched := false
	matchedSpec := false
	reportEcosystem := ecosystemForManager(report.Analysis.Manager)
	for i, spec := range report.Analysis.PackageSpecs {
		if spec.Name != name || (reportEcosystem != "" && reportEcosystem != ecosystem) {
			continue
		}
		matched = true
		matchedSpec = true
		version := spec.Version
		if version == "" && i == 0 {
			version = report.Version.Selected.Version
		}
		addLocalHistoryObservation(versions, version, "")
	}
	for _, artifact := range report.Artifacts {
		if artifact.Ecosystem != ecosystem || artifact.Name != name {
			continue
		}
		matched = true
		addLocalHistoryObservation(versions, artifact.Version, artifact.SHA256)
	}
	return versions, matched, matchedSpec
}

func addLocalHistoryObservation(versions map[string]map[string]bool, version, hash string) {
	if version == "" {
		return
	}
	if versions[version] == nil {
		versions[version] = map[string]bool{}
	}
	if hash != "" {
		versions[version][hash] = true
	}
}

func updateHistoryWindow(firstSeen, lastSeen *time.Time, seenAt time.Time) {
	if seenAt.IsZero() {
		return
	}
	if firstSeen.IsZero() || seenAt.Before(*firstSeen) {
		*firstSeen = seenAt
	}
	if lastSeen.IsZero() || seenAt.After(*lastSeen) {
		*lastSeen = seenAt
	}
}

func normalizeMaintainer(maintainer string) string {
	return strings.ToLower(strings.TrimSpace(maintainer))
}
