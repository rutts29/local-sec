package lsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func SelectNewestMatureCandidate(versions []RegistryVersion, now time.Time, maturityDays int) (RegistryVersion, bool) {
	cutoff := now.Add(-time.Duration(maturityDays) * 24 * time.Hour)
	sort.SliceStable(versions, func(i, j int) bool {
		return versions[i].PublishedAt.After(versions[j].PublishedAt)
	})
	for _, version := range versions {
		if version.Yanked || version.Deprecated || version.PublishedAt.IsZero() {
			continue
		}
		if !version.PublishedAt.After(cutoff) {
			return version, true
		}
	}
	return RegistryVersion{}, false
}

func SelectNewestMatureCleanCandidate(versions []RegistryVersion, now time.Time, maturityDays int, advisoryCheck func(RegistryVersion) ([]Advisory, []Finding)) (RegistryVersion, []VersionSkip, bool) {
	cutoff := now.Add(-time.Duration(maturityDays) * 24 * time.Hour)
	sort.SliceStable(versions, func(i, j int) bool {
		return versions[i].PublishedAt.After(versions[j].PublishedAt)
	})
	var skipped []VersionSkip
	for _, version := range versions {
		if version.Yanked || version.Deprecated || version.PublishedAt.IsZero() || version.PublishedAt.After(cutoff) {
			continue
		}
		advisories, findings := advisoryCheck(version)
		if hasBlockingFinding(findings) {
			return RegistryVersion{}, skipped, false
		}
		if len(advisories) == 0 {
			return version, skipped, true
		}
		skipped = append(skipped, VersionSkip{Version: version.Version, Reason: "advisory", AdvisoryIDs: advisoryIDs(advisories)})
	}
	return RegistryVersion{}, skipped, false
}

func ResolveVersion(ctx context.Context, analysis CommandAnalysis, maturityDays int) VersionInfo {
	if len(analysis.PackageSpecs) == 0 {
		return VersionInfo{}
	}
	spec := analysis.PackageSpecs[0]
	if spec.DirectURL || spec.VCS || spec.Name == "" {
		return VersionInfo{Requested: spec.Raw}
	}
	now := time.Now().UTC()
	if spec.Version != "" {
		if selected, latest, ok := resolvePinnedRegistryVersion(ctx, analysis.Manager, spec.Name, spec.Version); ok {
			return VersionInfo{
				Requested:  spec.Raw,
				Selected:   selected,
				Latest:     latest,
				AgeDays:    int(now.Sub(selected.PublishedAt).Hours() / 24),
				Candidates: []RegistryVersion{selected},
				Found:      true,
			}
		}
		return VersionInfo{
			Requested:  spec.Raw,
			Selected:   RegistryVersion{Version: spec.Version, PublishedAt: now},
			AgeDays:    0,
			Candidates: []RegistryVersion{{Version: spec.Version, PublishedAt: now}},
			Found:      true,
		}
	}
	var versions []RegistryVersion
	var latest RegistryVersion
	var err error
	switch ecosystemForManager(analysis.Manager) {
	case "npm":
		versions, latest, err = fetchNPMVersions(ctx, spec.Name)
	case "PyPI":
		versions, latest, err = fetchPyPIVersions(ctx, spec.Name)
	default:
		return VersionInfo{Requested: spec.Raw}
	}
	if err != nil || len(versions) == 0 {
		return VersionInfo{Requested: spec.Raw}
	}
	selected, ok := SelectNewestMatureCandidate(versions, now, maturityDays)
	if !ok {
		selected = latest
	}
	return VersionInfo{
		Requested:               spec.Raw,
		Selected:                selected,
		Latest:                  latest,
		AgeDays:                 int(now.Sub(selected.PublishedAt).Hours() / 24),
		MatureCandidateSelected: ok && selected.Version != latest.Version,
		Skipped:                 skippedTooNewVersions(versions, now, maturityDays),
		Candidates:              versions,
		Found:                   true,
	}
}

func resolvePinnedRegistryVersion(ctx context.Context, manager, name, requestedVersion string) (RegistryVersion, RegistryVersion, bool) {
	var versions []RegistryVersion
	var latest RegistryVersion
	var err error
	switch ecosystemForManager(manager) {
	case "npm":
		versions, latest, err = fetchNPMVersions(ctx, name)
	case "PyPI":
		versions, latest, err = fetchPyPIVersions(ctx, name)
	default:
		return RegistryVersion{}, RegistryVersion{}, false
	}
	if err != nil {
		return RegistryVersion{}, RegistryVersion{}, false
	}
	for _, version := range versions {
		if version.Version == requestedVersion && !version.PublishedAt.IsZero() {
			return version, latest, true
		}
	}
	return RegistryVersion{}, RegistryVersion{}, false
}

func FollowAdvisoryCleanCandidate(ctx context.Context, store Store, ecosystem, name string, version VersionInfo, cacheTTL time.Duration, maturityDays int) (VersionInfo, []Advisory, []Finding) {
	if !version.Found || ecosystem == "" || name == "" || version.Selected.Version == "" {
		return version, nil, nil
	}
	candidates := version.Candidates
	if len(candidates) == 0 {
		candidates = []RegistryVersion{version.Selected}
	}
	advisoryByVersion := map[string][]Advisory{}
	findingByVersion := map[string][]Finding{}
	selected, skipped, ok := SelectNewestMatureCleanCandidate(candidates, time.Now().UTC(), maturityDays, func(candidate RegistryVersion) ([]Advisory, []Finding) {
		advisories, findings := RefreshAdvisories(ctx, store, ecosystem, name, candidate.Version, cacheTTL)
		externalAdvisories, externalFindings := RefreshExternalAdvisories(ctx, []DependencyRef{{Ecosystem: ecosystem, Name: name, Version: candidate.Version, Raw: candidate.Version, Exact: true}})
		advisories = append(advisories, externalAdvisories...)
		findings = append(findings, externalFindings...)
		advisoryByVersion[candidate.Version] = advisories
		findingByVersion[candidate.Version] = findings
		return advisories, findings
	})
	version.Skipped = append(version.Skipped, skipped...)
	if ok {
		version.Selected = selected
		version.AgeDays = int(time.Since(selected.PublishedAt).Hours() / 24)
		version.MatureCandidateSelected = version.MatureCandidateSelected || selected.Version != version.Latest.Version
		return version, advisoryByVersion[selected.Version], findingByVersion[selected.Version]
	}
	if fresh, found := newestFreshCleanCandidate(candidates, time.Now().UTC(), maturityDays, func(candidate RegistryVersion) ([]Advisory, []Finding) {
		if _, ok := advisoryByVersion[candidate.Version]; !ok {
			advisories, findings := RefreshAdvisories(ctx, store, ecosystem, name, candidate.Version, cacheTTL)
			externalAdvisories, externalFindings := RefreshExternalAdvisories(ctx, []DependencyRef{{Ecosystem: ecosystem, Name: name, Version: candidate.Version, Raw: candidate.Version, Exact: true}})
			advisories = append(advisories, externalAdvisories...)
			findings = append(findings, externalFindings...)
			advisoryByVersion[candidate.Version] = advisories
			findingByVersion[candidate.Version] = findings
		}
		return advisoryByVersion[candidate.Version], findingByVersion[candidate.Version]
	}); found {
		version.Selected = fresh
		version.AgeDays = int(time.Since(fresh.PublishedAt).Hours() / 24)
		version.MatureCandidateSelected = false
		return version, advisoryByVersion[fresh.Version], findingByVersion[fresh.Version]
	}
	if _, ok := advisoryByVersion[version.Selected.Version]; !ok {
		advisories, findings := RefreshAdvisories(ctx, store, ecosystem, name, version.Selected.Version, cacheTTL)
		externalAdvisories, externalFindings := RefreshExternalAdvisories(ctx, []DependencyRef{{Ecosystem: ecosystem, Name: name, Version: version.Selected.Version, Raw: version.Selected.Version, Exact: true}})
		advisories = append(advisories, externalAdvisories...)
		findings = append(findings, externalFindings...)
		advisoryByVersion[version.Selected.Version] = advisories
		findingByVersion[version.Selected.Version] = findings
	}
	return version, advisoryByVersion[version.Selected.Version], findingByVersion[version.Selected.Version]
}

func newestFreshCleanCandidate(candidates []RegistryVersion, now time.Time, maturityDays int, advisoryCheck func(RegistryVersion) ([]Advisory, []Finding)) (RegistryVersion, bool) {
	cutoff := now.Add(-time.Duration(maturityDays) * 24 * time.Hour)
	sorted := append([]RegistryVersion(nil), candidates...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].PublishedAt.After(sorted[j].PublishedAt)
	})
	for _, candidate := range sorted {
		if candidate.Yanked || candidate.Deprecated || candidate.PublishedAt.IsZero() || !candidate.PublishedAt.After(cutoff) {
			continue
		}
		advisories, findings := advisoryCheck(candidate)
		if hasBlockingFinding(findings) {
			continue
		}
		if len(advisories) == 0 {
			return candidate, true
		}
	}
	return RegistryVersion{}, false
}

func advisoryIDs(advisories []Advisory) []string {
	ids := make([]string, 0, len(advisories))
	for _, advisory := range advisories {
		if advisory.ID != "" {
			ids = append(ids, advisory.ID)
		}
	}
	return ids
}

func skippedTooNewVersions(versions []RegistryVersion, now time.Time, maturityDays int) []VersionSkip {
	cutoff := now.Add(-time.Duration(maturityDays) * 24 * time.Hour)
	var skipped []VersionSkip
	for _, version := range versions {
		if version.Yanked || version.Deprecated || version.PublishedAt.IsZero() {
			continue
		}
		if version.PublishedAt.After(cutoff) {
			skipped = append(skipped, VersionSkip{Version: version.Version, Reason: "maturity_window"})
		}
	}
	return skipped
}

func fetchNPMVersions(ctx context.Context, name string) ([]RegistryVersion, RegistryVersion, error) {
	u := "https://registry.npmjs.org/" + url.PathEscape(name)
	var doc struct {
		Time     map[string]string `json:"time"`
		DistTags map[string]string `json:"dist-tags"`
	}
	if err := fetchJSON(ctx, u, &doc); err != nil {
		return nil, RegistryVersion{}, err
	}
	var versions []RegistryVersion
	for version, rawTime := range doc.Time {
		if version == "created" || version == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339, rawTime)
		if err != nil {
			continue
		}
		versions = append(versions, RegistryVersion{Version: version, PublishedAt: t})
	}
	latest := latestFromVersions(versions, doc.DistTags["latest"])
	return versions, latest, nil
}

func fetchPyPIVersions(ctx context.Context, name string) ([]RegistryVersion, RegistryVersion, error) {
	u := "https://pypi.org/pypi/" + url.PathEscape(name) + "/json"
	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
			Yanked     bool   `json:"yanked"`
		} `json:"releases"`
	}
	if err := fetchJSON(ctx, u, &doc); err != nil {
		return nil, RegistryVersion{}, err
	}
	var versions []RegistryVersion
	for version, files := range doc.Releases {
		if len(files) == 0 {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, files[0].UploadTime)
		if err != nil {
			continue
		}
		versions = append(versions, RegistryVersion{Version: version, PublishedAt: t, Yanked: files[0].Yanked})
	}
	latest := latestFromVersions(versions, doc.Info.Version)
	return versions, latest, nil
}

func latestFromVersions(versions []RegistryVersion, named string) RegistryVersion {
	for _, version := range versions {
		if version.Version == named {
			return version
		}
	}
	sort.SliceStable(versions, func(i, j int) bool {
		return versions[i].PublishedAt.After(versions[j].PublishedAt)
	})
	if len(versions) == 0 {
		return RegistryVersion{}
	}
	return versions[0]
}

func fetchJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s returned %s", u, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func FetchPackageMaintainers(ctx context.Context, ecosystem, name string) []string {
	switch ecosystem {
	case "npm":
		return fetchNPMMaintainers(ctx, name)
	case "PyPI":
		return fetchPyPIMaintainers(ctx, name)
	default:
		return nil
	}
}

func fetchNPMMaintainers(ctx context.Context, name string) []string {
	u := "https://registry.npmjs.org/" + url.PathEscape(name)
	var doc struct {
		Maintainers []struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"maintainers"`
	}
	if err := fetchJSON(ctx, u, &doc); err != nil {
		return nil
	}
	var maintainers []string
	for _, maintainer := range doc.Maintainers {
		identity := strings.TrimSpace(maintainer.Name)
		if identity == "" {
			identity = strings.TrimSpace(maintainer.Email)
		}
		if identity != "" {
			maintainers = append(maintainers, strings.ToLower(identity))
		}
	}
	return uniqueStrings(maintainers)
}

func fetchPyPIMaintainers(ctx context.Context, name string) []string {
	u := "https://pypi.org/pypi/" + url.PathEscape(name) + "/json"
	var doc struct {
		Info struct {
			Author          string `json:"author"`
			AuthorEmail     string `json:"author_email"`
			Maintainer      string `json:"maintainer"`
			MaintainerEmail string `json:"maintainer_email"`
		} `json:"info"`
	}
	if err := fetchJSON(ctx, u, &doc); err != nil {
		return nil
	}
	var maintainers []string
	for _, value := range []string{doc.Info.Maintainer, doc.Info.MaintainerEmail, doc.Info.Author, doc.Info.AuthorEmail} {
		value = strings.TrimSpace(value)
		if value != "" {
			maintainers = append(maintainers, strings.ToLower(value))
		}
	}
	return uniqueStrings(maintainers)
}

func ecosystemForManager(manager string) string {
	switch manager {
	case "npm", "npx":
		return "npm"
	case "pip", "pip3", "pipx", "uv", "uvx":
		return "PyPI"
	}
	if strings.HasPrefix(manager, "python") {
		return "PyPI"
	}
	return ""
}
