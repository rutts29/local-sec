package lsec

import (
	"testing"
	"time"
)

const (
	localRepHashOne = "1111111111111111111111111111111111111111111111111111111111111111"
	localRepHashTwo = "2222222222222222222222222222222222222222222222222222222222222222"
)

func TestLoadLocalPackageHistoryFromJSONL(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	firstSeen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	lastSeen := firstSeen.Add(time.Hour)
	for _, report := range []RunReport{
		localReputationReport("run-history-1", firstSeen, "1.0.0", localRepHashOne, []string{"Alice"}),
		localReputationReport("run-history-2", lastSeen, "1.1.0", localRepHashTwo, []string{"bob"}),
	} {
		if err := store.AppendEvent("preflight", report); err != nil {
			t.Fatal(err)
		}
	}

	history, err := store.LoadLocalPackageHistory("npm", "left-pad")
	if err != nil {
		t.Fatal(err)
	}

	if !history.PackageSeen || history.InstallCount != 2 {
		t.Fatalf("history = %#v, want seen package with two installs", history)
	}
	if !history.VersionSeen("1.0.0") || !history.VersionSeen("1.1.0") {
		t.Fatalf("versions = %#v, want both versions seen", history.Versions)
	}
	if !history.HashSeen("1.0.0", localRepHashOne) || !history.HashSeen("1.1.0", localRepHashTwo) {
		t.Fatalf("hashes by version = %#v, want recorded hashes", history.Versions)
	}
	if !history.FirstSeen.Equal(firstSeen) || !history.LastSeen.Equal(lastSeen) {
		t.Fatalf("first/last = %s/%s, want %s/%s", history.FirstSeen, history.LastSeen, firstSeen, lastSeen)
	}
	if !stringSliceContains(history.Maintainers, "alice") || !stringSliceContains(history.Maintainers, "bob") {
		t.Fatalf("maintainers = %#v, want normalized maintainers", history.Maintainers)
	}
}

func TestCheckLocalReputationPromptsFirstSeenPackage(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	findings := CheckLocalReputation(store, "npm", CommandAnalysis{
		PackageSpecs: []PackageSpec{{Name: "left-pad", Version: "1.0.0"}},
	}, VersionInfo{}, nil)

	assertFindingCode(t, findings, "first_seen_package")
}

func TestCheckLocalReputationPromptsNewVersionForKnownPackage(t *testing.T) {
	store := localReputationStoreWithReport(t, localReputationReport("run-seen", time.Now().UTC(), "1.0.0", localRepHashOne, nil))

	findings := CheckLocalReputation(store, "npm", CommandAnalysis{
		PackageSpecs: []PackageSpec{{Name: "left-pad", Version: "1.1.0"}},
	}, VersionInfo{}, nil)

	assertFindingCode(t, findings, "first_seen_package_version")
}

func TestCheckLocalReputationPromptsArtifactHashDrift(t *testing.T) {
	store := localReputationStoreWithReport(t, localReputationReport("run-seen", time.Now().UTC(), "1.0.0", localRepHashOne, nil))

	findings := CheckLocalReputation(store, "npm", CommandAnalysis{}, VersionInfo{}, []Artifact{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.0.0",
		SHA256:    localRepHashTwo,
		Kind:      "tar",
	}})

	assertFindingCode(t, findings, "artifact_hash_drift")
}

func TestCheckLocalReputationPromptsOwnershipDriftAndFirstSeenMaintainer(t *testing.T) {
	store := localReputationStoreWithReport(t, localReputationReport("run-seen", time.Now().UTC(), "1.0.0", localRepHashOne, []string{"alice"}))

	findings := CheckLocalReputation(store, "npm", CommandAnalysis{
		PackageSpecs: []PackageSpec{{Name: "left-pad", Version: "1.0.0"}},
	}, VersionInfo{Maintainers: []string{"alice", "charlie"}}, nil)

	assertFindingCode(t, findings, "ownership_drift")
	assertFindingCode(t, findings, "first_seen_maintainer")
}

func TestLocalReputationDoesNotDowngradeWithoutExactArtifactApproval(t *testing.T) {
	approvals := []Approval{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.0.0",
		Hash:      localRepHashOne,
	}}
	artifacts := []Artifact{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.0.0",
		SHA256:    localRepHashOne,
	}, {
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.0.0",
		SHA256:    localRepHashTwo,
	}}

	if ArtifactsApproved(approvals, artifacts) {
		t.Fatal("local reputation must not make partial exact approvals sufficient")
	}
}

func localReputationStoreWithReport(t *testing.T, report RunReport) Store {
	t.Helper()
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	return store
}

func localReputationReport(runID string, createdAt time.Time, version, hash string, maintainers []string) RunReport {
	return RunReport{
		RunID: runID,
		Analysis: CommandAnalysis{
			Manager: "npm",
			PackageSpecs: []PackageSpec{{
				Name:    "left-pad",
				Version: version,
			}},
		},
		Version: VersionInfo{
			Selected:    RegistryVersion{Version: version},
			Maintainers: maintainers,
			Found:       true,
		},
		Artifacts: []Artifact{{
			Ecosystem: "npm",
			Name:      "left-pad",
			Version:   version,
			SHA256:    hash,
			Kind:      "tar",
		}},
		Decision:  Decision{Verdict: VerdictAllow, Lane: LaneTrusted},
		CreatedAt: createdAt,
	}
}

func assertFindingCode(t *testing.T, findings []Finding, code string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code && finding.Severity == "prompt" {
			return
		}
	}
	t.Fatalf("findings = %#v, want prompt %s", findings, code)
}
