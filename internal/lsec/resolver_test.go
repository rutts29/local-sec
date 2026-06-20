package lsec

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSelectNewestMatureCandidateSkipsTooNewLatest(t *testing.T) {
	now := time.Now().UTC()
	versions := []RegistryVersion{
		{Version: "2.4.9", PublishedAt: now.Add(-3 * time.Hour)},
		{Version: "2.4.8", PublishedAt: now.Add(-19 * 24 * time.Hour)},
		{Version: "2.4.7", PublishedAt: now.Add(-60 * 24 * time.Hour)},
	}

	got, ok := SelectNewestMatureCandidate(versions, now, 7)
	if !ok {
		t.Fatal("expected mature candidate")
	}
	if got.Version != "2.4.8" {
		t.Fatalf("version = %s, want 2.4.8", got.Version)
	}
}

func TestSelectNewestMatureCleanCandidateSkipsAdvisoryVersion(t *testing.T) {
	now := time.Now().UTC()
	versions := []RegistryVersion{
		{Version: "2.4.9", PublishedAt: now.Add(-3 * time.Hour)},
		{Version: "2.4.8", PublishedAt: now.Add(-19 * 24 * time.Hour)},
		{Version: "2.4.7", PublishedAt: now.Add(-60 * 24 * time.Hour)},
	}

	got, skipped, ok := SelectNewestMatureCleanCandidate(versions, now, 7, func(candidate RegistryVersion) ([]Advisory, []Finding) {
		if candidate.Version == "2.4.8" {
			return []Advisory{{ID: "GHSA-bad", Severity: "critical"}}, nil
		}
		return nil, nil
	})

	if !ok {
		t.Fatal("expected clean mature candidate")
	}
	if got.Version != "2.4.7" {
		t.Fatalf("version = %s, want 2.4.7", got.Version)
	}
	if len(skipped) != 1 || skipped[0].Version != "2.4.8" || skipped[0].Reason != "advisory" {
		t.Fatalf("skipped = %#v, want advisory skip for 2.4.8", skipped)
	}
}

func TestFollowAdvisoryCleanCandidateSelectsOlderCleanVersion(t *testing.T) {
	t.Setenv("PATH", "")
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	withFakeOSVByVersion(t, map[string]string{
		"2.4.8": `{"vulns":[{"id":"GHSA-bad","summary":"bad","database_specific":{"severity":"CRITICAL"}}]}`,
		"2.4.7": `{"vulns":[]}`,
	})
	now := time.Now().UTC()
	version := VersionInfo{
		Requested: "example",
		Selected:  RegistryVersion{Version: "2.4.8", PublishedAt: now.Add(-19 * 24 * time.Hour)},
		Latest:    RegistryVersion{Version: "2.4.9", PublishedAt: now.Add(-3 * time.Hour)},
		AgeDays:   19,
		Found:     true,
		Candidates: []RegistryVersion{
			{Version: "2.4.9", PublishedAt: now.Add(-3 * time.Hour)},
			{Version: "2.4.8", PublishedAt: now.Add(-19 * 24 * time.Hour)},
			{Version: "2.4.7", PublishedAt: now.Add(-60 * 24 * time.Hour)},
		},
	}

	got, advisories, findings := FollowAdvisoryCleanCandidate(context.Background(), store, "npm", "example", version, 30*time.Minute, 7)

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if len(advisories) != 0 {
		t.Fatalf("advisories = %#v, want none for selected clean version", advisories)
	}
	if got.Selected.Version != "2.4.7" {
		t.Fatalf("selected = %s, want 2.4.7", got.Selected.Version)
	}
	if len(got.Skipped) != 1 || got.Skipped[0].Version != "2.4.8" || got.Skipped[0].AdvisoryIDs[0] != "GHSA-bad" {
		t.Fatalf("skipped = %#v, want advisory skip for 2.4.8", got.Skipped)
	}
}

func TestFollowAdvisoryCleanCandidateSelectsFreshCleanFixWhenMatureCandidateIsVulnerable(t *testing.T) {
	t.Setenv("PATH", "")
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	withFakeOSVByVersion(t, map[string]string{
		"2.4.9": `{"vulns":[]}`,
		"2.4.8": `{"vulns":[{"id":"GHSA-bad","summary":"bad","database_specific":{"severity":"CRITICAL"}}]}`,
	})
	now := time.Now().UTC()
	version := VersionInfo{
		Requested: "example",
		Selected:  RegistryVersion{Version: "2.4.8", PublishedAt: now.Add(-19 * 24 * time.Hour)},
		Latest:    RegistryVersion{Version: "2.4.9", PublishedAt: now.Add(-3 * time.Hour)},
		AgeDays:   19,
		Found:     true,
		Candidates: []RegistryVersion{
			{Version: "2.4.9", PublishedAt: now.Add(-3 * time.Hour)},
			{Version: "2.4.8", PublishedAt: now.Add(-19 * 24 * time.Hour)},
		},
	}

	got, advisories, findings := FollowAdvisoryCleanCandidate(context.Background(), store, "npm", "example", version, 30*time.Minute, 7)

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if len(advisories) != 0 {
		t.Fatalf("advisories = %#v, want none for fresh clean fix", advisories)
	}
	if got.Selected.Version != "2.4.9" {
		t.Fatalf("selected = %s, want fresh clean fix 2.4.9", got.Selected.Version)
	}
	if got.AgeDays >= 7 {
		t.Fatalf("age days = %d, want selected fresh fix to remain inside maturity window", got.AgeDays)
	}
	if len(got.Skipped) != 1 || got.Skipped[0].Version != "2.4.8" || got.Skipped[0].Reason != "advisory" {
		t.Fatalf("skipped = %#v, want advisory skip for mature vulnerable version", got.Skipped)
	}
}

func TestResolvePinnedVersionUsesRegistryPublishTime(t *testing.T) {
	now := time.Now().UTC()
	withFakeDefaultHTTP(t, `{
		"dist-tags":{"latest":"1.3.0"},
		"time":{
			"created":"`+now.Add(-900*24*time.Hour).Format(time.RFC3339)+`",
			"modified":"`+now.Format(time.RFC3339)+`",
			"1.3.0":"`+now.Add(-800*24*time.Hour).Format(time.RFC3339)+`"
		}
	}`)
	analysis := CommandAnalysis{
		Manager: "npm",
		PackageSpecs: []PackageSpec{{
			Raw:     "left-pad@1.3.0",
			Name:    "left-pad",
			Version: "1.3.0",
		}},
	}

	got := ResolveVersion(context.Background(), analysis, 7)

	if !got.Found {
		t.Fatal("expected pinned version to resolve")
	}
	if got.AgeDays < 700 {
		t.Fatalf("age days = %d, want registry publish age for old pinned version", got.AgeDays)
	}
	if len(got.Candidates) != 1 || got.Candidates[0].Version != "1.3.0" {
		t.Fatalf("candidates = %#v, want only exact pinned candidate", got.Candidates)
	}
}

func withFakeOSVByVersion(t *testing.T, bodies map[string]string) {
	t.Helper()
	previousEndpoint := osvEndpoint
	previousClient := osvHTTPClient
	osvEndpoint = "https://osv.test/query"
	osvHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		selected := `{"vulns":[]}`
		for version, response := range bodies {
			if strings.Contains(string(body), `"version":"`+version+`"`) {
				selected = response
				break
			}
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(selected)),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() {
		osvEndpoint = previousEndpoint
		osvHTTPClient = previousClient
	})
}
