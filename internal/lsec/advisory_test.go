package lsec

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestQueryOSVParsesDatabaseSpecificObject(t *testing.T) {
	withFakeOSV(t, `{
			"vulns": [{
				"id": "GHSA-test-1234",
				"summary": "critical test advisory",
				"database_specific": {
					"severity": "CRITICAL",
					"github_reviewed": true
				}
			}]
		}`)

	advisories := QueryOSV(context.Background(), "npm", "example", "1.0.0")

	if len(advisories) != 1 {
		t.Fatalf("advisories len = %d, want 1: %#v", len(advisories), advisories)
	}
	if advisories[0].Severity != "critical" {
		t.Fatalf("severity = %q, want critical", advisories[0].Severity)
	}
}

func TestQueryOSVMarksMalwareAdvisory(t *testing.T) {
	withFakeOSV(t, `{
			"vulns": [{
				"id": "MAL-2026-0001",
				"summary": "known malware",
				"database_specific": {
					"malicious": true
				}
			}]
		}`)

	advisories := QueryOSV(context.Background(), "PyPI", "example", "1.0.0")

	if len(advisories) != 1 {
		t.Fatalf("advisories len = %d, want 1: %#v", len(advisories), advisories)
	}
	if advisories[0].Type != "malware" {
		t.Fatalf("type = %q, want malware", advisories[0].Type)
	}
}

func TestRefreshAdvisoriesUsesFreshCacheWhenOSVUnavailable(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	cached := AdvisoryCacheEntry{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		CheckedAt: time.Now().UTC(),
		Advisories: []Advisory{{
			Source: "osv",
			ID:     "GHSA-cached",
		}},
	}
	if err := store.PutAdvisoryCache(cached); err != nil {
		t.Fatal(err)
	}
	withFailingOSV(t)

	advisories, findings := RefreshAdvisories(context.Background(), store, "npm", "left-pad", "1.3.0", 30*time.Minute)

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none when fresh cache exists", findings)
	}
	if len(advisories) != 1 || advisories[0].ID != "GHSA-cached" {
		t.Fatalf("advisories = %#v, want cached advisory", advisories)
	}
}

func TestRefreshAdvisoriesFailsClosedWithoutFreshCache(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	withFailingOSV(t)

	advisories, findings := RefreshAdvisories(context.Background(), store, "npm", "left-pad", "1.3.0", 30*time.Minute)

	if len(advisories) != 0 {
		t.Fatalf("advisories = %#v, want none", advisories)
	}
	if firstFindingSeverity(findings, "advisory_refresh_failed") != "block" {
		t.Fatalf("expected blocking advisory_refresh_failed finding, got %#v", findings)
	}
}

func withFakeOSV(t *testing.T, body string) {
	t.Helper()
	previousEndpoint := osvEndpoint
	previousClient := osvHTTPClient
	osvEndpoint = "https://osv.test/query"
	osvHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() {
		osvEndpoint = previousEndpoint
		osvHTTPClient = previousClient
	})
}

func withFailingOSV(t *testing.T) {
	t.Helper()
	previousEndpoint := osvEndpoint
	previousClient := osvHTTPClient
	osvEndpoint = "https://osv.test/query"
	osvHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network unavailable")
	})}
	t.Cleanup(func() {
		osvEndpoint = previousEndpoint
		osvHTTPClient = previousClient
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
