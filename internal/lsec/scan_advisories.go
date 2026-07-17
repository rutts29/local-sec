package lsec

import (
	"context"
	"strings"
	"time"
)

func queryScanAdvisories(ctx context.Context, store Store, runID string, observations []ScanObservation) ([]ScanFinding, []ScanDiagnostic, []ScanProviderSnapshot) {
	components := exactScanComponents(observations)
	if len(components) == 0 {
		return nil, nil, []ScanProviderSnapshot{{Provider: "osv", Status: "not_applicable"}}
	}
	results := make([][]Advisory, len(components))
	var uncached []ScanObservation
	var uncachedIndexes []int
	cachedCount := 0
	for i, component := range components {
		if entry, ok := store.FreshAdvisoryCache(component.Ecosystem, component.Name, component.Version, 30*time.Minute); ok {
			results[i] = entry.Advisories
			cachedCount++
			continue
		}
		uncached = append(uncached, component)
		uncachedIndexes = append(uncachedIndexes, i)
	}
	if len(uncached) > 0 {
		fetched, err := QueryOSVBatchChecked(ctx, uncached)
		if err != nil {
			snapshot := ScanProviderSnapshot{Provider: "osv", Status: "error", CachedCount: cachedCount, QueriedCount: len(uncached), Error: err.Error()}
			return scanFindingsFromAdvisories(runID, components, results), []ScanDiagnostic{scanDiagnostic(runID, "provider_unavailable", "osv", err.Error())}, []ScanProviderSnapshot{snapshot}
		}
		now := time.Now().UTC()
		for i, advisories := range fetched {
			if i >= len(uncachedIndexes) {
				break
			}
			component := uncached[i]
			results[uncachedIndexes[i]] = advisories
			entry := AdvisoryCacheEntry{Ecosystem: component.Ecosystem, Name: component.Name, Version: component.Version, CheckedAt: now, Advisories: advisories}
			_ = store.PutAdvisoryCache(entry)
			_ = store.RecordAdvisoryChecks(entry)
		}
		snapshot := ScanProviderSnapshot{Provider: "osv", Status: "ok", FetchedAt: now.Format(time.RFC3339Nano), CachedCount: cachedCount, QueriedCount: len(uncached)}
		return scanFindingsFromAdvisories(runID, components, results), nil, []ScanProviderSnapshot{snapshot}
	}
	snapshot := ScanProviderSnapshot{Provider: "osv", Status: "cache_only", CachedCount: cachedCount}
	return scanFindingsFromAdvisories(runID, components, results), nil, []ScanProviderSnapshot{snapshot}
}

func scanFindingsFromAdvisories(runID string, components []ScanObservation, results [][]Advisory) []ScanFinding {
	var findings []ScanFinding
	for i, result := range results {
		if i >= len(components) {
			break
		}
		component := components[i]
		for _, advisory := range result {
			class := "vulnerability"
			urgency := "review"
			if strings.EqualFold(advisory.Type, "malware") {
				class = "malicious_package"
				urgency = "critical-immediate"
			} else if strings.EqualFold(advisory.Severity, "critical") {
				urgency = "high"
			}
			findings = append(findings, ScanFinding{
				Type: "finding", RunID: runID, FindingID: findingID("osv", advisory.ID, component),
				Provider: "osv", ProviderRecordID: advisory.ID, Class: class, Severity: advisory.Severity,
				Urgency: urgency, Confidence: "high", Presence: component.Presence, Ecosystem: component.Ecosystem,
				Name: component.Name, Version: component.Version, Title: nonEmpty(advisory.Summary, advisory.ID), SourcePath: component.SourcePath,
			})
		}
	}
	return findings
}

func exactScanComponents(observations []ScanObservation) []ScanObservation {
	seen := map[string]bool{}
	var components []ScanObservation
	for _, observation := range observations {
		if observation.Ecosystem == "" || observation.Name == "" || observation.Version == "" {
			continue
		}
		switch observation.Ecosystem {
		case "npm", "PyPI":
		default:
			continue
		}
		key := dependencyKey(observation.Ecosystem, observation.Normalized, observation.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		components = append(components, observation)
	}
	return components
}

func findingID(provider, id string, observation ScanObservation) string {
	return provider + ":" + id + ":" + observation.Ecosystem + ":" + observation.Normalized + ":" + observation.Version + ":" + observation.Presence
}

func nonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
