package lsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	osvEndpoint      = "https://api.osv.dev/v1/query"
	osvBatchEndpoint = "https://api.osv.dev/v1/querybatch"
	osvHTTPClient    = http.DefaultClient
)

func QueryOSV(ctx context.Context, ecosystem, name, version string) []Advisory {
	advisories, err := QueryOSVChecked(ctx, ecosystem, name, version)
	if err != nil {
		return nil
	}
	return advisories
}

func QueryOSVChecked(ctx context.Context, ecosystem, name, version string) ([]Advisory, error) {
	if ecosystem == "" || name == "" || version == "" {
		return nil, nil
	}
	reqBody := map[string]any{
		"version": version,
		"package": map[string]string{
			"ecosystem": ecosystem,
			"name":      name,
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := osvHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("OSV query returned %s", resp.Status)
	}
	var doc struct {
		Vulns []struct {
			ID               string          `json:"id"`
			Summary          string          `json:"summary"`
			DatabaseSpecific json.RawMessage `json:"database_specific"`
			Aliases          []string        `json:"aliases"`
			Severity         []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	advisories := make([]Advisory, 0, len(doc.Vulns))
	for _, vuln := range doc.Vulns {
		severity, advisoryType := classifyOSVSignals(vuln.ID, vuln.Aliases, vuln.DatabaseSpecific, vuln.Severity)
		advisories = append(advisories, Advisory{Source: "osv", ID: vuln.ID, Ecosystem: ecosystem, Name: name, Version: version, Severity: severity, Type: advisoryType, Summary: vuln.Summary})
	}
	return advisories, nil
}

func QueryOSVBatchChecked(ctx context.Context, components []ScanObservation) ([][]Advisory, error) {
	if len(components) == 0 {
		return nil, nil
	}
	queries := make([]map[string]any, 0, len(components))
	for _, component := range components {
		queries = append(queries, map[string]any{
			"version": component.Version,
			"package": map[string]string{
				"ecosystem": component.Ecosystem,
				"name":      component.Name,
			},
		})
	}
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := osvHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("OSV batch query returned %s", resp.Status)
	}
	var doc struct {
		Results []struct {
			Vulns []struct {
				ID               string          `json:"id"`
				Summary          string          `json:"summary"`
				DatabaseSpecific json.RawMessage `json:"database_specific"`
				Aliases          []string        `json:"aliases"`
				Severity         []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				} `json:"severity"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	results := make([][]Advisory, len(components))
	for i, result := range doc.Results {
		if i >= len(components) {
			break
		}
		component := components[i]
		for _, vuln := range result.Vulns {
			severity, advisoryType := classifyOSVSignals(vuln.ID, vuln.Aliases, vuln.DatabaseSpecific, vuln.Severity)
			results[i] = append(results[i], Advisory{
				Source: "osv", ID: vuln.ID, Ecosystem: component.Ecosystem, Name: component.Name,
				Version: component.Version, Severity: severity, Type: advisoryType, Summary: vuln.Summary,
			})
		}
	}
	return results, nil
}

func RefreshAdvisories(ctx context.Context, store Store, ecosystem, name, version string, cacheTTL time.Duration) ([]Advisory, []Finding) {
	advisories, err := QueryOSVChecked(ctx, ecosystem, name, version)
	if err == nil {
		entry := AdvisoryCacheEntry{Ecosystem: ecosystem, Name: name, Version: version, CheckedAt: time.Now().UTC(), Advisories: advisories}
		_ = store.PutAdvisoryCache(entry)
		_ = store.RecordAdvisoryChecks(entry)
		return advisories, nil
	}
	if entry, ok := store.FreshAdvisoryCache(ecosystem, name, version, cacheTTL); ok {
		return entry.Advisories, nil
	}
	return nil, []Finding{{
		Code: "advisory_refresh_failed", Severity: "block",
		Message:  "advisory refresh failed and no fresh local cache is available",
		Evidence: err.Error(),
	}}
}

func classifyOSVSignals(id string, aliases []string, databaseSpecific json.RawMessage, severityList []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) (string, string) {
	severity := "unknown"
	advisoryType := ""
	if isMalwareID(id) {
		advisoryType = "malware"
		severity = "critical"
	}
	for _, alias := range aliases {
		if isMalwareID(alias) {
			advisoryType = "malware"
			severity = "critical"
		}
	}
	if len(databaseSpecific) > 0 {
		var fields map[string]any
		if err := json.Unmarshal(databaseSpecific, &fields); err == nil {
			if malicious, ok := fields["malicious"].(bool); ok && malicious {
				advisoryType = "malware"
				severity = "critical"
			}
			if rawSeverity, ok := fields["severity"].(string); ok && rawSeverity != "" {
				severity = strings.ToLower(rawSeverity)
			}
		}
	}
	for _, item := range severityList {
		if severity != "unknown" {
			break
		}
		score := strings.ToLower(item.Score)
		if strings.Contains(score, "critical") || strings.HasPrefix(score, "9.") || strings.HasPrefix(score, "10.") {
			severity = "critical"
		}
	}
	return severity, advisoryType
}

func isMalwareID(id string) bool {
	return strings.HasPrefix(strings.ToUpper(id), "MAL-")
}
