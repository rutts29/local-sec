package lsec

import "encoding/json"

type scanStatusCounts struct {
	Runs        int
	PartialRuns int
	Findings    int
	Diagnostics int
}

type statusEventSnapshot struct {
	events   []EventSummary
	packages []PackageSummary
	scans    scanStatusCounts
}

func (s Store) loadStatusEventSnapshot(approvals []Approval) (statusEventSnapshot, error) {
	var snapshot statusEventSnapshot
	summaries := map[string]ScanSummary{}
	seenPackages := map[string]bool{}
	err := s.eventLog().forEach(func(line []byte) error {
		row, createdAt, ok := parseEventLogRow(line)
		if !ok {
			return nil
		}
		if row.Kind != "scan" {
			if row.Kind == "remote_sandbox" {
				if event, ok := parseEventSummaryRow(row, createdAt); ok {
					snapshot.events = append(snapshot.events, event)
				}
			} else {
				report, ok := parseRunReportPayload(row.JSON)
				if ok {
					if report.RunID != "" {
						snapshot.events = append(snapshot.events, runReportEventSummary(row.Kind, report, createdAt))
					}
					if reportBearingEventKind(row.Kind) {
						snapshot.packages = appendPackageSummaries(snapshot.packages, seenPackages, approvals, report, createdAt)
					}
				}
			}
			return nil
		}
		summary, ok := parseScanSummaryPayload(row.JSON)
		if !ok {
			return nil
		}
		snapshot.events = append(snapshot.events, scanEventSummary(row.Kind, summary, createdAt))
		if validStructuredScanSummary(summary) {
			summaries[summary.RunID] = summary
		}
		return nil
	})
	if err != nil {
		return statusEventSnapshot{}, err
	}
	reverseEventSummaries(snapshot.events)
	snapshot.scans = aggregateScanStatus(summaries)
	return snapshot, nil
}

func parseScanSummaryPayload(payload json.RawMessage) (ScanSummary, bool) {
	var summary ScanSummary
	if err := json.Unmarshal(payload, &summary); err != nil || summary.RunID == "" {
		return ScanSummary{}, false
	}
	return summary, true
}

func validStructuredScanSummary(summary ScanSummary) bool {
	return summary.Type == "scan_summary" &&
		summary.InventoryCount >= 0 &&
		summary.FindingCount >= 0 &&
		summary.DiagnosticCount >= 0
}

func aggregateScanStatus(summaries map[string]ScanSummary) scanStatusCounts {
	counts := scanStatusCounts{Runs: len(summaries)}
	for _, summary := range summaries {
		if summary.Status == "partial" {
			counts.PartialRuns++
		}
		counts.Findings += summary.FindingCount
		counts.Diagnostics += summary.DiagnosticCount
	}
	return counts
}
