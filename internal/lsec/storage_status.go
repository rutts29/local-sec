package lsec

import (
	"strings"
	"time"
)

func (s Store) LoadPackageSummaries(limit int) ([]PackageSummary, error) {
	approvals, err := s.LoadApprovals()
	if err != nil {
		return nil, err
	}
	var summaries []PackageSummary
	seen := map[string]bool{}
	err = s.eventLog().forEach(func(line []byte) error {
		report, createdAt, ok := parseEventRunReportWithCreatedAt(line)
		if !ok {
			return nil
		}
		summaries = appendPackageSummaries(summaries, seen, approvals, report, createdAt)
		return nil
	})
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(summaries)-1; i < j; i, j = i+1, j-1 {
		summaries[i], summaries[j] = summaries[j], summaries[i]
	}
	if limit > 0 && len(summaries) > limit {
		summaries = summaries[:limit]
	}
	return summaries, nil
}

func (s Store) LoadStatus() (LocalStatus, error) {
	return s.loadStatus(nil)
}

func (s Store) loadStatus(afterEventSnapshot func()) (LocalStatus, error) {
	approvals, err := s.LoadApprovals()
	if err != nil {
		return LocalStatus{}, err
	}
	snapshot, err := s.loadStatusEventSnapshot(approvals)
	if err != nil {
		return LocalStatus{}, err
	}
	if afterEventSnapshot != nil {
		afterEventSnapshot()
	}
	uniqueEvents := latestEventByRunID(snapshot.events)
	status := LocalStatus{
		Runs:            len(uniqueEvents),
		Packages:        len(snapshot.packages),
		Approvals:       len(approvals),
		ScanRuns:        snapshot.scans.Runs,
		PartialScanRuns: snapshot.scans.PartialRuns,
		ScanFindings:    snapshot.scans.Findings,
		ScanDiagnostics: snapshot.scans.Diagnostics,
		Verdicts:        map[Verdict]int{},
		Lanes:           map[RiskLane]int{},
	}
	for _, event := range uniqueEvents {
		if event.Verdict != "" {
			status.Verdicts[event.Verdict]++
		}
		if event.Lane != "" {
			status.Lanes[event.Lane]++
		}
	}
	for _, pkg := range snapshot.packages {
		if pkg.Approved {
			status.ApprovedPackages++
		}
	}
	return status, nil
}

func appendPackageSummaries(summaries []PackageSummary, seen map[string]bool, approvals []Approval, report RunReport, createdAt time.Time) []PackageSummary {
	for _, artifact := range report.Artifacts {
		if artifact.Ecosystem == "" || artifact.Name == "" || artifact.Version == "" || artifact.SHA256 == "" {
			continue
		}
		key := strings.Join([]string{artifact.Ecosystem, artifact.Name, artifact.Version, artifact.SHA256}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		summaries = append(summaries, PackageSummary{Ecosystem: artifact.Ecosystem, Name: artifact.Name, Version: artifact.Version, Hash: artifact.SHA256, Kind: artifact.Kind, RunID: report.RunID, Verdict: report.Decision.Verdict, Lane: report.Decision.Lane, Approved: IsApproved(approvals, artifact.Ecosystem, artifact.Name, artifact.Version, artifact.SHA256), SeenAt: createdAt})
	}
	return summaries
}

func latestEventByRunID(events []EventSummary) []EventSummary {
	seen := map[string]bool{}
	var unique []EventSummary
	for _, event := range events {
		key := event.RunID
		if key == "" {
			key = event.Kind + "\x00" + event.Command + "\x00" + event.CreatedAt.Format(time.RFC3339Nano)
		}
		if seen[key] || (event.RunID != "" && event.Verdict == "" && hasReportEventForRun(events, event.RunID)) {
			continue
		}
		seen[key] = true
		unique = append(unique, event)
	}
	return unique
}

func hasReportEventForRun(events []EventSummary, runID string) bool {
	for _, event := range events {
		if event.RunID == runID && event.Verdict != "" {
			return true
		}
	}
	return false
}
