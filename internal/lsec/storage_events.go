package lsec

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func (s Store) AppendEvent(kind string, report any) error {
	report = sanitizeEventPersistencePayload(report)
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	createdAt := time.Now().UTC()
	if err := s.eventLog().append(kind, body, createdAt); err != nil {
		return err
	}
	if _, err := exec.LookPath("sqlite3"); err == nil {
		runID := eventRunID(report)
		_ = execSQLiteParams(s.paths.DB, "INSERT INTO events(run_id,kind,json,created_at) VALUES(@run_id,@kind,@json,@created_at);", map[string]string{
			"@run_id":     runID,
			"@kind":       kind,
			"@json":       string(body),
			"@created_at": createdAt.Format(time.RFC3339Nano),
		})
		if r, ok := report.(RunReport); ok {
			_ = s.RecordRunReport(r)
		}
		if b, ok := report.(EvidenceBundle); ok {
			_ = s.RecordRunReport(b.RunReport())
		}
	}
	return nil
}

func (s Store) AppendNotificationEvent(kind string, report any) error {
	if kind != "notification_planned" && kind != "notification_sent" {
		return fmt.Errorf("unsupported notification event kind %q", kind)
	}
	report = sanitizeEventPersistencePayload(report)
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return s.eventLog().append(kind, body, time.Now().UTC())
}

func sanitizeEventPersistencePayload(report any) any {
	switch r := report.(type) {
	case RunReport:
		return sanitizeRunReportForPersistence(r)
	case EvidenceBundle:
		return sanitizeEvidenceBundleForPersistence(r)
	case inboxLLMReviewEvent:
		return sanitizeInboxLLMReviewEvent(r)
	default:
		return report
	}
}

func eventRunID(report any) string {
	switch r := report.(type) {
	case RunReport:
		return r.RunID
	case EvidenceBundle:
		return r.RunID
	case ScanSummary:
		return r.RunID
	case remoteSandboxEvent:
		return r.RunID
	case NotificationPayload:
		return r.RunID
	case NotificationSentEvent:
		return r.RunID
	default:
		return ""
	}
}

func (s Store) LoadEventSummaries(limit int) ([]EventSummary, error) {
	var summaries []EventSummary
	err := s.eventLog().forEach(func(line []byte) error {
		summary, ok := parseEventSummary(line)
		if ok {
			summaries = append(summaries, summary)
			if limit > 0 && len(summaries) > limit {
				summaries = summaries[1:]
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	reverseEventSummaries(summaries)
	return summaries, nil
}

func reverseEventSummaries(summaries []EventSummary) {
	for i, j := 0, len(summaries)-1; i < j; i, j = i+1, j-1 {
		summaries[i], summaries[j] = summaries[j], summaries[i]
	}
}

func (s Store) LoadRunReport(runID string) (RunReport, bool, error) {
	var found RunReport
	ok := false
	err := s.eventLog().forEach(func(line []byte) error {
		report, lineOK := parseEventRunReport(line)
		if !lineOK || report.RunID != runID {
			return nil
		}
		found = report
		ok = true
		return nil
	})
	if err != nil {
		return RunReport{}, false, err
	}
	return found, ok, nil
}

func (s Store) LoadSeenMaintainers(ecosystem, name string) ([]string, error) {
	seen := map[string]bool{}
	err := s.eventLog().forEach(func(line []byte) error {
		report, lineOK := parseEventRunReport(line)
		if !lineOK || !reportMatchesPackage(report, ecosystem, name) {
			return nil
		}
		for _, maintainer := range report.Version.Maintainers {
			normalized := strings.ToLower(strings.TrimSpace(maintainer))
			if normalized != "" {
				seen[normalized] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var maintainers []string
	for maintainer := range seen {
		maintainers = append(maintainers, maintainer)
	}
	return maintainers, nil
}

func reportMatchesPackage(report RunReport, ecosystem, name string) bool {
	reportEcosystem := ecosystemForManager(report.Analysis.Manager)
	for _, spec := range report.Analysis.PackageSpecs {
		if (reportEcosystem == "" || reportEcosystem == ecosystem) && spec.Name == name {
			return true
		}
	}
	for _, artifact := range report.Artifacts {
		if artifact.Ecosystem == ecosystem && artifact.Name == name {
			return true
		}
	}
	return false
}

func parseEventSummary(line []byte) (EventSummary, bool) {
	row, createdAt, ok := parseEventLogRow(line)
	if !ok {
		return EventSummary{}, false
	}
	return parseEventSummaryRow(row, createdAt)
}

func parseEventSummaryRow(row eventLogRow, createdAt time.Time) (EventSummary, bool) {
	if row.Kind == "scan" {
		if summary, ok := parseScanSummaryPayload(row.JSON); ok {
			return scanEventSummary(row.Kind, summary, createdAt), true
		}
		return EventSummary{}, false
	}
	if row.Kind == "remote_sandbox" {
		var event remoteSandboxEvent
		if err := json.Unmarshal(row.JSON, &event); err == nil && event.RunID != "" {
			return EventSummary{Kind: row.Kind, RunID: event.RunID, Command: remoteSandboxEventCommand(event), CreatedAt: createdAt}, true
		}
		return EventSummary{}, false
	}
	report, ok := parseRunReportPayload(row.JSON)
	if ok && report.RunID != "" {
		return runReportEventSummary(row.Kind, report, createdAt), true
	}
	return EventSummary{}, false
}

func runReportEventSummary(kind string, report RunReport, createdAt time.Time) EventSummary {
	return EventSummary{Kind: kind, RunID: report.RunID, Verdict: report.Decision.Verdict, Lane: report.Decision.Lane, Command: strings.Join(report.Analysis.Raw, " "), CreatedAt: createdAt}
}

func scanEventSummary(kind string, summary ScanSummary, createdAt time.Time) EventSummary {
	return EventSummary{Kind: kind, RunID: summary.RunID, Command: scanEventCommand(summary), CreatedAt: createdAt}
}

func scanEventCommand(summary ScanSummary) string {
	return fmt.Sprintf("scan --profile %s --backend %s --network %s status=%s inventory=%d findings=%d diagnostics=%d", summary.Profile, summary.Backend, summary.NetworkMode, summary.Status, summary.InventoryCount, summary.FindingCount, summary.DiagnosticCount)
}

func remoteSandboxEventCommand(event remoteSandboxEvent) string {
	return fmt.Sprintf("remote-sandbox status=%s findings=%d", event.Status, event.FindingCount)
}

func parseEventRunReport(line []byte) (RunReport, bool) {
	report, _, ok := parseEventRunReportWithCreatedAt(line)
	return report, ok
}

func parseEventRunReportWithCreatedAt(line []byte) (RunReport, time.Time, bool) {
	row, createdAt, ok := parseEventLogRow(line)
	if !ok || !reportBearingEventKind(row.Kind) {
		return RunReport{}, time.Time{}, false
	}
	report, ok := parseRunReportPayload(row.JSON)
	if !ok {
		return RunReport{}, time.Time{}, false
	}
	return report, createdAt, true
}

func parseRunReportPayload(payload json.RawMessage) (RunReport, bool) {
	var report RunReport
	if err := json.Unmarshal(payload, &report); err != nil {
		var bundle EvidenceBundle
		if err := json.Unmarshal(payload, &bundle); err != nil {
			return RunReport{}, false
		}
		report = bundle.RunReport()
	}
	return report, true
}

func reportBearingEventKind(kind string) bool {
	switch kind {
	case "preflight", "guard_preflight", "evidence", "sandbox_run":
		return true
	default:
		return false
	}
}
