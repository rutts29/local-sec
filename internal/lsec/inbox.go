package lsec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type inboxMarker struct {
	RunID     string    `json:"run_id"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

const (
	inboxDenyAction      = "inbox_deny"
	inboxViewLaterAction = "inbox_view_later"
)

type inboxRun struct {
	report    RunReport
	createdAt time.Time
	marker    inboxMarker
}

func runInbox(args []string, stdout io.Writer, store Store) error {
	if len(args) == 0 {
		return runInboxList(20, stdout, store)
	}
	switch args[0] {
	case "show":
		if len(args) != 2 {
			return errors.New("inbox show requires run_id")
		}
		return runInboxShow(args[1], stdout, store)
	case "approve-once":
		if len(args) < 2 {
			return errors.New("inbox approve-once requires run_id [reason...]")
		}
		return runInboxApproveOnce(args[1], args[2:], stdout, store)
	case "review-llm":
		return runInboxReviewLLM(args[1:], stdout, store)
	case "deny":
		if len(args) < 2 {
			return errors.New("inbox deny requires run_id [reason...]")
		}
		return runInboxMark(inboxDenyAction, args[1], args[2:], store)
	case "view-later":
		if len(args) < 2 {
			return errors.New("inbox view-later requires run_id [reason...]")
		}
		return runInboxMark(inboxViewLaterAction, args[1], args[2:], store)
	default:
		if len(args) > 1 {
			return errors.New("inbox accepts optional limit")
		}
		limit, err := parseInboxLimit(args[0])
		if err != nil {
			return err
		}
		return runInboxList(limit, stdout, store)
	}
}

func runInboxList(limit int, stdout io.Writer, store Store) error {
	approvals, err := store.LoadApprovals()
	if err != nil {
		return err
	}
	runs, err := loadInboxRuns(store)
	if err != nil {
		return err
	}
	wrote := 0
	for _, run := range runs {
		if wrote == limit {
			break
		}
		if run.marker.Action == inboxDenyAction {
			continue
		}
		report := run.report
		if report.Decision.Verdict == VerdictBlock {
			continue
		}
		if report.Decision.Verdict != VerdictPrompt && report.Decision.Lane != LaneRisky {
			continue
		}
		unapprovedArtifacts := unapprovedExactInboxArtifacts(approvals, report.Artifacts)
		if len(unapprovedArtifacts) == 0 {
			continue
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			formatInboxTime(run.createdAt), report.RunID, report.Decision.Verdict, report.Decision.Lane,
			formatInboxMarker(run.marker),
			strings.Join(report.Analysis.Raw, " "), summarizeInboxArtifacts(unapprovedArtifacts))
		wrote++
	}
	return nil
}

func runInboxShow(runID string, stdout io.Writer, store Store) error {
	report, ok, err := store.LoadRunReport(runID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("run %q not found", runID)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(BuildEvidenceBundle(report))
}

func runInboxApproveOnce(runID string, reasonArgs []string, stdout io.Writer, store Store) error {
	report, ok, err := store.LoadRunReport(runID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("run %q not found", runID)
	}
	if report.Decision.Verdict == VerdictBlock {
		return fmt.Errorf("run %q is blocked and cannot be approved", runID)
	}
	evidenceSHA256 := BuildEvidenceBundle(report).EvidenceSHA256
	if blocked, err := latestLLMReviewBlocksApproval(store, runID, evidenceSHA256); err != nil {
		return err
	} else if blocked {
		return fmt.Errorf("run %q latest LLM review blocked approval", runID)
	}
	if len(report.Artifacts) == 0 {
		return fmt.Errorf("run %q has no exact approvable artifacts", runID)
	}
	for _, artifact := range report.Artifacts {
		if !exactInboxArtifact(artifact) {
			return fmt.Errorf("run %q has malformed artifact identity", runID)
		}
	}
	reason := inboxReason(runID, reasonArgs)
	for _, artifact := range report.Artifacts {
		if err := store.AddApproval(Approval{
			Ecosystem: artifact.Ecosystem,
			Name:      artifact.Name,
			Version:   artifact.Version,
			Hash:      artifact.SHA256,
			Reason:    reason,
		}); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "approved %d artifacts for %s\n", len(report.Artifacts), runID)
	return nil
}

func runInboxMark(kind, runID string, reasonArgs []string, store Store) error {
	if _, ok, err := store.LoadRunReport(runID); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("run %q not found", runID)
	}
	return store.AppendEvent(kind, inboxMarker{
		RunID:     runID,
		Action:    kind,
		Reason:    inboxReason(runID, reasonArgs),
		CreatedAt: time.Now().UTC(),
	})
}

func loadInboxRuns(store Store) ([]inboxRun, error) {
	var chronological []inboxRun
	markers := map[string]inboxMarker{}
	if err := store.eventLog().forEach(func(line []byte) error {
		if marker, ok := parseInboxMarker(line); ok {
			markers[marker.RunID] = marker
			return nil
		}
		report, createdAt, ok := parseEventRunReportWithCreatedAt(line)
		if !ok || report.RunID == "" {
			return nil
		}
		chronological = append(chronological, inboxRun{report: report, createdAt: createdAt})
		return nil
	}); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var recent []inboxRun
	for i := len(chronological) - 1; i >= 0; i-- {
		run := chronological[i]
		if seen[run.report.RunID] {
			continue
		}
		seen[run.report.RunID] = true
		run.marker = markers[run.report.RunID]
		recent = append(recent, run)
	}
	return recent, nil
}

func parseInboxMarker(line []byte) (inboxMarker, bool) {
	row, createdAt, ok := parseEventLogRow(line)
	if !ok || !inboxMarkerEventKind(row.Kind) {
		return inboxMarker{}, false
	}
	var marker inboxMarker
	if err := json.Unmarshal(row.JSON, &marker); err != nil || marker.RunID == "" {
		return inboxMarker{}, false
	}
	marker.Action = row.Kind
	if marker.CreatedAt.IsZero() {
		marker.CreatedAt = createdAt
	}
	return marker, true
}

func inboxMarkerEventKind(kind string) bool {
	return kind == inboxDenyAction || kind == inboxViewLaterAction
}

func parseInboxLimit(raw string) (int, error) {
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 {
		return 0, errors.New("inbox limit must be a positive integer")
	}
	return limit, nil
}

func hasExactApprovableArtifact(artifacts []Artifact) bool {
	for _, artifact := range artifacts {
		if exactInboxArtifact(artifact) {
			return true
		}
	}
	return false
}

func exactInboxArtifact(artifact Artifact) bool {
	return artifact.Ecosystem != "" &&
		artifact.Name != "" &&
		artifact.Version != "" &&
		validSHA256Hex(artifact.SHA256)
}

func unapprovedExactInboxArtifacts(approvals []Approval, artifacts []Artifact) []Artifact {
	var unapproved []Artifact
	for _, artifact := range artifacts {
		if !exactInboxArtifact(artifact) {
			continue
		}
		if IsApproved(approvals, artifact.Ecosystem, artifact.Name, artifact.Version, artifact.SHA256) {
			continue
		}
		unapproved = append(unapproved, artifact)
	}
	return unapproved
}

func inboxReason(runID string, args []string) string {
	if len(args) == 0 {
		return "inbox-" + runID
	}
	return strings.Join(args, " ")
}

func summarizeInboxArtifacts(artifacts []Artifact) string {
	var summaries []string
	for _, artifact := range artifacts {
		if !exactInboxArtifact(artifact) {
			continue
		}
		summary := fmt.Sprintf("%s:%s@%s %s", artifact.Ecosystem, artifact.Name, artifact.Version, artifact.SHA256)
		if artifact.Kind != "" {
			summary += " " + artifact.Kind
		}
		summaries = append(summaries, summary)
	}
	return strings.Join(summaries, ", ")
}

func formatInboxMarker(marker inboxMarker) string {
	switch marker.Action {
	case inboxViewLaterAction:
		if marker.Reason == "" {
			return "view-later"
		}
		return "view-later: " + marker.Reason
	case inboxDenyAction:
		if marker.Reason == "" {
			return "deny"
		}
		return "deny: " + marker.Reason
	default:
		return ""
	}
}

func formatInboxTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}
