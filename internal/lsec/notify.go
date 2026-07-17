package lsec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const discordWebhookTimeout = 10 * time.Second

func discordHTTPClient() *http.Client {
	return &http.Client{
		Timeout: discordWebhookTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("discord webhook too many redirects")
			}
			if req.URL == nil {
				return errors.New("discord webhook redirect missing URL")
			}
			if err := validateDiscordWebhookURL(req.URL.String()); err != nil {
				return fmt.Errorf("discord webhook redirect rejected: %w", err)
			}
			return nil
		},
	}
}

const notificationSchema = "local-sec.notification.plan"

type NotificationPayload struct {
	Schema         string                 `json:"schema"`
	Version        int                    `json:"version"`
	NotificationID string                 `json:"notification_id"`
	RunID          string                 `json:"run_id"`
	EvidenceSHA256 string                 `json:"evidence_sha256"`
	Verdict        Verdict                `json:"verdict"`
	Lane           RiskLane               `json:"lane"`
	Command        NotificationCommand    `json:"command"`
	Artifacts      []NotificationArtifact `json:"artifacts"`
	Risk           NotificationRisk       `json:"risk"`
	CreatedAt      time.Time              `json:"created_at"`
	Redacted       bool                   `json:"redacted"`
}

type NotificationCommand struct {
	Manager  string                        `json:"manager,omitempty"`
	Action   string                        `json:"action,omitempty"`
	Packages []NotificationPackageIdentity `json:"packages,omitempty"`
}

type NotificationPackageIdentity struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type NotificationArtifact struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Hash      string `json:"hash,omitempty"`
}

type NotificationRisk struct {
	Reasons    []string                     `json:"reasons,omitempty"`
	Flags      []NotificationFindingSummary `json:"flags,omitempty"`
	Findings   []NotificationFindingSummary `json:"findings,omitempty"`
	Advisories []NotificationFindingSummary `json:"advisories,omitempty"`
}

type NotificationFindingSummary struct {
	Code     string `json:"code,omitempty"`
	Severity string `json:"severity,omitempty"`
	Message  string `json:"message,omitempty"`
}

type NotificationSentEvent struct {
	NotificationID string    `json:"notification_id"`
	RunID          string    `json:"run_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	Redacted       bool      `json:"redacted"`
}

func runNotifyCLI(args []string, stdout io.Writer, store Store) error {
	if len(args) == 0 {
		return errors.New("notify requires a subcommand")
	}
	switch args[0] {
	case "plan":
		if len(args) < 2 {
			return errors.New("notify plan requires run_id")
		}
		out, err := parseRemoteSandboxPathFlag(args[2:], "--out")
		if err != nil {
			return err
		}
		payload, err := PlanNotification(store, args[1], time.Now().UTC())
		if err != nil {
			return err
		}
		if err := writeRemoteSandboxJSON(stdout, out, payload); err != nil {
			return err
		}
		return store.AppendNotificationEvent("notification_planned", payload)
	case "list":
		limit, err := parseNotifyLimit(args[1:])
		if err != nil {
			return err
		}
		notifications, err := store.LoadUnsentNotifications(limit)
		if err != nil {
			return err
		}
		for _, notification := range notifications {
			created := ""
			if !notification.CreatedAt.IsZero() {
				created = notification.CreatedAt.Format(time.RFC3339)
			}
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n", created, notification.NotificationID, notification.RunID, notification.Verdict, notification.Lane, notification.EvidenceSHA256)
		}
		return nil
	case "mark-sent":
		if len(args) != 2 || strings.TrimSpace(args[1]) == "" {
			return errors.New("notify mark-sent requires notification_id")
		}
		notificationID := strings.TrimSpace(args[1])
		planned, ok, err := store.LoadPlannedNotification(notificationID)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("notification %s not found in planned notifications", notificationID)
		}
		event := NotificationSentEvent{NotificationID: notificationID, RunID: planned.RunID, CreatedAt: time.Now().UTC(), Redacted: true}
		if err := store.AppendNotificationEvent("notification_sent", event); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "notification marked sent locally: %s\n", notificationID)
		return nil
	case "send-discord":
		if len(args) != 2 || strings.TrimSpace(args[1]) == "" {
			return errors.New("notify send-discord requires notification_id")
		}
		return sendDiscordNotification(store, strings.TrimSpace(args[1]), stdout)
	default:
		return fmt.Errorf("unknown notify subcommand %q", args[0])
	}
}

func sendDiscordNotification(store Store, notificationID string, stdout io.Writer) error {
	planned, ok, err := store.LoadPlannedNotification(notificationID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("notification %s not found in planned notifications", notificationID)
	}
	webhook := strings.TrimSpace(os.Getenv("LSEC_DISCORD_WEBHOOK_URL"))
	if webhook == "" {
		return errors.New("LSEC_DISCORD_WEBHOOK_URL is required for notify send-discord")
	}
	if err := validateDiscordWebhookURL(webhook); err != nil {
		return err
	}
	body, err := discordWebhookBody(planned)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := discordHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned %s", resp.Status)
	}
	event := NotificationSentEvent{NotificationID: notificationID, RunID: planned.RunID, CreatedAt: time.Now().UTC(), Redacted: true}
	if err := store.AppendNotificationEvent("notification_sent", event); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "notification sent to discord: %s\n", notificationID)
	return nil
}

func validateDiscordWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid discord webhook URL")
	}
	if u.Scheme != "https" {
		return errors.New("discord webhook URL must use https")
	}
	host := strings.ToLower(u.Hostname())
	if host != "discord.com" && host != "discordapp.com" {
		return errors.New("discord webhook URL host must be discord.com or discordapp.com")
	}
	if !strings.HasPrefix(u.Path, "/api/webhooks/") {
		return errors.New("discord webhook URL path must start with /api/webhooks/")
	}
	return nil
}

func discordWebhookBody(payload NotificationPayload) ([]byte, error) {
	content := fmt.Sprintf(
		"local-sec review\nrun_id=%s\nverdict=%s\nlane=%s\nevidence=%s\nnotification_id=%s\nmanager=%s action=%s",
		payload.RunID, payload.Verdict, payload.Lane, payload.EvidenceSHA256, payload.NotificationID, payload.Command.Manager, payload.Command.Action,
	)
	if len(payload.Risk.Reasons) > 0 {
		content += "\nreason=" + payload.Risk.Reasons[0]
	}
	// Discord content hard limit is 2000 characters; keep redacted summary short.
	if len(content) > 1800 {
		content = content[:1800]
	}
	return json.Marshal(map[string]string{"content": content})
}

func parseNotifyLimit(args []string) (int, error) {
	limit := 20
	if len(args) > 1 {
		return 0, errors.New("notify list accepts optional limit")
	}
	if len(args) == 1 {
		parsed, err := strconv.Atoi(args[0])
		if err != nil || parsed < 1 {
			return 0, errors.New("notify list limit must be a positive integer")
		}
		limit = parsed
	}
	return limit, nil
}

func PlanNotification(store Store, runID string, now time.Time) (NotificationPayload, error) {
	report, ok, err := store.LoadRunReport(runID)
	if err != nil {
		return NotificationPayload{}, err
	}
	if !ok {
		return NotificationPayload{}, fmt.Errorf("run %s not found", runID)
	}
	evidence := BuildRemoteSandboxEvidenceBundle(report)
	payload := NotificationPayload{
		Schema:         notificationSchema,
		Version:        1,
		RunID:          runID,
		EvidenceSHA256: evidence.EvidenceSHA256,
		Verdict:        evidence.Decision.Verdict,
		Lane:           evidence.Decision.Lane,
		Command:        notificationCommandSummary(evidence.Analysis),
		Artifacts:      notificationArtifactIdentities(evidence.Artifacts),
		Risk:           notificationRiskSummary(evidence),
		CreatedAt:      now.UTC(),
		Redacted:       true,
	}
	payload.NotificationID = notificationID(payload.Schema, payload.RunID, payload.EvidenceSHA256)
	return payload, nil
}

func notificationCommandSummary(analysis CommandAnalysis) NotificationCommand {
	command := NotificationCommand{
		Manager: redactEvidenceValue(analysis.Manager),
		Action:  redactEvidenceValue(analysis.Action),
	}
	for _, spec := range analysis.PackageSpecs {
		command.Packages = append(command.Packages, NotificationPackageIdentity{
			Name:    redactEvidenceValue(spec.Name),
			Version: redactEvidenceValue(spec.Version),
		})
	}
	return command
}

func notificationArtifactIdentities(artifacts []Artifact) []NotificationArtifact {
	identities := make([]NotificationArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		identities = append(identities, NotificationArtifact{
			Ecosystem: redactEvidenceValue(artifact.Ecosystem),
			Name:      redactEvidenceValue(artifact.Name),
			Version:   redactEvidenceValue(artifact.Version),
			Hash:      redactEvidenceValue(artifact.SHA256),
		})
	}
	return identities
}

func notificationRiskSummary(evidence EvidenceBundle) NotificationRisk {
	risk := NotificationRisk{
		Reasons: redactRemoteSandboxStrings(evidence.Decision.Reasons),
	}
	for _, flag := range evidence.Analysis.RiskFlags {
		risk.Flags = append(risk.Flags, NotificationFindingSummary{
			Code:     redactEvidenceValue(flag.Code),
			Severity: redactEvidenceValue(flag.Severity),
			Message:  redactRemoteSandboxTranscriptField(redactEvidenceText(flag.Message)),
		})
	}
	for _, finding := range evidence.Findings {
		risk.Findings = append(risk.Findings, NotificationFindingSummary{
			Code:     redactEvidenceValue(finding.Code),
			Severity: redactEvidenceValue(finding.Severity),
			Message:  redactRemoteSandboxTranscriptField(redactEvidenceText(finding.Message)),
		})
	}
	for _, advisory := range evidence.Advisories {
		risk.Advisories = append(risk.Advisories, NotificationFindingSummary{
			Code:     redactEvidenceValue(advisory.ID),
			Severity: redactEvidenceValue(advisory.Severity),
			Message:  redactEvidenceText(advisory.Summary),
		})
	}
	return risk
}

func notificationID(schema, runID, evidenceSHA256 string) string {
	sum := sha256.Sum256([]byte(schema + "\x00" + runID + "\x00" + evidenceSHA256))
	return "notif_" + hex.EncodeToString(sum[:])[:24]
}

func (s Store) LoadPlannedNotification(notificationID string) (NotificationPayload, bool, error) {
	var found NotificationPayload
	ok := false
	err := s.eventLog().forEach(func(line []byte) error {
		row, createdAt, rowOK := parseEventLogRow(line)
		if !rowOK || row.Kind != "notification_planned" {
			return nil
		}
		var payload NotificationPayload
		if err := json.Unmarshal(row.JSON, &payload); err != nil || payload.NotificationID != notificationID {
			return nil
		}
		if payload.CreatedAt.IsZero() {
			payload.CreatedAt = createdAt
		}
		found = payload
		ok = true
		return nil
	})
	if err != nil {
		return NotificationPayload{}, false, err
	}
	return found, ok, nil
}

func (s Store) LoadUnsentNotifications(limit int) ([]NotificationPayload, error) {
	var planned []NotificationPayload
	sent := map[string]bool{}
	err := s.eventLog().forEach(func(line []byte) error {
		row, createdAt, ok := parseEventLogRow(line)
		if !ok {
			return nil
		}
		switch row.Kind {
		case "notification_planned":
			var payload NotificationPayload
			if err := json.Unmarshal(row.JSON, &payload); err != nil || payload.NotificationID == "" {
				return nil
			}
			if payload.CreatedAt.IsZero() {
				payload.CreatedAt = createdAt
			}
			planned = append(planned, payload)
		case "notification_sent":
			var event NotificationSentEvent
			if err := json.Unmarshal(row.JSON, &event); err != nil || event.NotificationID == "" {
				return nil
			}
			sent[event.NotificationID] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var unsent []NotificationPayload
	seen := map[string]bool{}
	for i := len(planned) - 1; i >= 0; i-- {
		notificationID := planned[i].NotificationID
		if seen[notificationID] {
			continue
		}
		seen[notificationID] = true
		if sent[notificationID] {
			continue
		}
		unsent = append(unsent, planned[i])
		if limit > 0 && len(unsent) >= limit {
			break
		}
	}
	return unsent, nil
}
