package lsec

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPlanNotificationIsRedactedAndDeterministic(t *testing.T) {
	root := t.TempDir()
	paths := pathsFromRoot(root)
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := RunReport{
		RunID: "run-notify-1",
		Analysis: CommandAnalysis{
			Manager: "npm",
			Action:  "install",
			Raw:     []string{"npm", "install", "left-pad@1.3.0"},
			PackageSpecs: []PackageSpec{{
				Raw: "left-pad@1.3.0", Name: "left-pad", Version: "1.3.0",
			}},
			RiskFlags: []RiskFlag{{Code: "one_shot_exec", Severity: "prompt", Message: "review"}},
		},
		Version: VersionInfo{Found: true, Selected: RegistryVersion{Version: "1.3.0"}},
		Artifacts: []Artifact{{
			Path: filepath.Join(root, "secret-project", "left-pad.tgz"), Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", SHA256: strings.Repeat("ab", 32), Kind: "tar",
		}},
		Findings:  []Finding{{Code: "first_seen_package", Severity: "prompt", Message: "new package", File: filepath.Join(root, "secret-project", "pkg")}},
		Decision:  Decision{Verdict: VerdictPrompt, Lane: LaneRisky, Reasons: []string{"package has not been seen"}},
		CreatedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}

	payload, err := PlanNotification(store, report.RunID, time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if payload.NotificationID == "" || payload.RunID != report.RunID || !payload.Redacted {
		t.Fatalf("payload = %#v", payload)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-project", root} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("notification leaked %q: %s", forbidden, body)
		}
	}
}

func TestNotifyMarkSentTracksLocalBookkeeping(t *testing.T) {
	root := t.TempDir()
	store := NewStore(pathsFromRoot(root))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := RunReport{
		RunID:     "run-notify-2",
		Analysis:  CommandAnalysis{Manager: "npm", Action: "install", Raw: []string{"npm", "install", "x"}},
		Decision:  Decision{Verdict: VerdictPrompt, Lane: LaneRisky, Reasons: []string{"review"}},
		CreatedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runNotifyCLI([]string{"plan", report.RunID}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	var planned NotificationPayload
	if err := json.Unmarshal(stdout.Bytes(), &planned); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runNotifyCLI([]string{"mark-sent", planned.NotificationID}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	unsent, err := store.LoadUnsentNotifications(20)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range unsent {
		if item.NotificationID == planned.NotificationID {
			t.Fatalf("notification still unsent after mark-sent: %#v", unsent)
		}
	}
}

func TestValidateDiscordWebhookURL(t *testing.T) {
	tests := map[string]bool{
		"https://discord.com/api/webhooks/123/abc":    true,
		"https://discordapp.com/api/webhooks/123/abc": true,
		"http://discord.com/api/webhooks/123/abc":     false,
		"https://evil.example/api/webhooks/123/abc":   false,
		"https://discord.com/not-webhooks/123/abc":    false,
	}
	for raw, wantOK := range tests {
		err := validateDiscordWebhookURL(raw)
		if wantOK && err != nil {
			t.Fatalf("validateDiscordWebhookURL(%q) = %v, want nil", raw, err)
		}
		if !wantOK && err == nil {
			t.Fatalf("validateDiscordWebhookURL(%q) = nil, want error", raw)
		}
	}
}

func TestDiscordWebhookBodyIsRedactedSummary(t *testing.T) {
	payload := NotificationPayload{
		Schema:         notificationSchema,
		Version:        1,
		NotificationID: "note-1",
		RunID:          "run-1",
		EvidenceSHA256: strings.Repeat("ab", 32),
		Verdict:        VerdictPrompt,
		Lane:           LaneRisky,
		Command:        NotificationCommand{Manager: "npm", Action: "install"},
		Risk:           NotificationRisk{Reasons: []string{"fresh package"}},
		CreatedAt:      time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC),
		Redacted:       true,
	}
	body, err := discordWebhookBody(payload)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]string
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	content := doc["content"]
	for _, want := range []string{"run-1", "prompt", "note-1", "npm"} {
		if !strings.Contains(content, want) {
			t.Fatalf("content = %q, want %q", content, want)
		}
	}
	for _, forbidden := range []string{"/Users/", "token=", "password"} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("content leaked %q: %q", forbidden, content)
		}
	}
}

func TestNotifySendDiscordRequiresWebhook(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LSEC_DISCORD_WEBHOOK_URL", "")
	err := runNotifyCLI([]string{"send-discord", "missing"}, &bytes.Buffer{}, store)
	if err == nil {
		t.Fatal("expected error without webhook env")
	}
}

func TestDiscordHTTPClientRejectsNonDiscordRedirect(t *testing.T) {
	client := discordHTTPClient()
	if client.Timeout != discordWebhookTimeout {
		t.Fatalf("timeout = %v, want %v", client.Timeout, discordWebhookTimeout)
	}
	req, err := http.NewRequest(http.MethodGet, "https://evil.example/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(req, []*http.Request{req}); err == nil {
		t.Fatal("expected non-discord redirect rejection")
	}
	okReq, err := http.NewRequest(http.MethodGet, "https://discord.com/api/webhooks/1/abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(okReq, []*http.Request{okReq}); err != nil {
		t.Fatalf("unexpected reject for valid discord hop: %v", err)
	}
}
