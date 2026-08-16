package lsec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNotifyPlanStdoutJSONRedactsRunSecrets(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	report := rawSecretRunReport()
	report.RunID = "run-notify-1"
	seedRawRunEvent(t, pathsFromRoot(root), report)

	var stdout bytes.Buffer
	err := Run([]string{"notify", "plan", "run-notify-1"}, strings.NewReader(""), &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	body := stdout.String()
	assertNoNotificationSecrets(t, body)
	var payload NotificationPayload
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("stdout is not notification JSON: %q err=%v", body, err)
	}
	if payload.Schema != notificationSchema || payload.Version != 1 || !payload.Redacted {
		t.Fatalf("payload metadata = %#v, want schema/version/redacted", payload)
	}
	if payload.NotificationID == "" || payload.RunID != "run-notify-1" || payload.EvidenceSHA256 == "" {
		t.Fatalf("payload ids = %#v, want notification/run/evidence ids", payload)
	}
	if payload.Command.Manager != "npm" || payload.Command.Action != "install" {
		t.Fatalf("command summary = %#v, want npm install", payload.Command)
	}
	if len(payload.Artifacts) != 1 || payload.Artifacts[0].Name != "pkg" || payload.Artifacts[0].Hash == "" {
		t.Fatalf("artifacts = %#v, want package identity only", payload.Artifacts)
	}

	eventsBody, err := os.ReadFile(pathsFromRoot(root).Events)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(eventsBody), `"kind":"notification_planned"`) {
		t.Fatalf("events = %s, want notification_planned event", eventsBody)
	}
	assertNoNotificationSecrets(t, notificationEventRow(t, string(eventsBody), "notification_planned"))
}

func TestNotifyPlanRedactsLocalPackageSpecs(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	report := rawSecretRunReport()
	report.RunID = "run-notify-local-specs"
	report.Analysis.PackageSpecs = []PackageSpec{
		{Raw: "../secret-project", Name: "../secret-project", LocalPath: true},
		{Raw: "./pkg", Name: "./pkg", LocalPath: true},
		{Raw: "file:../pkg", Name: "file:../pkg", LocalPath: true},
		{Raw: "workspace:../pkg", Name: "workspace:../pkg", Version: "workspace:../pkg", LocalPath: true},
		{Raw: "dist/pkg.whl", Name: "dist/pkg.whl"},
		{Raw: "packages/pkg.tgz", Name: "packages/pkg.tgz"},
		{Raw: "vendor/pkg.tar.gz", Name: "vendor/pkg.tar.gz"},
		{Raw: "@scope/pkg@1.2.3", Name: "@scope/pkg", Version: "1.2.3"},
	}
	seedRawRunEvent(t, pathsFromRoot(root), report)

	var stdout bytes.Buffer
	if err := Run([]string{"notify", "plan", "run-notify-local-specs"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	body := stdout.String()
	for _, forbidden := range []string{"../secret-project", "./pkg", "file:../pkg", "workspace:../pkg", "dist/pkg.whl", "packages/pkg.tgz", "vendor/pkg.tar.gz"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("notification contains unredacted local package spec %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(body, "@scope/pkg") {
		t.Fatalf("notification JSON = %s, want scoped npm package name preserved", body)
	}
	if !strings.Contains(body, "[redacted-local-package-spec]") {
		t.Fatalf("notification JSON = %s, want local package spec redaction marker", body)
	}
}

func TestNotifyPlanOutWritesPrivateFileAndRejectsUnsafePaths(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	report := rawSecretRunReport()
	report.RunID = "run-notify-1"
	seedRawRunEvent(t, pathsFromRoot(root), report)

	out := filepath.Join(t.TempDir(), "private", "notification.json")
	var stdout bytes.Buffer
	if err := Run([]string{"notify", "plan", "run-notify-1", "--out", out}, strings.NewReader(""), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty with --out", stdout.String())
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 0600", got)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertNoNotificationSecrets(t, string(body))

	for _, unsafe := range []string{"notification.json", filepath.Join("..", "notification.json"), filepath.Join(string(filepath.Separator), "tmp", "notification.json")} {
		err := Run([]string{"notify", "plan", "run-notify-1", "--out", unsafe}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil {
			t.Fatalf("unsafe path %q succeeded", unsafe)
		}
	}
}

func TestNotifyListShowsPlannedUnsentNewestFirstAndHidesSent(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	first := NotificationPayload{Schema: notificationSchema, Version: 1, NotificationID: "notif-old", RunID: "run-old", Redacted: true}
	second := NotificationPayload{Schema: notificationSchema, Version: 1, NotificationID: "notif-new", RunID: "run-new", Redacted: true}
	if err := store.AppendEvent("notification_planned", first); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("notification_planned", second); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("notification_sent", NotificationSentEvent{NotificationID: "notif-old", RunID: "run-old", Redacted: true}); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	if err := runNotifyCLI([]string{"list"}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	if !strings.Contains(output, "notif-new") || strings.Contains(output, "notif-old") {
		t.Fatalf("list output = %q, want only unsent newest notification", output)
	}
}

func TestNotifyListDedupesRepeatedPlanRowsNewestFirst(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	first := NotificationPayload{Schema: notificationSchema, Version: 1, NotificationID: "notif-same", RunID: "run-same", CreatedAt: time.Date(2026, 7, 2, 1, 0, 0, 0, time.UTC), Redacted: true}
	second := NotificationPayload{Schema: notificationSchema, Version: 1, NotificationID: "notif-other", RunID: "run-other", CreatedAt: time.Date(2026, 7, 2, 2, 0, 0, 0, time.UTC), Redacted: true}
	third := NotificationPayload{Schema: notificationSchema, Version: 1, NotificationID: "notif-same", RunID: "run-same", CreatedAt: time.Date(2026, 7, 2, 3, 0, 0, 0, time.UTC), Redacted: true}
	for _, payload := range []NotificationPayload{first, second, third} {
		if err := store.AppendEvent("notification_planned", payload); err != nil {
			t.Fatal(err)
		}
	}

	var stdout bytes.Buffer
	if err := runNotifyCLI([]string{"list"}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	if strings.Count(output, "notif-same") != 1 {
		t.Fatalf("list output = %q, want duplicate notification id once", output)
	}
	if strings.Index(output, "notif-same") > strings.Index(output, "notif-other") {
		t.Fatalf("list output = %q, want newest duplicate before older notification", output)
	}
}

func TestNotifyListRejectsTrailingLimitText(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	err := runNotifyCLI([]string{"list", "10x"}, &bytes.Buffer{}, store)
	if err == nil || !strings.Contains(err.Error(), "notify list limit must be a positive integer") {
		t.Fatalf("err = %v, want positive integer limit error", err)
	}
}

func TestNotifyMarkSentUnknownIDErrorsWithoutAppendingSentEvent(t *testing.T) {
	store := NewStore(pathsFromRoot(t.TempDir()))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	planned := NotificationPayload{Schema: notificationSchema, Version: 1, NotificationID: "notif-known", RunID: "run-known", Redacted: true}
	if err := store.AppendEvent("notification_planned", planned); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err := runNotifyCLI([]string{"mark-sent", "notif-missing"}, &stdout, store)
	if err == nil || !strings.Contains(err.Error(), "notification notif-missing not found") {
		t.Fatalf("err = %v, want unknown notification error", err)
	}
	eventsBody, err := os.ReadFile(store.paths.Events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(eventsBody), `"kind":"notification_sent"`) {
		t.Fatalf("events = %s, want no notification_sent row", eventsBody)
	}
}

func TestNotifyMarkSentAppendsRunIDAndHidesFromList(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LSEC_HOME", root)
	planned := NotificationPayload{Schema: notificationSchema, Version: 1, NotificationID: "notif-123", RunID: "run-123", Redacted: true}
	if err := appendNotificationTestEvent(pathsFromRoot(root), "notification_planned", planned); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	if err := Run([]string{"notify", "mark-sent", "notif-123"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "notif-123") {
		t.Fatalf("stdout = %q, want notification id", stdout.String())
	}
	eventsBody, err := os.ReadFile(pathsFromRoot(root).Events)
	if err != nil {
		t.Fatal(err)
	}
	row := notificationEventRow(t, string(eventsBody), "notification_sent")
	if !strings.Contains(row, `"notification_id":"notif-123"`) {
		t.Fatalf("event row = %s, want notification id", row)
	}
	if !strings.Contains(row, `"run_id":"run-123"`) {
		t.Fatalf("event row = %s, want planned run id", row)
	}
	stdout.Reset()
	if err := Run([]string{"notify", "list"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "notif-123") {
		t.Fatalf("list output = %q, want sent notification hidden", stdout.String())
	}
}

func TestNotifyPlanDoesNotInvokeSQLite(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nprintf 'sqlite invoked\\n' >> "+shellQuote(logPath)+"\n")
	t.Setenv("PATH", bin)
	t.Setenv("LSEC_HOME", filepath.Join(root, ".lsec"))
	report := rawSecretRunReport()
	report.RunID = "run-notify-no-sqlite"
	seedRawRunEvent(t, pathsFromRoot(filepath.Join(root, ".lsec")), report)

	var stdout bytes.Buffer
	if err := Run([]string{"notify", "plan", "run-notify-no-sqlite"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("sqlite log stat err = %v, want sqlite3 not invoked", err)
	}
}

func TestNotifyMarkSentDoesNotInvokeSQLite(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(root, "sqlite.log")
	writeFakeTool(t, bin, "sqlite3", "#!/bin/sh\nprintf 'sqlite invoked\\n' >> "+shellQuote(logPath)+"\n")
	t.Setenv("PATH", bin)
	t.Setenv("LSEC_HOME", filepath.Join(root, ".lsec"))
	planned := NotificationPayload{Schema: notificationSchema, Version: 1, NotificationID: "notif-local-only", RunID: "run-local-only", Redacted: true}
	if err := appendNotificationTestEvent(pathsFromRoot(filepath.Join(root, ".lsec")), "notification_planned", planned); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	if err := Run([]string{"notify", "mark-sent", "notif-local-only"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("sqlite log stat err = %v, want sqlite3 not invoked", err)
	}
}

func assertNoNotificationSecrets(t *testing.T, body string) {
	t.Helper()
	assertNoRemoteSandboxSecrets(t, body)
	for _, forbidden := range []string{
		"raw prompt",
		"raw response",
		`"path":`,
		`"evidence":`,
		`"fake_environment":`,
		"OPENAI_API_KEY",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("body contains forbidden value %q: %s", forbidden, body)
		}
	}
}

func notificationEventRow(t *testing.T, events, kind string) string {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(events), "\n") {
		if strings.Contains(line, `"kind":"`+kind+`"`) {
			return line
		}
	}
	t.Fatalf("events = %s, want %s row", events, kind)
	return ""
}

func appendNotificationTestEvent(paths Paths, kind string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return eventLog{path: paths.Events}.append(kind, body, time.Now().UTC())
}
