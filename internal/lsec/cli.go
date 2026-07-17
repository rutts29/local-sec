package lsec

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}
	if args[0] == "version" || args[0] == "--version" || args[0] == "-v" {
		PrintVersion(stdout)
		return nil
	}
	if args[0] == "sandbox" {
		request, err := validateSandboxCLI(args[1:])
		if err != nil {
			return err
		}
		paths, err := DefaultPaths()
		if err != nil {
			return err
		}
		store := NewStore(paths)
		if err := store.Init(); err != nil {
			return err
		}
		return runSandboxCLI(request, stdout, store)
	}
	if args[0] == "remote-sandbox" {
		paths, err := DefaultPaths()
		if err != nil {
			return err
		}
		store := NewStore(paths)
		if err := store.Init(); err != nil {
			return err
		}
		return runRemoteSandboxCLI(args[1:], stdout, store)
	}
	if args[0] == "notify" {
		paths, err := DefaultPaths()
		if err != nil {
			return err
		}
		store := NewStore(paths)
		if err := store.Init(); err != nil {
			return err
		}
		return runNotifyCLI(args[1:], stdout, store)
	}
	if args[0] == "macos-detonation" {
		paths, err := DefaultPaths()
		if err != nil {
			return err
		}
		store := NewStore(paths)
		if err := store.Init(); err != nil {
			return err
		}
		return runMacOSDetonationCLI(args[1:], stdout, store)
	}
	paths, err := DefaultPaths()
	if err != nil {
		return err
	}
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		return err
	}

	switch args[0] {
	case "guard":
		if len(args) < 2 {
			return errors.New("guard requires a command")
		}
		return runGuard(args[1:], stdin, stdout, stderr, paths, store)
	case "preflight":
		if len(args) < 2 {
			return errors.New("preflight requires a command")
		}
		report, err := preflight(args[1:], paths, store)
		if err != nil {
			return err
		}
		writeReport(stdout, report)
		return store.AppendEvent("preflight", report)
	case "evidence":
		if len(args) < 2 {
			return errors.New("evidence requires a command")
		}
		report, err := preflight(args[1:], paths, store)
		if err != nil {
			return err
		}
		bundle := BuildEvidenceBundle(report)
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(bundle); err != nil {
			return err
		}
		return store.AppendEvent("evidence", bundle)
	case "install-shims":
		return InstallShims(paths, stdout)
	case "doctor":
		return Doctor(paths, stdout)
	case "scan":
		return runScan(args[1:], stdout, paths, store)
	case "status":
		return runStatus(args[1:], stdout, store)
	case "approvals":
		return runApprovals(args[1:], stdout, store)
	case "inbox":
		return runInbox(args[1:], stdout, store)
	case "notify":
		return runNotifyCLI(args[1:], stdout, store)
	case "history":
		return runHistory(args[1:], stdout, store)
	case "packages":
		return runPackages(args[1:], stdout, store)
	case "show":
		return runShow(args[1:], stdout, store)
	default:
		printUsage(stdout)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runGuard(command []string, stdin io.Reader, stdout, stderr io.Writer, paths Paths, store Store) error {
	report, err := preflight(command, paths, store)
	if err != nil {
		return err
	}
	reportOutput := stdout
	if isDownloader(report.Analysis) {
		reportOutput = stderr
	}
	writeReport(reportOutput, report)
	if err := store.AppendEvent("guard_preflight", report); err != nil {
		return err
	}
	if report.Decision.Verdict == VerdictBlock {
		return errors.New("blocked by local-sec policy")
	}
	if isDownloader(report.Analysis) && !stdoutIsTerminalFunc() {
		return errors.New("blocked downloader output to non-terminal; use preflight and download to a file instead")
	}
	approved := false
	if report.Decision.Verdict == VerdictPrompt {
		approved = promptApproval(stdin, reportOutput)
		if !approved {
			return errors.New("not approved")
		}
	}
	if isDownloader(report.Analysis) {
		return streamStagedDownloaderArtifact(report, stdout)
	}
	finalCommand := rewriteCommandForSelectedVersion(command, report)
	return executeRealCommand(finalCommand, stdin, stdout, stderr)
}

func isDownloader(analysis CommandAnalysis) bool {
	return analysis.Manager == "curl" || analysis.Manager == "wget"
}

func streamStagedDownloaderArtifact(report RunReport, stdout io.Writer) error {
	if len(report.Artifacts) != 1 {
		return errors.New("downloader guard requires exactly one staged artifact")
	}
	f, err := os.Open(report.Artifacts[0].Path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(stdout, f)
	return err
}

func executeRealCommand(command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(command) == 0 {
		return errors.New("empty command")
	}
	realPath, err := findRealExecutable(command[0])
	if err != nil {
		return err
	}
	cmd := exec.Command(realPath, command[1:]...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func findRealExecutable(name string) (string, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return name, nil
	}
	shimDir := os.Getenv("LSEC_SHIM_DIR")
	if shimDir == "" {
		if paths, err := DefaultPaths(); err == nil {
			shimDir = paths.Bin
		}
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if shimDir != "" && filepath.Clean(dir) == filepath.Clean(shimDir) {
			continue
		}
		candidate := filepath.Join(dir, name)
		if pointsIntoShimDir(candidate, shimDir) {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("real executable for %s not found after excluding shim dir", name)
}

func pointsIntoShimDir(candidate, shimDir string) bool {
	if shimDir == "" {
		return false
	}
	info, err := os.Lstat(candidate)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return false
	}
	cleanShimDir, err := filepath.EvalSymlinks(shimDir)
	if err != nil {
		cleanShimDir = filepath.Clean(shimDir)
	}
	rel, err := filepath.Rel(filepath.Clean(cleanShimDir), filepath.Clean(target))
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != "..")
}

func promptApproval(stdin io.Reader, stdout io.Writer) bool {
	fmt.Fprintln(stdout, "Type 'yes' to approve this run once:")
	scanner := bufio.NewScanner(stdin)
	if !scanner.Scan() {
		return false
	}
	return strings.TrimSpace(scanner.Text()) == "yes"
}

func writeReport(w io.Writer, report RunReport) {
	fmt.Fprintf(w, "local-sec run %s\n", report.RunID)
	fmt.Fprintf(w, "command: %s\n", strings.Join(report.Analysis.Raw, " "))
	fmt.Fprintf(w, "verdict: %s\n", report.Decision.Verdict)
	fmt.Fprintf(w, "lane: %s\n", report.Decision.Lane)
	for _, reason := range report.Decision.Reasons {
		fmt.Fprintf(w, "- %s\n", reason)
	}
	if report.Version.Found {
		fmt.Fprintf(w, "selected version: %s\n", report.Version.Selected.Version)
		if report.Version.MatureCandidateSelected {
			fmt.Fprintf(w, "latest skipped: %s\n", report.Version.Latest.Version)
		}
		for _, skipped := range report.Version.Skipped {
			fmt.Fprintf(w, "skipped version: %s (%s", skipped.Version, skipped.Reason)
			if len(skipped.AdvisoryIDs) > 0 {
				fmt.Fprintf(w, ": %s", strings.Join(skipped.AdvisoryIDs, ","))
			}
			fmt.Fprintln(w, ")")
		}
	}
	for _, artifact := range report.Artifacts {
		fmt.Fprintf(w, "artifact[%s]: %s %s\n", artifact.Kind, artifact.SHA256, artifact.Path)
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "finding[%s]: %s %s\n", finding.Severity, finding.Code, finding.File)
	}
}

func runApprovals(args []string, stdout io.Writer, store Store) error {
	if len(args) == 0 {
		return errors.New("approvals requires list, add, or revoke")
	}
	switch args[0] {
	case "list":
		approvals, err := store.LoadApprovals()
		if err != nil {
			return err
		}
		body, _ := json.MarshalIndent(approvals, "", "  ")
		fmt.Fprintln(stdout, string(body))
		return nil
	case "add":
		if len(args) < 5 {
			return errors.New("approvals add requires ecosystem name version sha256 [reason]")
		}
		if strings.TrimSpace(args[4]) == "" {
			return errors.New("approvals add requires a non-empty sha256")
		}
		if !validSHA256Hex(args[4]) {
			return errors.New("approvals add requires a 64-character lowercase hex sha256")
		}
		reason := "manual approval"
		if len(args) > 5 {
			reason = strings.Join(args[5:], " ")
		}
		return store.AddApproval(Approval{Ecosystem: args[1], Name: args[2], Version: args[3], Hash: args[4], Reason: reason})
	case "revoke":
		if len(args) != 4 && len(args) != 5 {
			return errors.New("approvals revoke requires ecosystem name version [sha256]")
		}
		hash := ""
		if len(args) == 5 {
			if !validSHA256Hex(args[4]) {
				return errors.New("approvals revoke requires a 64-character lowercase hex sha256 when hash is provided")
			}
			hash = args[4]
		}
		return store.RevokeApproval(args[1], args[2], args[3], hash)
	case "suggest":
		if len(args) != 2 {
			return errors.New("approvals suggest requires run_id")
		}
		return runApprovalSuggestions(args[1], stdout, store)
	default:
		return fmt.Errorf("unknown approvals command %q", args[0])
	}
}

func runApprovalSuggestions(runID string, stdout io.Writer, store Store) error {
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
	wrote := false
	for _, artifact := range report.Artifacts {
		if artifact.Ecosystem == "" || artifact.Name == "" || artifact.Version == "" || artifact.SHA256 == "" {
			continue
		}
		fmt.Fprintf(stdout, "lsec approvals add %s %s %s %s reviewed-%s\n", artifact.Ecosystem, artifact.Name, artifact.Version, artifact.SHA256, runID)
		wrote = true
	}
	if !wrote {
		return fmt.Errorf("run %q has no exact approvable artifacts", runID)
	}
	return nil
}

func runHistory(args []string, stdout io.Writer, store Store) error {
	limit := 20
	if len(args) > 1 {
		return errors.New("history accepts optional limit")
	}
	if len(args) == 1 {
		var parsed int
		if _, err := fmt.Sscanf(args[0], "%d", &parsed); err != nil || parsed < 1 {
			return errors.New("history limit must be a positive integer")
		}
		limit = parsed
	}
	events, err := store.LoadEventSummaries(limit)
	if err != nil {
		return err
	}
	for _, event := range events {
		created := ""
		if !event.CreatedAt.IsZero() {
			created = event.CreatedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n", created, event.Kind, event.RunID, event.Verdict, event.Lane, event.Command)
	}
	return nil
}

func runStatus(args []string, stdout io.Writer, store Store) error {
	if len(args) != 0 {
		return errors.New("status does not accept arguments")
	}
	status, err := store.LoadStatus()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "runs: %d\n", status.Runs)
	fmt.Fprintf(stdout, "packages: %d\n", status.Packages)
	fmt.Fprintf(stdout, "approvals: %d\n", status.Approvals)
	fmt.Fprintf(stdout, "approved_packages: %d\n", status.ApprovedPackages)
	fmt.Fprintf(stdout, "scan_runs: %d\n", status.ScanRuns)
	fmt.Fprintf(stdout, "partial_scan_runs: %d\n", status.PartialScanRuns)
	fmt.Fprintf(stdout, "scan_findings: %d\n", status.ScanFindings)
	fmt.Fprintf(stdout, "scan_diagnostics: %d\n", status.ScanDiagnostics)
	for _, verdict := range []Verdict{VerdictAllow, VerdictPrompt, VerdictBlock} {
		fmt.Fprintf(stdout, "verdict[%s]: %d\n", verdict, status.Verdicts[verdict])
	}
	for _, lane := range []RiskLane{LaneTrusted, LaneRisky, LaneBlock} {
		fmt.Fprintf(stdout, "lane[%s]: %d\n", lane, status.Lanes[lane])
	}
	return nil
}

func runPackages(args []string, stdout io.Writer, store Store) error {
	limit := 50
	if len(args) > 1 {
		return errors.New("packages accepts optional limit")
	}
	if len(args) == 1 {
		var parsed int
		if _, err := fmt.Sscanf(args[0], "%d", &parsed); err != nil || parsed < 1 {
			return errors.New("packages limit must be a positive integer")
		}
		limit = parsed
	}
	packages, err := store.LoadPackageSummaries(limit)
	if err != nil {
		return err
	}
	for _, pkg := range packages {
		status := "unapproved"
		if pkg.Approved {
			status = "approved"
		}
		seen := ""
		if !pkg.SeenAt.IsZero() {
			seen = pkg.SeenAt.Format(time.RFC3339)
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", seen, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Hash, pkg.Verdict, pkg.Lane, status, pkg.RunID)
	}
	return nil
}

func runShow(args []string, stdout io.Writer, store Store) error {
	if len(args) != 1 {
		return errors.New("show requires run_id")
	}
	report, ok, err := store.LoadRunReport(args[0])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("run %q not found", args[0])
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  lsec guard <command> ...")
	fmt.Fprintln(w, "  lsec preflight <command> ...")
	fmt.Fprintln(w, "  lsec evidence <command> ...")
	fmt.Fprintln(w, "  lsec status")
	fmt.Fprintln(w, "  lsec history [limit]")
	fmt.Fprintln(w, "  lsec packages [limit]")
	fmt.Fprintln(w, "  lsec show <run_id>")
	fmt.Fprintln(w, "  lsec scan --profile baseline|project|deep [--root PATH] [--network off|advisories] [--format table|json|ndjson] [--findings-only] [--redact-paths home|all|hash]")
	fmt.Fprintln(w, "  lsec sandbox run --mode docker-fixture [--docker PATH] -- <command> ...")
	fmt.Fprintln(w, "  lsec remote-sandbox prepare <run_id> [--out PATH]")
	fmt.Fprintln(w, "  lsec remote-sandbox submit-fake <run_id> [--result PATH]")
	fmt.Fprintln(w, "  lsec remote-sandbox submit <run_id> --result PATH")
	fmt.Fprintln(w, "  lsec remote-sandbox run-local <run_id> [--result PATH]")
	fmt.Fprintln(w, "  lsec macos-detonation prepare-fixture <run_id> [--out PATH]")
	fmt.Fprintln(w, "  lsec macos-detonation run-local-fixture <run_id> [--result PATH]")
	fmt.Fprintln(w, "  lsec macos-detonation validate-result --job PATH --result PATH")
	fmt.Fprintln(w, "  lsec macos-detonation run-external <run_id>")
	fmt.Fprintln(w, "  lsec notify plan <run_id> [--out PATH]")
	fmt.Fprintln(w, "  lsec notify list [limit]")
	fmt.Fprintln(w, "  lsec notify mark-sent <notification_id>")
	fmt.Fprintln(w, "  lsec notify send-discord <notification_id>")
	fmt.Fprintln(w, "  lsec install-shims")
	fmt.Fprintln(w, "  lsec doctor")
	fmt.Fprintln(w, "  lsec approvals list|add|revoke|suggest")
	fmt.Fprintln(w, "  lsec inbox [limit]|show|approve-once|deny|view-later|review-llm")
	fmt.Fprintln(w, "  lsec version")
}

func stdoutIsTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

var stdoutIsTerminalFunc = stdoutIsTerminal
