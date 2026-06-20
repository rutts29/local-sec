package lsec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Approval struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Hash      string    `json:"hash,omitempty"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

type AdvisoryCacheEntry struct {
	Ecosystem  string     `json:"ecosystem"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	CheckedAt  time.Time  `json:"checked_at"`
	Advisories []Advisory `json:"advisories"`
}

type Store struct {
	paths Paths
}

type EventSummary struct {
	Kind      string    `json:"kind"`
	RunID     string    `json:"run_id"`
	Verdict   Verdict   `json:"verdict,omitempty"`
	Lane      RiskLane  `json:"lane,omitempty"`
	Command   string    `json:"command,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type PackageSummary struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Hash      string    `json:"hash"`
	Kind      string    `json:"kind"`
	RunID     string    `json:"run_id"`
	Verdict   Verdict   `json:"verdict"`
	Lane      RiskLane  `json:"lane"`
	Approved  bool      `json:"approved"`
	SeenAt    time.Time `json:"seen_at"`
}

type LocalStatus struct {
	Runs             int
	Packages         int
	Approvals        int
	ApprovedPackages int
	Verdicts         map[Verdict]int
	Lanes            map[RiskLane]int
}

func NewStore(paths Paths) Store {
	return Store{paths: paths}
}

func (s Store) Init() error {
	if err := s.paths.Ensure(); err != nil {
		return err
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil
	}
	schema := `
CREATE TABLE IF NOT EXISTS package_versions(ecosystem TEXT, name TEXT, version TEXT, published_at TEXT, artifact_sha256 TEXT, advisory_status TEXT, socket_status TEXT, first_seen_at TEXT, last_checked_at TEXT, approved_status TEXT, approved_at TEXT, approved_reason TEXT, PRIMARY KEY(ecosystem,name,version));
CREATE TABLE IF NOT EXISTS artifacts(sha256 TEXT PRIMARY KEY, ecosystem TEXT, name TEXT, version TEXT, path TEXT, first_seen_at TEXT);
CREATE TABLE IF NOT EXISTS advisory_checks(id INTEGER PRIMARY KEY, ecosystem TEXT, name TEXT, version TEXT, source TEXT, advisory_id TEXT, severity TEXT, advisory_type TEXT, checked_at TEXT);
CREATE TABLE IF NOT EXISTS static_findings(id INTEGER PRIMARY KEY, run_id TEXT, code TEXT, severity TEXT, file TEXT, message TEXT, evidence TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS resolution_decisions(id TEXT PRIMARY KEY, requested_command TEXT, requested_spec TEXT, selected_spec TEXT, latest_available TEXT, selected_reason TEXT, maturity_days INTEGER, final_verdict TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS approvals(id INTEGER PRIMARY KEY, ecosystem TEXT, name TEXT, version TEXT, hash TEXT, reason TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, run_id TEXT, kind TEXT, json TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS sandbox_runs(id TEXT PRIMARY KEY, run_id TEXT, mode TEXT, verdict TEXT, evidence_json TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS canary_events(id INTEGER PRIMARY KEY, run_id TEXT, kind TEXT, marker TEXT, path TEXT, destination TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS llm_reviews(id INTEGER PRIMARY KEY, run_id TEXT, model TEXT, verdict TEXT, confidence TEXT, evidence_hash TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS skillpack_versions(id INTEGER PRIMARY KEY, name TEXT, version TEXT, sha256 TEXT, loaded_at TEXT);
CREATE TABLE IF NOT EXISTS model_eval_cases(id INTEGER PRIMARY KEY, name TEXT, evidence_json TEXT, expected_verdict TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS scan_runs(run_id TEXT PRIMARY KEY, profile TEXT, backend TEXT, platform TEXT, scanner_version TEXT, config_hash TEXT, policy_hash TEXT, network_mode TEXT, started_at TEXT, finished_at TEXT, status TEXT, inventory_count INTEGER, finding_count INTEGER, diagnostic_count INTEGER);
CREATE TABLE IF NOT EXISTS scan_roots(run_id TEXT, root_id TEXT, root_kind TEXT, path_local TEXT, path_hash TEXT, status TEXT, files_considered INTEGER, files_read INTEGER, skipped_count INTEGER);
CREATE TABLE IF NOT EXISTS component_observations(observation_id TEXT PRIMARY KEY, run_id TEXT, ecosystem TEXT, name TEXT, normalized_name TEXT, version TEXT, purl TEXT, presence_state TEXT, source_type TEXT, source_path_local TEXT, source_path_hash TEXT, project_id TEXT, direct_dependency INTEGER, development_dependency INTEGER, installer TEXT, artifact_sha256 TEXT, confidence TEXT, metadata_hash TEXT, observed_mtime TEXT, observed_size INTEGER);
CREATE TABLE IF NOT EXISTS scan_findings(finding_id TEXT PRIMARY KEY, run_id TEXT, finding_key TEXT, class TEXT, severity TEXT, urgency TEXT, confidence TEXT, presence_state TEXT, component_observation_id TEXT, campaign_id TEXT, advisory_id TEXT, title TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS finding_evidence(finding_id TEXT, provider TEXT, provider_record_id TEXT, evidence_type TEXT, evidence_hash TEXT, captured_at TEXT);
CREATE TABLE IF NOT EXISTS catalog_snapshots(catalog_id TEXT, schema_version TEXT, sequence_number INTEGER, source TEXT, sha256 TEXT, signature_status TEXT, signing_key_id TEXT, generated_at TEXT, fetched_at TEXT, expires_at TEXT);
CREATE TABLE IF NOT EXISTS provider_snapshots(provider TEXT, fetched_at TEXT, expires_at TEXT, etag TEXT, status TEXT, response_hash TEXT);
CREATE TABLE IF NOT EXISTS remediation_candidates(finding_id TEXT, action TEXT, target_version TEXT, artifact_sha256 TEXT, maturity_days INTEGER, advisory_status TEXT, confidence TEXT, rationale TEXT);
CREATE TABLE IF NOT EXISTS finding_state(finding_key TEXT PRIMARY KEY, first_seen_at TEXT, last_seen_at TEXT, resolved_at TEXT, acknowledged_at TEXT, acknowledgement_reason TEXT, suppressed_until TEXT);
CREATE TABLE IF NOT EXISTS scan_diagnostics(run_id TEXT, source_adapter TEXT, path_hash TEXT, code TEXT, message TEXT, severity TEXT);
`
	return runSQLite(s.paths.DB, schema)
}

func (s Store) AppendEvent(kind string, report any) error {
	if err := os.MkdirAll(filepath.Dir(s.paths.Events), 0o700); err != nil {
		return err
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.paths.Events, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		return err
	}
	defer unlockFile(f)
	if _, err := fmt.Fprintf(f, `{"kind":%q,"json":%s,"created_at":%q}`+"\n", kind, body, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := exec.LookPath("sqlite3"); err == nil {
		runID := eventRunID(report)
		sql := fmt.Sprintf("INSERT INTO events(run_id,kind,json,created_at) VALUES('%s','%s','%s','%s');", sqlQuote(runID), sqlQuote(kind), sqlQuote(string(body)), time.Now().UTC().Format(time.RFC3339Nano))
		_ = runSQLite(s.paths.DB, sql)
		if r, ok := report.(RunReport); ok {
			_ = s.RecordRunReport(r)
		}
		if b, ok := report.(EvidenceBundle); ok {
			_ = s.RecordRunReport(b.RunReport())
		}
	}
	return nil
}

func eventRunID(report any) string {
	switch r := report.(type) {
	case RunReport:
		return r.RunID
	case EvidenceBundle:
		return r.RunID
	default:
		return ""
	}
}

func (s Store) LoadEventSummaries(limit int) ([]EventSummary, error) {
	body, err := os.ReadFile(s.paths.Events)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var summaries []EventSummary
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		summary, ok := parseEventSummary([]byte(line))
		if ok {
			summaries = append(summaries, summary)
		}
	}
	for i, j := 0, len(summaries)-1; i < j; i, j = i+1, j-1 {
		summaries[i], summaries[j] = summaries[j], summaries[i]
	}
	if limit > 0 && len(summaries) > limit {
		summaries = summaries[:limit]
	}
	return summaries, nil
}

func (s Store) LoadRunReport(runID string) (RunReport, bool, error) {
	body, err := os.ReadFile(s.paths.Events)
	if os.IsNotExist(err) {
		return RunReport{}, false, nil
	}
	if err != nil {
		return RunReport{}, false, err
	}
	var found RunReport
	ok := false
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		report, lineOK := parseEventRunReport([]byte(line))
		if !lineOK || report.RunID != runID {
			continue
		}
		found = report
		ok = true
	}
	return found, ok, nil
}

func (s Store) LoadSeenMaintainers(ecosystem, name string) ([]string, error) {
	body, err := os.ReadFile(s.paths.Events)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		report, lineOK := parseEventRunReport([]byte(line))
		if !lineOK || !reportMatchesPackage(report, ecosystem, name) {
			continue
		}
		for _, maintainer := range report.Version.Maintainers {
			normalized := strings.ToLower(strings.TrimSpace(maintainer))
			if normalized != "" {
				seen[normalized] = true
			}
		}
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

func (s Store) LoadPackageSummaries(limit int) ([]PackageSummary, error) {
	body, err := os.ReadFile(s.paths.Events)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	approvals, err := s.LoadApprovals()
	if err != nil {
		return nil, err
	}
	var summaries []PackageSummary
	seen := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		report, createdAt, ok := parseEventRunReportWithCreatedAt([]byte(line))
		if !ok {
			continue
		}
		for _, artifact := range report.Artifacts {
			if artifact.Ecosystem == "" || artifact.Name == "" || artifact.Version == "" || artifact.SHA256 == "" {
				continue
			}
			key := strings.Join([]string{artifact.Ecosystem, artifact.Name, artifact.Version, artifact.SHA256}, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			summaries = append(summaries, PackageSummary{
				Ecosystem: artifact.Ecosystem,
				Name:      artifact.Name,
				Version:   artifact.Version,
				Hash:      artifact.SHA256,
				Kind:      artifact.Kind,
				RunID:     report.RunID,
				Verdict:   report.Decision.Verdict,
				Lane:      report.Decision.Lane,
				Approved:  IsApproved(approvals, artifact.Ecosystem, artifact.Name, artifact.Version, artifact.SHA256),
				SeenAt:    createdAt,
			})
		}
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
	events, err := s.LoadEventSummaries(0)
	if err != nil {
		return LocalStatus{}, err
	}
	packages, err := s.LoadPackageSummaries(0)
	if err != nil {
		return LocalStatus{}, err
	}
	approvals, err := s.LoadApprovals()
	if err != nil {
		return LocalStatus{}, err
	}
	uniqueEvents := latestEventByRunID(events)
	status := LocalStatus{
		Runs:      len(uniqueEvents),
		Packages:  len(packages),
		Approvals: len(approvals),
		Verdicts:  map[Verdict]int{},
		Lanes:     map[RiskLane]int{},
	}
	for _, event := range uniqueEvents {
		if event.Verdict != "" {
			status.Verdicts[event.Verdict]++
		}
		if event.Lane != "" {
			status.Lanes[event.Lane]++
		}
	}
	for _, pkg := range packages {
		if pkg.Approved {
			status.ApprovedPackages++
		}
	}
	return status, nil
}

func latestEventByRunID(events []EventSummary) []EventSummary {
	seen := map[string]bool{}
	var unique []EventSummary
	for _, event := range events {
		key := event.RunID
		if key == "" {
			key = event.Kind + "\x00" + event.Command + "\x00" + event.CreatedAt.Format(time.RFC3339Nano)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, event)
	}
	return unique
}

func parseEventSummary(line []byte) (EventSummary, bool) {
	var row struct {
		Kind      string          `json:"kind"`
		JSON      json.RawMessage `json:"json"`
		CreatedAt string          `json:"created_at"`
	}
	if err := json.Unmarshal(line, &row); err != nil {
		return EventSummary{}, false
	}
	var report RunReport
	if err := json.Unmarshal(row.JSON, &report); err != nil {
		return EventSummary{}, false
	}
	createdAt, _ := time.Parse(time.RFC3339Nano, row.CreatedAt)
	return EventSummary{
		Kind:      row.Kind,
		RunID:     report.RunID,
		Verdict:   report.Decision.Verdict,
		Lane:      report.Decision.Lane,
		Command:   strings.Join(report.Analysis.Raw, " "),
		CreatedAt: createdAt,
	}, true
}

func parseEventRunReport(line []byte) (RunReport, bool) {
	report, _, ok := parseEventRunReportWithCreatedAt(line)
	return report, ok
}

func parseEventRunReportWithCreatedAt(line []byte) (RunReport, time.Time, bool) {
	var row struct {
		JSON      json.RawMessage `json:"json"`
		CreatedAt string          `json:"created_at"`
	}
	if err := json.Unmarshal(line, &row); err != nil {
		return RunReport{}, time.Time{}, false
	}
	var report RunReport
	if err := json.Unmarshal(row.JSON, &report); err != nil {
		var bundle EvidenceBundle
		if err := json.Unmarshal(row.JSON, &bundle); err != nil {
			return RunReport{}, time.Time{}, false
		}
		report = bundle.RunReport()
	}
	createdAt, _ := time.Parse(time.RFC3339Nano, row.CreatedAt)
	return report, createdAt, true
}

func (s Store) RecordRunReport(report RunReport) error {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil
	}
	createdAt := report.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	if report.Version.Found && report.Version.Selected.Version != "" && len(report.Analysis.PackageSpecs) > 0 {
		name := report.Analysis.PackageSpecs[0].Name
		ecosystem := ecosystemForManager(report.Analysis.Manager)
		hash := artifactHashFor(report.Artifacts, ecosystem, name, report.Version.Selected.Version)
		if hash == "" {
			hash = artifactHashFor(report.Artifacts, "", name, report.Version.Selected.Version)
		}
		if err := s.recordPackageVersion(ecosystem, name, report.Version.Selected, hash, report.Decision.Verdict, createdAt); err != nil {
			return err
		}
	}
	for _, artifact := range report.Artifacts {
		if err := s.recordArtifact(artifact, createdAt); err != nil {
			return err
		}
		if artifact.Name != "" && artifact.Version != "" {
			version := RegistryVersion{Version: artifact.Version}
			if err := s.recordPackageVersion(artifact.Ecosystem, artifact.Name, version, artifact.SHA256, report.Decision.Verdict, createdAt); err != nil {
				return err
			}
		}
	}
	for _, finding := range report.Findings {
		if err := s.recordStaticFinding(report.RunID, finding, createdAt); err != nil {
			return err
		}
	}
	if err := s.recordReportAdvisories(report.Advisories, createdAt); err != nil {
		return err
	}
	return s.recordResolutionDecision(report, createdAt)
}

func (s Store) recordArtifact(artifact Artifact, seenAt time.Time) error {
	sql := fmt.Sprintf("INSERT OR REPLACE INTO artifacts(sha256,ecosystem,name,version,path,first_seen_at) VALUES('%s','%s','%s','%s','%s','%s');",
		sqlQuote(artifact.SHA256), sqlQuote(artifact.Ecosystem), sqlQuote(artifact.Name), sqlQuote(artifact.Version), sqlQuote(artifact.Path), seenAt.Format(time.RFC3339Nano))
	return runSQLite(s.paths.DB, sql)
}

func (s Store) recordPackageVersion(ecosystem, name string, version RegistryVersion, hash string, verdict Verdict, checkedAt time.Time) error {
	publishedAt := ""
	if !version.PublishedAt.IsZero() {
		publishedAt = version.PublishedAt.Format(time.RFC3339Nano)
	}
	sql := fmt.Sprintf("INSERT OR REPLACE INTO package_versions(ecosystem,name,version,published_at,artifact_sha256,advisory_status,first_seen_at,last_checked_at) VALUES('%s','%s','%s','%s','%s','%s','%s','%s');",
		sqlQuote(ecosystem), sqlQuote(name), sqlQuote(version.Version), sqlQuote(publishedAt), sqlQuote(hash), sqlQuote(string(verdict)), checkedAt.Format(time.RFC3339Nano), checkedAt.Format(time.RFC3339Nano))
	return runSQLite(s.paths.DB, sql)
}

func (s Store) recordStaticFinding(runID string, finding Finding, createdAt time.Time) error {
	sql := fmt.Sprintf("INSERT INTO static_findings(run_id,code,severity,file,message,evidence,created_at) VALUES('%s','%s','%s','%s','%s','%s','%s');",
		sqlQuote(runID), sqlQuote(finding.Code), sqlQuote(finding.Severity), sqlQuote(finding.File), sqlQuote(finding.Message), sqlQuote(finding.Evidence), createdAt.Format(time.RFC3339Nano))
	return runSQLite(s.paths.DB, sql)
}

func (s Store) recordReportAdvisories(advisories []Advisory, checkedAt time.Time) error {
	seen := map[string]bool{}
	for _, advisory := range advisories {
		key := strings.Join([]string{advisory.Source, advisory.ID, advisory.Ecosystem, advisory.Name, advisory.Version}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		sql := fmt.Sprintf("INSERT INTO advisory_checks(ecosystem,name,version,source,advisory_id,severity,advisory_type,checked_at) VALUES('%s','%s','%s','%s','%s','%s','%s','%s');",
			sqlQuote(advisory.Ecosystem), sqlQuote(advisory.Name), sqlQuote(advisory.Version), sqlQuote(advisory.Source), sqlQuote(advisory.ID), sqlQuote(advisory.Severity), sqlQuote(advisory.Type), checkedAt.Format(time.RFC3339Nano))
		if err := runSQLite(s.paths.DB, sql); err != nil {
			return err
		}
	}
	return nil
}

func (s Store) recordResolutionDecision(report RunReport, createdAt time.Time) error {
	requestedSpec := ""
	if len(report.Analysis.PackageSpecs) > 0 {
		requestedSpec = report.Analysis.PackageSpecs[0].Raw
	}
	selectedSpec := report.Version.Selected.Version
	latest := report.Version.Latest.Version
	reason := strings.Join(report.Decision.Reasons, "; ")
	sql := fmt.Sprintf("INSERT OR REPLACE INTO resolution_decisions(id,requested_command,requested_spec,selected_spec,latest_available,selected_reason,maturity_days,final_verdict,created_at) VALUES('%s','%s','%s','%s','%s','%s',%d,'%s','%s');",
		sqlQuote(report.RunID), sqlQuote(strings.Join(report.Analysis.Raw, " ")), sqlQuote(requestedSpec), sqlQuote(selectedSpec), sqlQuote(latest), sqlQuote(reason), DefaultPolicy().MaturityDays, sqlQuote(string(report.Decision.Verdict)), createdAt.Format(time.RFC3339Nano))
	return runSQLite(s.paths.DB, sql)
}

func artifactHashFor(artifacts []Artifact, ecosystem, name, version string) string {
	for _, artifact := range artifacts {
		if ecosystem != "" && artifact.Ecosystem != ecosystem {
			continue
		}
		if artifact.Name == name && artifact.Version == version {
			return artifact.SHA256
		}
	}
	return ""
}

func (s Store) LoadApprovals() ([]Approval, error) {
	body, err := os.ReadFile(s.paths.Approvals)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var approvals []Approval
	if err := json.Unmarshal(body, &approvals); err != nil {
		return nil, err
	}
	return approvals, nil
}

func (s Store) LoadAdvisoryCache() ([]AdvisoryCacheEntry, error) {
	body, err := os.ReadFile(s.paths.AdvisoryCache)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []AdvisoryCacheEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s Store) PutAdvisoryCache(entry AdvisoryCacheEntry) error {
	return withPathLock(s.paths.AdvisoryCache+".lock", func() error {
		return s.putAdvisoryCacheUnlocked(entry)
	})
}

func (s Store) putAdvisoryCacheUnlocked(entry AdvisoryCacheEntry) error {
	entries, err := s.LoadAdvisoryCache()
	if err != nil {
		return err
	}
	replaced := false
	for i := range entries {
		if sameAdvisoryTarget(entries[i], entry.Ecosystem, entry.Name, entry.Version) {
			entries[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, entry)
	}
	body, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.paths.AdvisoryCache), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.paths.AdvisoryCache, body, 0o600)
}

func (s Store) FreshAdvisoryCache(ecosystem, name, version string, ttl time.Duration) (AdvisoryCacheEntry, bool) {
	entries, err := s.LoadAdvisoryCache()
	if err != nil {
		return AdvisoryCacheEntry{}, false
	}
	for _, entry := range entries {
		if !sameAdvisoryTarget(entry, ecosystem, name, version) {
			continue
		}
		if time.Since(entry.CheckedAt) <= ttl {
			return entry, true
		}
	}
	return AdvisoryCacheEntry{}, false
}

func (s Store) RecordAdvisoryChecks(entry AdvisoryCacheEntry) error {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil
	}
	if len(entry.Advisories) == 0 {
		sql := fmt.Sprintf("INSERT INTO advisory_checks(ecosystem,name,version,source,advisory_id,severity,advisory_type,checked_at) VALUES('%s','%s','%s','%s','%s','%s','%s','%s');",
			sqlQuote(entry.Ecosystem), sqlQuote(entry.Name), sqlQuote(entry.Version), "osv", "clean", "", "", entry.CheckedAt.Format(time.RFC3339Nano))
		return runSQLite(s.paths.DB, sql)
	}
	for _, advisory := range entry.Advisories {
		sql := fmt.Sprintf("INSERT INTO advisory_checks(ecosystem,name,version,source,advisory_id,severity,advisory_type,checked_at) VALUES('%s','%s','%s','%s','%s','%s','%s','%s');",
			sqlQuote(entry.Ecosystem), sqlQuote(entry.Name), sqlQuote(entry.Version), sqlQuote(advisory.Source), sqlQuote(advisory.ID), sqlQuote(advisory.Severity), sqlQuote(advisory.Type), entry.CheckedAt.Format(time.RFC3339Nano))
		if err := runSQLite(s.paths.DB, sql); err != nil {
			return err
		}
	}
	return nil
}

func sameAdvisoryTarget(entry AdvisoryCacheEntry, ecosystem, name, version string) bool {
	return entry.Ecosystem == ecosystem && entry.Name == name && entry.Version == version
}

func (s Store) SaveApprovals(approvals []Approval) error {
	return withPathLock(s.paths.Approvals+".lock", func() error {
		return s.saveApprovalsUnlocked(approvals)
	})
}

func (s Store) saveApprovalsUnlocked(approvals []Approval) error {
	body, err := json.MarshalIndent(approvals, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.paths.Approvals), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.paths.Approvals, body, 0o600)
}

func (s Store) AddApproval(approval Approval) error {
	approval.CreatedAt = time.Now().UTC()
	if err := withPathLock(s.paths.Approvals+".lock", func() error {
		approvals, err := s.LoadApprovals()
		if err != nil {
			return err
		}
		replaced := false
		for i := range approvals {
			if sameApprovalTarget(approvals[i], approval) {
				approvals[i] = approval
				replaced = true
				break
			}
		}
		if !replaced {
			approvals = append(approvals, approval)
		}
		return s.saveApprovalsUnlocked(approvals)
	}); err != nil {
		return err
	}
	if _, err := exec.LookPath("sqlite3"); err == nil {
		_ = s.deleteApprovalSQLite(approval.Ecosystem, approval.Name, approval.Version, approval.Hash)
		sql := fmt.Sprintf("INSERT INTO approvals(ecosystem,name,version,hash,reason,created_at) VALUES('%s','%s','%s','%s','%s','%s');",
			sqlQuote(approval.Ecosystem), sqlQuote(approval.Name), sqlQuote(approval.Version), sqlQuote(approval.Hash), sqlQuote(approval.Reason), approval.CreatedAt.Format(time.RFC3339Nano))
		_ = runSQLite(s.paths.DB, sql)
	}
	return nil
}

func sameApprovalTarget(left, right Approval) bool {
	return left.Ecosystem == right.Ecosystem &&
		left.Name == right.Name &&
		left.Version == right.Version &&
		left.Hash == right.Hash
}

func (s Store) RevokeApproval(ecosystem, name, version, hash string) error {
	if err := withPathLock(s.paths.Approvals+".lock", func() error {
		approvals, err := s.LoadApprovals()
		if err != nil {
			return err
		}
		var kept []Approval
		for _, approval := range approvals {
			if approval.Ecosystem == ecosystem && approval.Name == name && approval.Version == version {
				if hash == "" || approval.Hash == hash {
					continue
				}
			}
			kept = append(kept, approval)
		}
		return s.saveApprovalsUnlocked(kept)
	}); err != nil {
		return err
	}
	_ = s.deleteApprovalSQLite(ecosystem, name, version, hash)
	return nil
}

func (s Store) deleteApprovalSQLite(ecosystem, name, version, hash string) error {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil
	}
	conditions := fmt.Sprintf("ecosystem='%s' AND name='%s' AND version='%s'",
		sqlQuote(ecosystem), sqlQuote(name), sqlQuote(version))
	if hash != "" {
		conditions += fmt.Sprintf(" AND hash='%s'", sqlQuote(hash))
	}
	return runSQLite(s.paths.DB, "DELETE FROM approvals WHERE "+conditions+";")
}

func IsApproved(approvals []Approval, ecosystem, name, version, hash string) bool {
	if !validSHA256Hex(hash) {
		return false
	}
	for _, approval := range approvals {
		if approval.Ecosystem != ecosystem || approval.Name != name || approval.Version != version {
			continue
		}
		if validSHA256Hex(approval.Hash) && approval.Hash == hash {
			return true
		}
	}
	return false
}

func ArtifactsApproved(approvals []Approval, artifacts []Artifact) bool {
	if len(artifacts) == 0 {
		return false
	}
	for _, artifact := range artifacts {
		if artifact.Ecosystem == "" || artifact.Name == "" || artifact.Version == "" || artifact.SHA256 == "" {
			return false
		}
		if !IsApproved(approvals, artifact.Ecosystem, artifact.Name, artifact.Version, artifact.SHA256) {
			return false
		}
	}
	return true
}

func sqlQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !('0' <= r && r <= '9') && !('a' <= r && r <= 'f') {
			return false
		}
	}
	return true
}

func runSQLite(dbPath, sql string) error {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil
	}
	return exec.Command("sqlite3", "-cmd", ".timeout 5000", dbPath, sql).Run()
}

func withPathLock(lockPath string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		return err
	}
	defer unlockFile(f)
	return fn()
}

func writeFileAtomic(path string, body []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
