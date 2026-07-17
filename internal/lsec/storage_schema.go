package lsec

func (s Store) Init() error {
	if err := s.paths.Ensure(); err != nil {
		return err
	}
	return runSQLite(s.paths.DB, storeSchema)
}

const storeSchema = `
CREATE TABLE IF NOT EXISTS package_versions(ecosystem TEXT, name TEXT, version TEXT, published_at TEXT, artifact_sha256 TEXT, advisory_status TEXT, socket_status TEXT, first_seen_at TEXT, last_checked_at TEXT, approved_status TEXT, approved_at TEXT, approved_reason TEXT, PRIMARY KEY(ecosystem,name,version));
CREATE TABLE IF NOT EXISTS artifacts(sha256 TEXT PRIMARY KEY, ecosystem TEXT, name TEXT, version TEXT, path TEXT, first_seen_at TEXT);
CREATE TABLE IF NOT EXISTS advisory_checks(id INTEGER PRIMARY KEY, ecosystem TEXT, name TEXT, version TEXT, source TEXT, advisory_id TEXT, severity TEXT, advisory_type TEXT, checked_at TEXT);
CREATE TABLE IF NOT EXISTS static_findings(id INTEGER PRIMARY KEY, run_id TEXT, code TEXT, severity TEXT, file TEXT, message TEXT, evidence TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS resolution_decisions(id TEXT PRIMARY KEY, requested_command TEXT, requested_spec TEXT, selected_spec TEXT, latest_available TEXT, selected_reason TEXT, maturity_days INTEGER, final_verdict TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS approvals(id INTEGER PRIMARY KEY, ecosystem TEXT, name TEXT, version TEXT, hash TEXT, reason TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, run_id TEXT, kind TEXT, json TEXT, created_at TEXT);
`
