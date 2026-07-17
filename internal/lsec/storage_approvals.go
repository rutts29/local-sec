package lsec

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

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
		if sameAdvisoryTarget(entry, ecosystem, name, version) && time.Since(entry.CheckedAt) <= ttl {
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
		return execSQLiteParams(s.paths.DB, "INSERT INTO advisory_checks(ecosystem,name,version,source,advisory_id,severity,advisory_type,checked_at) VALUES(@ecosystem,@name,@version,@source,@advisory_id,@severity,@advisory_type,@checked_at);", map[string]string{"@ecosystem": entry.Ecosystem, "@name": entry.Name, "@version": entry.Version, "@source": "osv", "@advisory_id": "clean", "@severity": "", "@advisory_type": "", "@checked_at": entry.CheckedAt.Format(time.RFC3339Nano)})
	}
	for _, advisory := range entry.Advisories {
		err := execSQLiteParams(s.paths.DB, "INSERT INTO advisory_checks(ecosystem,name,version,source,advisory_id,severity,advisory_type,checked_at) VALUES(@ecosystem,@name,@version,@source,@advisory_id,@severity,@advisory_type,@checked_at);", map[string]string{"@ecosystem": entry.Ecosystem, "@name": entry.Name, "@version": entry.Version, "@source": advisory.Source, "@advisory_id": advisory.ID, "@severity": advisory.Severity, "@advisory_type": advisory.Type, "@checked_at": entry.CheckedAt.Format(time.RFC3339Nano)})
		if err != nil {
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
		_ = execSQLiteParams(s.paths.DB, "INSERT INTO approvals(ecosystem,name,version,hash,reason,created_at) VALUES(@ecosystem,@name,@version,@hash,@reason,@created_at);", map[string]string{"@ecosystem": approval.Ecosystem, "@name": approval.Name, "@version": approval.Version, "@hash": approval.Hash, "@reason": approval.Reason, "@created_at": approval.CreatedAt.Format(time.RFC3339Nano)})
	}
	return nil
}

func sameApprovalTarget(left, right Approval) bool {
	return left.Ecosystem == right.Ecosystem && left.Name == right.Name && left.Version == right.Version && left.Hash == right.Hash
}

func (s Store) RevokeApproval(ecosystem, name, version, hash string) error {
	if err := withPathLock(s.paths.Approvals+".lock", func() error {
		approvals, err := s.LoadApprovals()
		if err != nil {
			return err
		}
		var kept []Approval
		for _, approval := range approvals {
			if approval.Ecosystem == ecosystem && approval.Name == name && approval.Version == version && (hash == "" || approval.Hash == hash) {
				continue
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
	params := map[string]string{"@ecosystem": ecosystem, "@name": name, "@version": version}
	query := "DELETE FROM approvals WHERE ecosystem=@ecosystem AND name=@name AND version=@version"
	if hash != "" {
		query += " AND hash=@hash"
		params["@hash"] = hash
	}
	return execSQLiteParams(s.paths.DB, query+";", params)
}

func IsApproved(approvals []Approval, ecosystem, name, version, hash string) bool {
	if !validSHA256Hex(hash) {
		return false
	}
	for _, approval := range approvals {
		if approval.Ecosystem == ecosystem && approval.Name == name && approval.Version == version && validSHA256Hex(approval.Hash) && approval.Hash == hash {
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
		if artifact.Ecosystem == "" || artifact.Name == "" || artifact.Version == "" || artifact.SHA256 == "" || !IsApproved(approvals, artifact.Ecosystem, artifact.Name, artifact.Version, artifact.SHA256) {
			return false
		}
	}
	return true
}
