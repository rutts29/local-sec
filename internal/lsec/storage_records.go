package lsec

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func (s Store) RecordRunReport(report RunReport) error {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil
	}
	report = sanitizeRunReportForPersistence(report)
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
	return execSQLiteParams(s.paths.DB, "INSERT OR REPLACE INTO artifacts(sha256,ecosystem,name,version,path,first_seen_at) VALUES(@sha256,@ecosystem,@name,@version,@path,@first_seen_at);", map[string]string{"@sha256": artifact.SHA256, "@ecosystem": artifact.Ecosystem, "@name": artifact.Name, "@version": artifact.Version, "@path": artifact.Path, "@first_seen_at": seenAt.Format(time.RFC3339Nano)})
}

func (s Store) recordPackageVersion(ecosystem, name string, version RegistryVersion, hash string, verdict Verdict, checkedAt time.Time) error {
	publishedAt := ""
	if !version.PublishedAt.IsZero() {
		publishedAt = version.PublishedAt.Format(time.RFC3339Nano)
	}
	return execSQLiteParams(s.paths.DB, "INSERT OR REPLACE INTO package_versions(ecosystem,name,version,published_at,artifact_sha256,advisory_status,first_seen_at,last_checked_at) VALUES(@ecosystem,@name,@version,@published_at,@artifact_sha256,@advisory_status,@first_seen_at,@last_checked_at);", map[string]string{"@ecosystem": ecosystem, "@name": name, "@version": version.Version, "@published_at": publishedAt, "@artifact_sha256": hash, "@advisory_status": string(verdict), "@first_seen_at": checkedAt.Format(time.RFC3339Nano), "@last_checked_at": checkedAt.Format(time.RFC3339Nano)})
}

func (s Store) recordStaticFinding(runID string, finding Finding, createdAt time.Time) error {
	return execSQLiteParams(s.paths.DB, "INSERT INTO static_findings(run_id,code,severity,file,message,evidence,created_at) VALUES(@run_id,@code,@severity,@file,@message,@evidence,@created_at);", map[string]string{"@run_id": runID, "@code": finding.Code, "@severity": finding.Severity, "@file": finding.File, "@message": finding.Message, "@evidence": finding.Evidence, "@created_at": createdAt.Format(time.RFC3339Nano)})
}

func (s Store) recordReportAdvisories(advisories []Advisory, checkedAt time.Time) error {
	seen := map[string]bool{}
	for _, advisory := range advisories {
		key := strings.Join([]string{advisory.Source, advisory.ID, advisory.Ecosystem, advisory.Name, advisory.Version}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		err := execSQLiteParams(s.paths.DB, "INSERT INTO advisory_checks(ecosystem,name,version,source,advisory_id,severity,advisory_type,checked_at) VALUES(@ecosystem,@name,@version,@source,@advisory_id,@severity,@advisory_type,@checked_at);", map[string]string{"@ecosystem": advisory.Ecosystem, "@name": advisory.Name, "@version": advisory.Version, "@source": advisory.Source, "@advisory_id": advisory.ID, "@severity": advisory.Severity, "@advisory_type": advisory.Type, "@checked_at": checkedAt.Format(time.RFC3339Nano)})
		if err != nil {
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
	return execSQLiteParams(s.paths.DB, "INSERT OR REPLACE INTO resolution_decisions(id,requested_command,requested_spec,selected_spec,latest_available,selected_reason,maturity_days,final_verdict,created_at) VALUES(@id,@requested_command,@requested_spec,@selected_spec,@latest_available,@selected_reason,@maturity_days,@final_verdict,@created_at);", map[string]string{"@id": report.RunID, "@requested_command": strings.Join(report.Analysis.Raw, " "), "@requested_spec": requestedSpec, "@selected_spec": report.Version.Selected.Version, "@latest_available": report.Version.Latest.Version, "@selected_reason": strings.Join(report.Decision.Reasons, "; "), "@maturity_days": fmt.Sprintf("%d", DefaultPolicy().MaturityDays), "@final_verdict": string(report.Decision.Verdict), "@created_at": createdAt.Format(time.RFC3339Nano)})
}

func artifactHashFor(artifacts []Artifact, ecosystem, name, version string) string {
	for _, artifact := range artifacts {
		if (ecosystem == "" || artifact.Ecosystem == ecosystem) && artifact.Name == name && artifact.Version == version {
			return artifact.SHA256
		}
	}
	return ""
}
