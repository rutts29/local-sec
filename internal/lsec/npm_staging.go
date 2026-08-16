package lsec

import (
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type npmLockedArtifact struct {
	Name      string
	Version   string
	Resolved  string
	Integrity string
}

func stageNPM(ctx context.Context, staging string, analysis CommandAnalysis, version VersionInfo) ([]Artifact, []Finding) {
	npmPath, err := findRealExecutable("npm")
	if err != nil {
		return nil, []Finding{{Code: "missing_tool", Severity: "prompt", Message: "npm is not installed"}}
	}
	spec := selectedSpec(analysis, version, "@")
	if spec == "" {
		return nil, nil
	}
	project := filepath.Join(staging, "npm-project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		return nil, []Finding{{Code: "staging_error", Severity: "prompt", Message: err.Error()}}
	}
	cmd := exec.CommandContext(ctx, npmPath, "install", "--package-lock-only", "--ignore-scripts", "--audit=false", "--fund=false", spec)
	cmd.Dir = project
	cmd.Env = safeEnv(staging)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, []Finding{{Code: "stage_download_failed", Severity: "prompt", Message: "npm lockfile resolution failed", Evidence: limitString(string(out), 400)}}
	}
	locked, findings := parseNPMStagingLockfile(filepath.Join(project, "package-lock.json"))
	if hasBlockingFinding(findings) {
		return nil, findings
	}
	for _, pkg := range locked {
		if finding := downloadNPMTarball(ctx, staging, pkg); finding != nil {
			return nil, []Finding{*finding}
		}
	}
	return collectArtifacts(staging)
}

func parseNPMStagingLockfile(path string) ([]npmLockedArtifact, []Finding) {
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, []Finding{{Code: "npm_lockfile_missing", Severity: "block", File: path, Message: "npm lockfile-only resolution did not create package-lock.json", Evidence: err.Error()}}
	}
	var doc struct {
		Packages map[string]struct {
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
			Link      bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
			Link      bool   `json:"link"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, []Finding{{Code: "npm_lockfile_parse_failed", Severity: "block", File: path, Message: "could not parse package-lock.json", Evidence: err.Error()}}
	}
	var out []npmLockedArtifact
	var findings []Finding
	if len(doc.Packages) > 0 {
		for pkgPath, pkg := range doc.Packages {
			if pkgPath == "" {
				continue
			}
			if pkg.Link {
				findings = append(findings, linkedNPMLockfileFinding(path, pkgPath))
				continue
			}
			name, ok := packageNameFromNodeModulesPath(pkgPath)
			if !ok {
				findings = append(findings, unverifiedNPMLockfilePackagePathFinding(path, pkgPath))
				continue
			}
			artifact, packageFindings := lockedNPMArtifact(path, name, pkg.Version, pkg.Resolved, pkg.Integrity)
			if artifact.Name != "" {
				out = append(out, artifact)
			}
			findings = append(findings, packageFindings...)
		}
	} else {
		for name, dep := range doc.Dependencies {
			if dep.Link {
				findings = append(findings, linkedNPMLockfileFinding(path, name))
				continue
			}
			artifact, depFindings := lockedNPMArtifact(path, name, dep.Version, dep.Resolved, dep.Integrity)
			if artifact.Name != "" {
				out = append(out, artifact)
			}
			findings = append(findings, depFindings...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out, findings
}

func lockedNPMArtifact(file, name, version, resolved, integrity string) (npmLockedArtifact, []Finding) {
	if name == "" || version == "" {
		return npmLockedArtifact{}, []Finding{{Code: "npm_lockfile_missing_version", Severity: "block", File: file, Message: "package-lock entry is missing an exact version", Evidence: name}}
	}
	if findings := npmLockfileResolvedFindings(file, name, version, resolved); len(findings) > 0 {
		return npmLockedArtifact{}, findings
	}
	if integrity == "" {
		return npmLockedArtifact{}, []Finding{{Code: "npm_lockfile_missing_integrity", Severity: "block", File: file, Message: "package-lock entry is missing integrity", Evidence: name + "@" + version}}
	}
	if _, err := parseNPMIntegrity(integrity); err != nil {
		return npmLockedArtifact{}, []Finding{{Code: "npm_lockfile_unsupported_integrity", Severity: "block", File: file, Message: "package-lock entry integrity is missing a supported sha512 or sha1 digest", Evidence: name + "@" + version + " " + integrity}}
	}
	return npmLockedArtifact{Name: name, Version: version, Resolved: resolved, Integrity: integrity}, nil
}

func downloadNPMTarball(ctx context.Context, staging string, pkg npmLockedArtifact) *Finding {
	if _, err := url.Parse(pkg.Resolved); err != nil {
		return &Finding{Code: "npm_tarball_url_invalid", Severity: "block", Message: "npm tarball URL is invalid", Evidence: pkg.Name + " " + pkg.Resolved}
	}
	target := filepath.Join(staging, npmTarballFilename(pkg.Name, pkg.Version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pkg.Resolved, nil)
	if err != nil {
		return &Finding{Code: "npm_tarball_download_failed", Severity: "prompt", Message: err.Error(), Evidence: pkg.Name + "@" + pkg.Version}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &Finding{Code: "npm_tarball_download_failed", Severity: "prompt", Message: err.Error(), Evidence: pkg.Name + "@" + pkg.Version}
	}
	defer resp.Body.Close()
	finalURL := req.URL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL
	}
	if !isAllowedNPMRegistryResolvedURL(finalURL.String()) {
		return &Finding{Code: "npm_tarball_external_redirect", Severity: "block", Message: "npm tarball download redirected outside the npm registry", Evidence: finalURL.String()}
	}
	if resp.StatusCode >= 300 {
		return &Finding{Code: "npm_tarball_download_failed", Severity: "prompt", Message: resp.Status, Evidence: pkg.Name + "@" + pkg.Version}
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return &Finding{Code: "npm_tarball_download_failed", Severity: "prompt", Message: err.Error(), Evidence: pkg.Name + "@" + pkg.Version}
	}
	_, copyErr := io.Copy(&limitedByteWriter{w: f, limit: maxDownloadedFileBytes, remaining: maxDownloadedFileBytes, label: "npm tarball"}, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(target)
		if isLimitExceeded(copyErr) {
			return &Finding{Code: "npm_tarball_too_large", Severity: "block", Message: "npm tarball exceeds size limit", Evidence: pkg.Name + "@" + pkg.Version}
		}
		return &Finding{Code: "npm_tarball_download_failed", Severity: "prompt", Message: copyErr.Error(), Evidence: pkg.Name + "@" + pkg.Version}
	}
	if closeErr != nil {
		_ = os.Remove(target)
		return &Finding{Code: "npm_tarball_download_failed", Severity: "prompt", Message: closeErr.Error(), Evidence: pkg.Name + "@" + pkg.Version}
	}
	if err := verifyNPMTarballIntegrity(target, pkg.Integrity); err != nil {
		_ = os.Remove(target)
		return &Finding{Code: "npm_tarball_integrity_mismatch", Severity: "block", Message: "npm tarball integrity did not match package-lock.json", Evidence: pkg.Name + "@" + pkg.Version + " " + err.Error()}
	}
	return nil
}

func verifyNPMTarballIntegrity(path, integrity string) error {
	expected, err := parseNPMIntegrity(integrity)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return err
	}
	switch expected.algorithm {
	case "sha512":
		sum := sha512.Sum512(body)
		if !bytesEqual(sum[:], expected.digest) {
			return fmt.Errorf("sha512 mismatch")
		}
	case "sha1":
		sum := sha1.Sum(body)
		if !bytesEqual(sum[:], expected.digest) {
			return fmt.Errorf("sha1 mismatch")
		}
	default:
		return fmt.Errorf("unsupported integrity algorithm %q", expected.algorithm)
	}
	return nil
}

type npmIntegrity struct {
	algorithm string
	digest    []byte
}

func parseNPMIntegrity(integrity string) (npmIntegrity, error) {
	for _, algorithm := range []string{"sha512", "sha1"} {
		for _, field := range strings.Fields(integrity) {
			prefix := algorithm + "-"
			if !strings.HasPrefix(field, prefix) {
				continue
			}
			value := strings.TrimPrefix(field, prefix)
			if i := strings.IndexByte(value, '?'); i >= 0 {
				value = value[:i]
			}
			digest, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return npmIntegrity{}, err
			}
			return npmIntegrity{algorithm: algorithm, digest: digest}, nil
		}
	}
	return npmIntegrity{}, fmt.Errorf("unsupported integrity")
}

func npmTarballFilename(name, version string) string {
	name = url.PathEscape(name)
	if name == "" {
		name = "package"
	}
	if version == "" {
		return name + ".tgz"
	}
	return name + "-" + version + ".tgz"
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
