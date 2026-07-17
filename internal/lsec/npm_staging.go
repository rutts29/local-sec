package lsec

import (
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func npmRegistryHTTPClient() *http.Client {
	base := http.DefaultClient
	if base == nil {
		base = &http.Client{}
	}
	client := *base
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("npm tarball too many redirects")
		}
		if req.URL == nil || !isAllowedNPMRegistryResolvedURL(req.URL.String()) {
			host := ""
			if req.URL != nil {
				host = req.URL.String()
			}
			return fmt.Errorf("npm tarball redirect outside registry: %s", host)
		}
		return nil
	}
	return &client
}

func isNPMRegistryRedirectRejected(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "redirect outside registry") || strings.Contains(msg, "too many redirects")
}

type npmLockedArtifact = npmLockedPackage

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
	artifacts, findings := collectArtifacts(staging)
	if seedFindings := seedNPMOfflineCache(ctx, staging, artifacts); len(seedFindings) > 0 {
		findings = append(findings, seedFindings...)
	}
	return artifacts, findings
}

func seedNPMOfflineCache(ctx context.Context, staging string, artifacts []Artifact) []Finding {
	tarballs := npmStagedTarballs(artifacts)
	// Seed whenever more than one tarball is present, or when any one-shot path may
	// need offline package promotion (exec/init/npx rewrite uses the cache).
	if len(tarballs) == 0 {
		return nil
	}
	if len(tarballs) == 1 {
		// Single install root uses the tarball path; still seed for exec/create rewrites.
		// Cheap and keeps promotion deterministic.
	}
	cacheDir, ok := npmOfflineCacheDir(artifacts)
	if !ok {
		return []Finding{{Code: "npm_offline_cache_unavailable", Severity: "block", Message: "could not determine offline cache directory for staged npm tarballs"}}
	}
	npmPath, err := findRealExecutable("npm")
	if err != nil {
		return []Finding{{Code: "missing_tool", Severity: "prompt", Message: "npm is not installed"}}
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return []Finding{{Code: "npm_offline_cache_failed", Severity: "block", Message: "could not create npm offline cache", Evidence: err.Error()}}
	}
	for _, artifact := range tarballs {
		cmd := exec.CommandContext(ctx, npmPath, "cache", "add", artifact.Path, "--cache", cacheDir)
		cmd.Env = safeEnv(staging)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return []Finding{{
				Code:     "npm_offline_cache_failed",
				Severity: "block",
				Message:  "failed to seed npm offline cache with staged tarball",
				Evidence: artifact.Name + "@" + artifact.Version + " " + limitString(string(out), 400),
			}}
		}
	}
	return nil
}

func parseNPMStagingLockfile(path string) ([]npmLockedArtifact, []Finding) {
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, []Finding{{Code: "npm_lockfile_missing", Severity: "block", File: path, Message: "npm lockfile-only resolution did not create package-lock.json", Evidence: err.Error()}}
	}
	locked, findings := parseNPMLockfileDocument(path, body)
	verified := make([]npmLockedArtifact, 0, len(locked))
	for _, pkg := range locked {
		if _, err := parseNPMIntegrity(pkg.Integrity); err != nil {
			findings = append(findings, Finding{Code: "npm_lockfile_unsupported_integrity", Severity: "block", File: path, Message: "package-lock entry integrity is missing a supported sha512 or sha1 digest", Evidence: pkg.Name + "@" + pkg.Version + " " + pkg.Integrity})
			continue
		}
		verified = append(verified, pkg)
	}
	return verified, findings
}

func downloadNPMTarball(ctx context.Context, staging string, pkg npmLockedArtifact) *Finding {
	if _, err := url.Parse(pkg.Resolved); err != nil {
		return &Finding{Code: "npm_tarball_url_invalid", Severity: "block", Message: "npm tarball URL is invalid", Evidence: pkg.Name + " " + pkg.Resolved}
	}
	if !isAllowedNPMRegistryResolvedURL(pkg.Resolved) {
		return &Finding{Code: "npm_tarball_external_source", Severity: "block", Message: "npm tarball URL is outside the npm registry", Evidence: pkg.Name + " " + pkg.Resolved}
	}
	target := filepath.Join(staging, npmTarballFilename(pkg.Name, pkg.Version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pkg.Resolved, nil)
	if err != nil {
		return &Finding{Code: "npm_tarball_download_failed", Severity: "prompt", Message: err.Error(), Evidence: pkg.Name + "@" + pkg.Version}
	}
	resp, err := npmRegistryHTTPClient().Do(req)
	if err != nil {
		if isNPMRegistryRedirectRejected(err) {
			return &Finding{Code: "npm_tarball_external_redirect", Severity: "block", Message: "npm tarball download redirected outside the npm registry", Evidence: pkg.Name + "@" + pkg.Version + " " + err.Error()}
		}
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
