package lsec

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	maxDownloadedFileBytes int64 = 128 << 20
	maxExtractedFileBytes  int64 = 128 << 20
)

func StageArtifacts(ctx context.Context, staging string, analysis CommandAnalysis, version VersionInfo) ([]Artifact, []Finding) {
	var findings []Finding
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return nil, []Finding{{Code: "staging_error", Severity: "prompt", Message: err.Error()}}
	}
	switch analysis.Manager {
	case "npm":
		if analysis.DirectURL || analysis.VCSDependency || analysis.LocalPath {
			return nil, []Finding{{Code: "unsafe_npm_staging_spec", Severity: "block", Message: "npm VCS, direct URL, and local path specs can execute package hooks during staging; blocked before npm pack"}}
		}
		return stageNPM(ctx, staging, analysis, version)
	case "pip", "pip3":
		if analysis.DirectURL || analysis.VCSDependency || analysis.LocalPath {
			return nil, []Finding{{Code: "unsafe_pip_staging_spec", Severity: "block", Message: "pip VCS, direct URL, local path, and editable specs can execute or fetch unsafe source during staging; blocked before pip download"}}
		}
		return stagePip(ctx, staging, analysis, version)
	case "curl", "wget":
		return stageDownload(ctx, staging, analysis)
	case "uv":
		if analysis.Action == "add" || strings.HasPrefix(analysis.Action, "pip install") {
			return nil, []Finding{{Code: "uv_staging_unsupported", Severity: "block", Message: "uv installs are blocked until wheel-only staging is implemented"}}
		}
		findings = append(findings, Finding{Code: "dynamic_stage_deferred", Severity: "prompt", Message: "one-shot execution requires later sandbox detonation"})
	case "pipx":
		if analysis.Action == "install" {
			return nil, []Finding{{Code: "pipx_staging_unsupported", Severity: "block", Message: "pipx installs are blocked until wheel-only staging is implemented"}}
		}
		findings = append(findings, Finding{Code: "dynamic_stage_deferred", Severity: "prompt", Message: "one-shot execution requires later sandbox detonation"})
	case "npx", "uvx":
		findings = append(findings, Finding{Code: "dynamic_stage_deferred", Severity: "prompt", Message: "one-shot or uv-style execution requires later sandbox detonation"})
	}
	return nil, findings
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
	cmd := exec.CommandContext(ctx, npmPath, "pack", spec, "--pack-destination", staging)
	cmd.Env = safeEnv(staging)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, []Finding{{Code: "stage_download_failed", Severity: "prompt", Message: "npm pack failed", Evidence: limitString(string(out), 400)}}
	}
	return collectArtifacts(staging)
}

func stagePip(ctx context.Context, staging string, analysis CommandAnalysis, version VersionInfo) ([]Artifact, []Finding) {
	if analysis.PythonModulePip && len(analysis.Raw) > 0 {
		pythonPath, err := findRealExecutable(analysis.Raw[0])
		if err != nil {
			return nil, []Finding{{Code: "missing_tool", Severity: "prompt", Message: "python interpreter is not installed"}}
		}
		return stagePipWithPython(ctx, staging, analysis, version, pythonPath)
	}
	pythonPath, err := findRealExecutable("python3")
	if err != nil {
		pythonPath, err = findRealExecutable("python")
	}
	if err != nil {
		return nil, []Finding{{Code: "missing_tool", Severity: "prompt", Message: "python is not installed"}}
	}
	return stagePipWithPython(ctx, staging, analysis, version, pythonPath)
}

func stagePipWithPython(ctx context.Context, staging string, analysis CommandAnalysis, version VersionInfo, pythonPath string) ([]Artifact, []Finding) {
	if analysis.RequirementsFile {
		args := []string{"-m", "pip", "download", "--require-hashes", "--only-binary=:all:", "-d", staging}
		for _, file := range analysis.RequirementFiles {
			args = append(args, "-r", file)
		}
		cmd := exec.CommandContext(ctx, pythonPath, args...)
		cmd.Env = safeEnv(staging)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, []Finding{{Code: "python_requirement_wheel_download_failed", Severity: "block", Message: "wheel-only requirements download failed", Evidence: limitString(string(out), 400)}}
		}
		return collectArtifacts(staging)
	}
	spec := selectedSpec(analysis, version, "==")
	if spec == "" {
		return nil, nil
	}
	cmd := exec.CommandContext(ctx, pythonPath, "-m", "pip", "download", "--only-binary=:all:", "-d", staging, spec)
	cmd.Env = safeEnv(staging)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, []Finding{{Code: "python_source_build_or_download_failed", Severity: "block", Message: "wheel-only pip download failed; source build may be required and is blocked by default", Evidence: limitString(string(out), 400)}}
	}
	return collectArtifacts(staging)
}

func stageDownload(ctx context.Context, staging string, analysis CommandAnalysis) ([]Artifact, []Finding) {
	for _, spec := range analysis.PackageSpecs {
		if !strings.HasPrefix(spec.Raw, "http://") && !strings.HasPrefix(spec.Raw, "https://") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(spec.Raw), "http://") {
			return nil, []Finding{{Code: "plaintext_http_download", Severity: "block", Message: "plain HTTP downloader URLs are blocked before network access", Evidence: spec.Raw}}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.Raw, nil)
		if err != nil {
			return nil, []Finding{{Code: "download_failed", Severity: "prompt", Message: err.Error()}}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, []Finding{{Code: "download_failed", Severity: "prompt", Message: err.Error()}}
		}
		defer resp.Body.Close()
		finalURL := req.URL
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL
		}
		if strings.EqualFold(finalURL.Scheme, "http") {
			return nil, []Finding{{Code: "plaintext_http_redirect", Severity: "block", Message: "HTTPS downloader URL redirected to plain HTTP", Evidence: finalURL.String()}}
		}
		if resp.StatusCode >= 300 {
			return nil, []Finding{{Code: "download_failed", Severity: "prompt", Message: resp.Status}}
		}
		target := filepath.Join(staging, filepath.Base(finalURL.Path))
		if target == staging || filepath.Base(target) == "." || filepath.Base(target) == "/" {
			target = filepath.Join(staging, "downloaded-script")
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, []Finding{{Code: "download_failed", Severity: "prompt", Message: err.Error()}}
		}
		_, copyErr := io.Copy(&limitedByteWriter{w: f, limit: maxDownloadedFileBytes, remaining: maxDownloadedFileBytes, label: "downloaded file"}, resp.Body)
		closeErr := f.Close()
		if copyErr != nil {
			if isLimitExceeded(copyErr) {
				return nil, []Finding{{Code: "download_too_large", Severity: "block", Message: "downloaded file exceeds size limit", Evidence: spec.Raw}}
			}
			return nil, []Finding{{Code: "download_failed", Severity: "prompt", Message: copyErr.Error()}}
		}
		if closeErr != nil {
			return nil, []Finding{{Code: "download_failed", Severity: "prompt", Message: closeErr.Error()}}
		}
	}
	return collectArtifacts(staging)
}

func selectedSpec(analysis CommandAnalysis, version VersionInfo, sep string) string {
	if len(analysis.PackageSpecs) == 0 {
		return ""
	}
	spec := analysis.PackageSpecs[0]
	if version.Found && version.Selected.Version != "" && spec.Name != "" {
		return spec.Name + sep + version.Selected.Version
	}
	return spec.Raw
}

func collectArtifacts(staging string) ([]Artifact, []Finding) {
	var artifacts []Artifact
	var findings []Finding
	entries, err := os.ReadDir(staging)
	if err != nil {
		return nil, []Finding{{Code: "stage_read_failed", Severity: "prompt", Message: err.Error()}}
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(staging, entry.Name())
		sum, err := fileSHA256(path)
		if err != nil {
			findings = append(findings, Finding{Code: "artifact_hash_failed", Severity: "prompt", File: entry.Name(), Message: err.Error()})
			continue
		}
		artifact := Artifact{Path: path, SHA256: sum, Kind: artifactKind(path)}
		artifact.Ecosystem = artifactEcosystem(artifact.Kind)
		extractDir := filepath.Join(staging, "extract", entry.Name())
		if err := extractArtifact(path, extractDir); err != nil {
			findings = append(findings, Finding{Code: "artifact_extract_failed", Severity: "prompt", File: entry.Name(), Message: err.Error()})
			continue
		}
		artifact.Name, artifact.Version, err = ExtractArtifactIdentity(extractDir, artifact.Ecosystem)
		if err != nil {
			findings = append(findings, Finding{Code: "artifact_identity_failed", Severity: "prompt", File: entry.Name(), Message: err.Error()})
		}
		deps, depFindings, err := ExtractDependencyRefs(extractDir, artifact.Ecosystem)
		if err != nil {
			findings = append(findings, Finding{Code: "dependency_extract_failed", Severity: "prompt", File: entry.Name(), Message: err.Error()})
		}
		artifact.Dependencies = deps
		findings = append(findings, depFindings...)
		scanFindings, err := StaticScan(extractDir)
		if err != nil {
			findings = append(findings, Finding{Code: "static_scan_failed", Severity: "prompt", File: entry.Name(), Message: err.Error()})
			continue
		}
		findings = append(findings, scanFindings...)
		artifacts = append(artifacts, artifact)
	}
	return artifacts, findings
}

func artifactEcosystem(kind string) string {
	switch kind {
	case "tar":
		return "npm"
	case "wheel":
		return "PyPI"
	default:
		return ""
	}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func artifactKind(path string) string {
	switch {
	case strings.HasSuffix(path, ".whl"):
		return "wheel"
	case strings.HasSuffix(path, ".tgz"), strings.HasSuffix(path, ".tar.gz"):
		return "tar"
	default:
		return "file"
	}
}

func extractArtifact(path, dest string) error {
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	switch {
	case strings.HasSuffix(path, ".whl"), strings.HasSuffix(path, ".zip"):
		return extractZip(path, dest)
	case strings.HasSuffix(path, ".tgz"), strings.HasSuffix(path, ".tar.gz"):
		return extractTarGz(path, dest)
	default:
		target := filepath.Join(dest, filepath.Base(path))
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
}

func extractZip(path, dest string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if err := safeExtractFile(dest, f.Name, func(w io.Writer) error {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			_, err = io.Copy(w, rc)
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

func extractTarGz(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if header.FileInfo().IsDir() {
			continue
		}
		if err := safeExtractFile(dest, header.Name, func(w io.Writer) error {
			_, err := io.Copy(w, tr)
			return err
		}); err != nil {
			return err
		}
	}
}

func safeExtractFile(dest, name string, write func(io.Writer) error) error {
	if unsafeArchivePath(name) {
		return fmt.Errorf("archive path escapes destination: %s", name)
	}
	clean := filepath.Clean(name)
	target := filepath.Join(dest, clean)
	if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
		return fmt.Errorf("archive path escapes destination: %s", name)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = write(&limitedByteWriter{w: out, limit: maxExtractedFileBytes, remaining: maxExtractedFileBytes, label: "extracted file"})
	closeErr := out.Close()
	if err != nil {
		return err
	}
	return closeErr
}

type limitedByteWriter struct {
	w         io.Writer
	limit     int64
	remaining int64
	label     string
}

func (w *limitedByteWriter) Write(p []byte) (int, error) {
	if w.limit <= 0 {
		return w.w.Write(p)
	}
	if int64(len(p)) > w.remaining {
		if w.remaining <= 0 {
			return 0, limitExceededError{label: w.label, limit: w.limit}
		}
		n, err := w.w.Write(p[:int(w.remaining)])
		w.remaining -= int64(n)
		if err != nil {
			return n, err
		}
		return n, limitExceededError{label: w.label, limit: w.limit}
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}

type limitExceededError struct {
	label string
	limit int64
}

func (e limitExceededError) Error() string {
	return fmt.Sprintf("%s exceeds %d bytes", e.label, e.limit)
}

func isLimitExceeded(err error) bool {
	_, ok := err.(limitExceededError)
	return ok
}

func unsafeArchivePath(name string) bool {
	if name == "" || filepath.IsAbs(name) || strings.Contains(name, `\`) {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func safeEnv(staging string) []string {
	home := filepath.Join(staging, "home")
	cache := filepath.Join(staging, "cache")
	config := filepath.Join(staging, "config")
	_ = os.MkdirAll(home, 0o700)
	_ = os.MkdirAll(cache, 0o700)
	_ = os.MkdirAll(config, 0o700)
	return []string{
		"PATH=" + pathWithoutShim(),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + config,
		"XDG_CACHE_HOME=" + cache,
		"NPM_CONFIG_USERCONFIG=" + filepath.Join(config, "npmrc"),
		"PIP_CONFIG_FILE=" + filepath.Join(config, "pip.conf"),
		"PIP_CACHE_DIR=" + filepath.Join(cache, "pip"),
		"PIP_DISABLE_PIP_VERSION_CHECK=1",
		"NO_COLOR=1",
	}
}

func pathWithoutShim() string {
	shimDir := os.Getenv("LSEC_SHIM_DIR")
	if shimDir == "" {
		if paths, err := DefaultPaths(); err == nil {
			shimDir = paths.Bin
		}
	}
	var kept []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if shimDir != "" && filepath.Clean(dir) == filepath.Clean(shimDir) {
			continue
		}
		kept = append(kept, dir)
	}
	return strings.Join(kept, string(os.PathListSeparator))
}

func limitString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func timeoutContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}
