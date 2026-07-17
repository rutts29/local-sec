package lsec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

func runOSVScanner(ctx context.Context, path string, inputs *providerInputSelection) ([]byte, []byte, []providerInputCopy, error) {
	var copies []providerInputCopy
	out, stderr, err := runScanProviderPreparedCommand(ctx, path, func(dir string) ([]string, error) {
		var copyErr error
		copies, copyErr = inputs.copyAcceptedToProviderDir(dir, true)
		if copyErr != nil {
			return nil, copyErr
		}
		args := []string{"scan"}
		for _, copy := range copies {
			args = append(args, "-L", copy.copied)
		}
		args = append(args, "--format", "json")
		return args, nil
	})
	return out, stderr, copies, err
}

func runPipAudit(ctx context.Context, path, requirementsFile string, inputs *providerInputSelection) ([]byte, []byte, error) {
	return runScanProviderPreparedCommand(ctx, path, func(dir string) ([]string, error) {
		inputDir := filepath.Join(dir, "inputs")
		if err := os.MkdirAll(inputDir, 0o700); err != nil {
			return nil, err
		}
		copy, ok, err := inputs.copyAcceptedPathToProviderDir(inputDir, 0, requirementsFile, false)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errNoProviderInputs
		}
		return []string{"--format", "json", "--progress-spinner", "off", "--requirement", copy.copied}, nil
	})
}

func runGrype(ctx context.Context, path, sbomFile string, inputs *providerInputSelection) ([]byte, []byte, error) {
	return runScanProviderPreparedCommand(ctx, path, func(dir string) ([]string, error) {
		inputDir := filepath.Join(dir, "inputs")
		if err := os.MkdirAll(inputDir, 0o700); err != nil {
			return nil, err
		}
		copy, ok, err := inputs.copyAcceptedPathToProviderDir(inputDir, 0, sbomFile, false)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errNoProviderInputs
		}
		return []string{"sbom:" + copy.copied, "-o", "json"}, nil
	})
}

func runScanProviderCommand(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
	return runScanProviderPreparedCommand(ctx, executable, func(string) ([]string, error) {
		return args, nil
	})
}

func runScanProviderPreparedCommand(ctx context.Context, executable string, buildArgs func(string) ([]string, error)) ([]byte, []byte, error) {
	dir, err := os.MkdirTemp("", "lsec-scan-provider-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	home := filepath.Join(dir, "home")
	cacheHome := filepath.Join(dir, "cache")
	configHome := filepath.Join(dir, "config")
	for _, path := range []string{home, cacheHome, configHome} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, nil, err
		}
	}
	args, err := buildArgs(dir)
	if err != nil {
		return nil, nil, err
	}
	providerCtx, cancel := context.WithTimeout(ctx, externalProviderTimeout)
	defer cancel()
	cmd := exec.CommandContext(providerCtx, executable, args...)
	cmd.Dir = dir
	cmd.Env = scanProviderEnv(home, cacheHome, configHome)
	configureProviderProcess(cmd)
	cmd.Cancel = func() error {
		return killProviderProcessTree(cmd)
	}
	stdout := &boundedProviderOutput{limit: externalProviderOutputLimit}
	stderr := &boundedProviderOutput{limit: externalProviderOutputLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	if providerErr := providerCtx.Err(); providerErr != nil {
		if errors.Is(providerErr, context.DeadlineExceeded) {
			err = fmt.Errorf("provider timed out: %w", providerErr)
		} else {
			err = fmt.Errorf("provider canceled: %w", providerErr)
		}
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func scanProviderEnv(home, cacheHome, configHome string) []string {
	env := []string{
		"NO_COLOR=1",
		"HOME=" + home,
		"XDG_CACHE_HOME=" + cacheHome,
		"XDG_CONFIG_HOME=" + configHome,
	}
	if value, ok := os.LookupEnv("PATH"); ok {
		env = append(env, "PATH="+value)
	}
	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy"} {
		if value, ok := os.LookupEnv(key); ok {
			if safeProxyEnvValue(key, value) {
				env = append(env, key+"="+value)
			}
		}
	}
	return env
}

func safeProxyEnvValue(key, value string) bool {
	if hasControlCharacter(value) {
		return false
	}
	switch strings.ToUpper(key) {
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
		parsed, err := url.Parse(value)
		if err != nil {
			return false
		}
		if parsed.User == nil && parsed.Host == "" && strings.Contains(value, "@") {
			return false
		}
		return parsed.User == nil
	default:
		return true
	}
}

func hasControlCharacter(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

type boundedProviderOutput struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedProviderOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) <= remaining {
			_, _ = b.buf.Write(p)
			return len(p), nil
		}
		_, _ = b.buf.Write(p[:remaining])
	}
	if !b.truncated {
		if b.buf.Len() > 0 {
			_, _ = b.buf.WriteString("\n")
		}
		_, _ = b.buf.WriteString(providerOutputTruncatedMarker)
		b.truncated = true
	}
	return len(p), nil
}

func (b *boundedProviderOutput) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func providerFailureMessage(provider string, runErr error, stdout, stderr []byte, parseErr error) string {
	message := provider + " failed: " + providerSnapshotError(runErr, parseErr)
	if bytes.Contains(stdout, []byte(providerOutputTruncatedMarker)) || bytes.Contains(stderr, []byte(providerOutputTruncatedMarker)) {
		message += ": provider output truncated"
	}
	return message
}

func providerSnapshotError(runErr, parseErr error) string {
	if runErr != nil {
		message := strings.ToLower(runErr.Error())
		switch {
		case errors.Is(runErr, context.DeadlineExceeded), strings.Contains(message, "timed out"), strings.Contains(message, "deadline exceeded"):
			return "timeout"
		case errors.Is(runErr, context.Canceled), strings.Contains(message, "canceled"):
			return "canceled"
		default:
			return "execution_failed"
		}
	}
	if parseErr != nil {
		return "invalid_output"
	}
	return "provider_failed"
}
