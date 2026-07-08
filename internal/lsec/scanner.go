package lsec

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func StaticScan(root string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		name := filepath.Base(path)
		if name == "package.json" {
			found, err := scanPackageJSON(path, rel)
			if err != nil {
				findings = append(findings, Finding{Code: "scan_error", Severity: "prompt", File: rel, Message: err.Error()})
			}
			findings = append(findings, found...)
		}
		if name == "sitecustomize.py" || name == "usercustomize.py" {
			findings = append(findings, Finding{Code: "python_startup_hook", Severity: "block", File: rel, Message: "Python startup hook file can execute automatically when the interpreter starts"})
		}
		if strings.HasSuffix(name, ".pth") {
			findings = append(findings, scanPTHFile(path, rel)...)
		}
		if !shouldScanSource(path) {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if len(body) > 2*1024*1024 {
			body = body[:2*1024*1024]
		}
		findings = append(findings, scanSource(rel, string(body))...)
		return nil
	})
	return findings, err
}

func scanPackageJSON(path, rel string) ([]Finding, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return nil, err
	}
	var findings []Finding
	for name, script := range pkg.Scripts {
		if defaultStaticScannerConfig.lifecycleScripts[strings.ToLower(name)] {
			severity, message := defaultStaticScannerConfig.findingText("npm_lifecycle_script", "")
			findings = append(findings, Finding{
				Code: "npm_lifecycle_script", Severity: severity, File: rel,
				Message: message, Evidence: name + ": " + script,
			})
		}
		networkOrExecutionPatterns := append(append([]string{}, defaultStaticScannerConfig.networkPatterns...), defaultStaticScannerConfig.executionPatterns...)
		if containsAny(script, defaultStaticScannerConfig.credentialPatterns) && containsAny(script, networkOrExecutionPatterns) {
			severity, message := defaultStaticScannerConfig.findingText("credential_exfil_pattern", "package")
			findings = append(findings, Finding{
				Code: "credential_exfil_pattern", Severity: severity, File: rel,
				Message: message, Evidence: name,
			})
		}
	}
	return findings, nil
}

func scanPTHFile(path, rel string) []Finding {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "import\t") {
			return []Finding{{
				Code:     "python_pth_execution",
				Severity: "block",
				File:     rel,
				Message:  ".pth file executes Python code on interpreter startup",
				Evidence: limitString(trimmed, 160),
			}}
		}
	}
	return nil
}

func scanSource(rel, source string) []Finding {
	return scanSourceWithConfig(rel, source, defaultStaticScannerConfig)
}

func scanSourceWithConfig(rel, source string, cfg staticScannerConfig) []Finding {
	var findings []Finding
	hasCred := containsAny(source, cfg.credentialPatterns)
	hasNetwork := containsAny(source, cfg.networkPatterns)
	hasExec := containsAny(source, cfg.executionPatterns)
	hasObfuscation := containsAny(source, cfg.obfuscationPatterns)
	hasPersistence := containsAny(source, cfg.persistencePatterns)

	if hasRemoteShellPayload(source) {
		findings = append(findings, Finding{Code: "remote_shell_payload", Severity: "block", File: rel, Message: "code downloads remote content and pipes it to a shell"})
	}
	if hasPersistence {
		severity, message := cfg.findingText("persistence_write_pattern", "")
		findings = append(findings, Finding{Code: "persistence_write_pattern", Severity: severity, File: rel, Message: message})
	}
	if hasCred && (hasNetwork || hasExec) {
		severity, message := cfg.findingText("credential_exfil_pattern", "source")
		findings = append(findings, Finding{Code: "credential_exfil_pattern", Severity: severity, File: rel, Message: message})
	} else if hasCred {
		severity, message := cfg.findingText("credential_path_reference", "")
		findings = append(findings, Finding{Code: "credential_path_reference", Severity: severity, File: rel, Message: message})
	}
	if hasObfuscation && hasNetwork {
		severity, message := cfg.findingText("obfuscated_network_payload", "")
		findings = append(findings, Finding{Code: "obfuscated_network_payload", Severity: severity, File: rel, Message: message})
	} else if hasObfuscation {
		severity, message := cfg.findingText("obfuscation_pattern", "")
		findings = append(findings, Finding{Code: "obfuscation_pattern", Severity: severity, File: rel, Message: message})
	}
	if hasExec {
		severity, message := cfg.findingText("process_execution", "")
		findings = append(findings, Finding{Code: "process_execution", Severity: severity, File: rel, Message: message})
	}
	if hasNetwork {
		severity, message := cfg.findingText("network_api", "")
		findings = append(findings, Finding{Code: "network_api", Severity: severity, File: rel, Message: message})
	}
	return findings
}

func hasRemoteShellPayload(source string) bool {
	lower := strings.ToLower(source)
	if !strings.Contains(lower, "curl") && !strings.Contains(lower, "wget") {
		return false
	}
	return strings.Contains(lower, "| sh") ||
		strings.Contains(lower, "|sh") ||
		strings.Contains(lower, "| bash") ||
		strings.Contains(lower, "|bash") ||
		strings.Contains(lower, "| zsh") ||
		strings.Contains(lower, "|zsh")
}

func shouldScanSource(path string) bool {
	return shouldScanSourceWithConfig(path, defaultStaticScannerConfig)
}

func shouldScanSourceWithConfig(path string, cfg staticScannerConfig) bool {
	name := filepath.Base(path)
	ext := filepath.Ext(path)
	if cfg.sourceFileNames[strings.ToLower(name)] {
		return true
	}
	for _, suffix := range cfg.sourceFileSuffixes {
		if strings.HasSuffix(strings.ToLower(name), strings.ToLower(suffix)) {
			return true
		}
	}
	return cfg.sourceExtensions[strings.ToLower(ext)]
}

func containsAny(source string, needles []string) bool {
	lower := strings.ToLower(source)
	for _, needle := range needles {
		if strings.Contains(lower, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func appendUniqueStrings(values []string, extra ...string) []string {
	seen := make(map[string]bool, len(values)+len(extra))
	for _, value := range values {
		seen[strings.ToLower(value)] = true
	}
	for _, value := range extra {
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		values = append(values, value)
		seen[key] = true
	}
	return values
}
