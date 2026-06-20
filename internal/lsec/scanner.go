package lsec

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var lifecycleScripts = map[string]bool{
	"preinstall": true, "install": true, "postinstall": true, "prepare": true,
}

var credentialPatterns = []string{
	".ssh", "id_rsa", ".aws", ".gcloud", ".azure", ".kube", ".npmrc", ".pypirc",
	".netrc", ".env", ".huggingface", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
	"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "HF_TOKEN",
}

var networkPatterns = []string{
	"requests.post", "requests.get", "urllib.request", "http.request", "https.request",
	"fetch(", "axios.", "net.connect", "socket.", "dns.", "curl ", "wget ",
}

var execPatterns = []string{
	"child_process", "subprocess", "os.system", "exec(", "eval(", "__import__", "spawn(",
}

var obfuscationPatterns = []string{
	"base64", "atob(", "zlib", "marshal.loads", "fromCharCode", "\\x", "obfuscator.io",
}

var persistencePatterns = []string{
	"LaunchAgents", "LaunchDaemons", "launchctl", "systemd/user", "crontab",
	".zshrc", ".bashrc", ".profile", "tasks.json", "SessionStart", ".claude", ".codex",
}

var embeddedSkillpackPatterns = map[string][]string{
	"credential": {
		".ssh", ".aws", ".gcloud", ".azure", ".kube", ".npmrc", ".pypirc",
		".netrc", ".env", ".huggingface", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
		"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY",
	},
	"network": {
		"fetch", "requests", "urllib", "socket", "dns", "http.request", "https.request",
	},
	"obfuscation": {
		"base64", "atob", "zlib", "marshal.loads", "fromCharCode", "obfuscator.io",
	},
	"persistence": {
		"Library/LaunchAgents", "Library/LaunchDaemons", "launchctl", "osascript",
		".claude/settings.json", ".codex/config.toml", ".cursor", ".continue", ".vscode/tasks.json",
	},
}

func init() {
	credentialPatterns = appendUniqueStrings(credentialPatterns, embeddedSkillpackPatterns["credential"]...)
	networkPatterns = appendUniqueStrings(networkPatterns, embeddedSkillpackPatterns["network"]...)
	obfuscationPatterns = appendUniqueStrings(obfuscationPatterns, embeddedSkillpackPatterns["obfuscation"]...)
	persistencePatterns = appendUniqueStrings(persistencePatterns, embeddedSkillpackPatterns["persistence"]...)
}

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
	if packageJSONDependencyCount(body) > 0 {
		findings = append(findings, Finding{
			Code: "dependency_metadata_present", Severity: "block", File: rel,
			Message: "package declares dependencies that are not recursively staged and pinned yet",
		})
	}
	for name, script := range pkg.Scripts {
		if lifecycleScripts[name] {
			findings = append(findings, Finding{
				Code: "npm_lifecycle_script", Severity: "prompt", File: rel,
				Message: "npm lifecycle script requires review", Evidence: name + ": " + script,
			})
		}
		if containsAny(script, credentialPatterns) && containsAny(script, append(networkPatterns, execPatterns...)) {
			findings = append(findings, Finding{
				Code: "credential_exfil_pattern", Severity: "block", File: rel,
				Message: "install script combines credential access with network or execution behavior", Evidence: name,
			})
		}
	}
	return findings, nil
}

func packageJSONDependencyCount(body []byte) int {
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return 0
	}
	return len(pkg.Dependencies) + len(pkg.OptionalDependencies) + len(pkg.PeerDependencies)
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
	var findings []Finding
	hasCred := containsAny(source, credentialPatterns)
	hasNetwork := containsAny(source, networkPatterns)
	hasExec := containsAny(source, execPatterns)
	hasObfuscation := containsAny(source, obfuscationPatterns)
	hasPersistence := containsAny(source, persistencePatterns)

	if hasRemoteShellPayload(source) {
		findings = append(findings, Finding{Code: "remote_shell_payload", Severity: "block", File: rel, Message: "code downloads remote content and pipes it to a shell"})
	}
	if hasPersistence {
		findings = append(findings, Finding{Code: "persistence_write_pattern", Severity: "block", File: rel, Message: "code references persistence locations or startup hooks"})
	}
	if hasCred && (hasNetwork || hasExec) {
		findings = append(findings, Finding{Code: "credential_exfil_pattern", Severity: "block", File: rel, Message: "code combines credential path access with network or process execution"})
	} else if hasCred {
		findings = append(findings, Finding{Code: "credential_path_reference", Severity: "prompt", File: rel, Message: "code references credential paths or secret-like environment variables"})
	}
	if hasObfuscation && hasNetwork {
		findings = append(findings, Finding{Code: "obfuscated_network_payload", Severity: "block", File: rel, Message: "code combines obfuscation with network behavior"})
	} else if hasObfuscation {
		findings = append(findings, Finding{Code: "obfuscation_pattern", Severity: "prompt", File: rel, Message: "code contains obfuscation patterns"})
	}
	if hasExec {
		findings = append(findings, Finding{Code: "process_execution", Severity: "prompt", File: rel, Message: "code can execute subprocesses or dynamic code"})
	}
	if hasNetwork {
		findings = append(findings, Finding{Code: "network_api", Severity: "prompt", File: rel, Message: "code contains network APIs"})
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
	name := filepath.Base(path)
	ext := filepath.Ext(path)
	switch name {
	case "install", "installer", "setup", "bootstrap", "downloaded-script":
		return true
	}
	if name == "setup.py" || name == "sitecustomize.py" || name == "usercustomize.py" || name == "pyproject.toml" || strings.HasSuffix(name, ".pth") {
		return true
	}
	switch ext {
	case ".js", ".mjs", ".cjs", ".py", ".toml":
		return true
	}
	return false
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
