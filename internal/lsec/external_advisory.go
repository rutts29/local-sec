package lsec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func RefreshExternalAdvisories(ctx context.Context, refs []DependencyRef) ([]Advisory, []Finding) {
	var advisories []Advisory
	var findings []Finding
	seen := map[string]bool{}
	socketPath, socketErr := exec.LookPath("socket")
	snykPath, snykErr := exec.LookPath("snyk")
	for _, ref := range refs {
		if !ref.Exact || ref.Name == "" || ref.Version == "" {
			continue
		}
		key := ref.Ecosystem + "\x00" + ref.Name + "\x00" + ref.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		if socketErr == nil && socketEcosystem(ref.Ecosystem) != "" {
			found, toolFindings := runExternalAdvisoryTool(ctx, socketPath, []string{"package", "score", socketEcosystem(ref.Ecosystem), ref.Name + "@" + ref.Version, "--json"}, "socket", ref)
			advisories = append(advisories, found...)
			findings = append(findings, toolFindings...)
		}
		if snykErr == nil && ref.Ecosystem == "npm" {
			found, toolFindings := runExternalAdvisoryTool(ctx, snykPath, []string{"test", ref.Name + "@" + ref.Version, "--json"}, "snyk", ref)
			advisories = append(advisories, found...)
			findings = append(findings, toolFindings...)
		}
	}
	return advisories, findings
}

func runExternalAdvisoryTool(ctx context.Context, path string, args []string, source string, ref DependencyRef) ([]Advisory, []Finding) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = externalToolEnv()
	out, err := cmd.CombinedOutput()
	advisories, parsed := parseExternalAdvisoryJSONChecked(source, ref.Ecosystem, ref.Name, ref.Version, out)
	if len(advisories) > 0 {
		return advisories, nil
	}
	if !parsed {
		return nil, []Finding{{
			Code:     "external_advisory_failed",
			Severity: "block",
			Message:  source + " advisory check failed",
			Evidence: limitString(string(out), 400),
		}}
	}
	if err != nil {
		return nil, []Finding{{
			Code:     "external_advisory_failed",
			Severity: "block",
			Message:  source + " advisory check failed",
			Evidence: limitString(string(out), 400),
		}}
	}
	return nil, nil
}

func parseExternalAdvisoryJSON(source, ecosystem, name, version string, body []byte) []Advisory {
	advisories, _ := parseExternalAdvisoryJSONChecked(source, ecosystem, name, version, body)
	return advisories
}

func parseExternalAdvisoryJSONChecked(source, ecosystem, name, version string, body []byte) ([]Advisory, bool) {
	var doc any
	if err := json.Unmarshal(extractJSONPayload(body), &doc); err != nil {
		return nil, false
	}
	var advisories []Advisory
	walkJSONObjects(doc, func(m map[string]any) {
		severity := externalSeverity(m)
		advisoryType := externalType(m)
		if severity == "" && advisoryType == "" {
			return
		}
		if advisoryType == "malware" && severity == "" {
			severity = "critical"
		}
		if severity == "" {
			severity = "unknown"
		}
		id := firstExternalString(m, "id", "issueId", "name", "type", "alertType", "key")
		if id == "" {
			id = source + "-advisory"
		}
		advisories = append(advisories, Advisory{
			Source:    source,
			ID:        id,
			Ecosystem: ecosystem,
			Name:      name,
			Version:   version,
			Severity:  severity,
			Type:      advisoryType,
			Summary:   firstExternalString(m, "title", "summary", "description", "message"),
		})
	})
	return dedupeAdvisories(advisories), true
}

func extractJSONPayload(body []byte) []byte {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return []byte(trimmed)
	}
	for i, r := range trimmed {
		if r == '{' || r == '[' {
			return []byte(trimmed[i:])
		}
	}
	return body
}

func walkJSONObjects(value any, visit func(map[string]any)) {
	switch v := value.(type) {
	case map[string]any:
		visit(v)
		for _, child := range v {
			walkJSONObjects(child, visit)
		}
	case []any:
		for _, child := range v {
			walkJSONObjects(child, visit)
		}
	}
}

func externalSeverity(m map[string]any) string {
	for _, key := range []string{"severity", "level", "severityLabel"} {
		if value, ok := m[key].(string); ok {
			if normalized := normalizeExternalSeverity(value); normalized != "" {
				return normalized
			}
		}
	}
	for _, value := range m {
		if s, ok := value.(string); ok {
			if normalized := normalizeExternalSeverity(s); normalized != "" {
				return normalized
			}
		}
	}
	return ""
}

func normalizeExternalSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "middle", "moderate":
		return "medium"
	case "low", "info", "informational":
		return "low"
	default:
		return ""
	}
}

func externalType(m map[string]any) string {
	for _, key := range []string{"type", "name", "alertType", "category", "title"} {
		if value, ok := m[key].(string); ok && strings.Contains(strings.ToLower(value), "malware") {
			return "malware"
		}
	}
	return ""
}

func firstExternalString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := m[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func dedupeAdvisories(in []Advisory) []Advisory {
	seen := map[string]bool{}
	out := make([]Advisory, 0, len(in))
	for _, advisory := range in {
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", advisory.Source, advisory.ID, advisory.Ecosystem, advisory.Name, advisory.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, advisory)
	}
	return out
}

func socketEcosystem(ecosystem string) string {
	switch ecosystem {
	case "npm":
		return "npm"
	case "PyPI":
		return "pypi"
	default:
		return ""
	}
}

func externalToolEnv() []string {
	var env []string
	for _, key := range []string{"PATH", "HOME", "SOCKET_SECURITY_API_TOKEN", "SNYK_TOKEN", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	env = append(env, "NO_COLOR=1")
	return env
}
