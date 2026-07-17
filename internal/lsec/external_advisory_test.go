package lsec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseExternalAdvisoryJSONFindsCriticalMalware(t *testing.T) {
	body := []byte(`{
		"alerts": [{
			"name": "knownMalware",
			"severity": "critical",
			"type": "malware",
			"title": "Known malware"
		}]
	}`)

	advisories := parseExternalAdvisoryJSON("socket", "npm", "left-pad", "1.3.0", body)

	if len(advisories) != 1 {
		t.Fatalf("advisories = %#v, want one", advisories)
	}
	if advisories[0].Source != "socket" || advisories[0].Severity != "critical" || advisories[0].Type != "malware" {
		t.Fatalf("advisory = %#v, want socket critical malware", advisories[0])
	}
}

func TestParseExternalAdvisoryJSONAcceptsSocketProgressPrefix(t *testing.T) {
	body := []byte(`ℹ Requesting deep score data for this purl: pkg:npm/left-pad@1.3.0
✔ Received Socket API response.
{
  "ok": true,
  "data": {
    "self": {
      "alerts": [{
        "name": "deprecated",
        "severity": "middle",
        "category": "maintenance"
      }]
    }
  }
}`)

	advisories := parseExternalAdvisoryJSON("socket", "npm", "left-pad", "1.3.0", body)

	if len(advisories) != 1 {
		t.Fatalf("advisories = %#v, want one", advisories)
	}
	if advisories[0].Source != "socket" || advisories[0].Severity != "medium" {
		t.Fatalf("advisory = %#v, want parsed socket medium advisory", advisories[0])
	}
}

func TestRefreshExternalAdvisoriesUsesSocketAndSnykWhenAvailable(t *testing.T) {
	bin := t.TempDir()
	writeFakeTool(t, bin, "socket", `#!/bin/sh
echo '{"alerts":[{"name":"knownMalware","severity":"critical","type":"malware","title":"Known malware"}]}'
`)
	writeFakeTool(t, bin, "snyk", `#!/bin/sh
echo '{"vulnerabilities":[{"id":"SNYK-JS-LEFTPAD-1","severity":"high","title":"Prototype pollution"}]}'
exit 1
`)
	t.Setenv("PATH", bin)

	advisories, findings := RefreshExternalAdvisories(context.Background(), []DependencyRef{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		Exact:     true,
	}})

	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if !hasAdvisory(advisories, "socket", "critical", "malware") {
		t.Fatalf("advisories = %#v, want socket critical malware", advisories)
	}
	if !hasAdvisory(advisories, "snyk", "high", "") {
		t.Fatalf("advisories = %#v, want snyk high advisory", advisories)
	}
}

func TestRefreshExternalAdvisoriesFailsClosedWhenInstalledToolErrors(t *testing.T) {
	bin := t.TempDir()
	writeFakeTool(t, bin, "socket", `#!/bin/sh
echo 'service unavailable' >&2
exit 1
`)
	t.Setenv("PATH", bin)

	_, findings := RefreshExternalAdvisories(context.Background(), []DependencyRef{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		Exact:     true,
	}})

	if firstFindingSeverity(findings, "external_advisory_failed") != "block" {
		t.Fatalf("findings = %#v, want blocking external_advisory_failed", findings)
	}
}

func TestRefreshExternalAdvisoriesFailureEvidenceDoesNotLeakToolOutput(t *testing.T) {
	bin := t.TempDir()
	writeFakeTool(t, bin, "socket", `#!/bin/sh
echo 'socket raw leak /Users/alice/.npmrc SOCKET_SECURITY_API_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456 lsec-canary-socket' >&2
exit 1
`)
	writeFakeTool(t, bin, "snyk", `#!/bin/sh
echo 'snyk raw leak /Users/alice/.config/snyk SNYK_TOKEN=sk-abcdefghijklmnopqrstuvwxyz API_KEY=secret-value' >&2
exit 2
`)
	t.Setenv("PATH", bin)

	_, findings := RefreshExternalAdvisories(context.Background(), []DependencyRef{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		Exact:     true,
	}})

	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want one finding per failed provider", findings)
	}
	for _, finding := range findings {
		body := finding.Message + " " + finding.Evidence
		for _, forbidden := range []string{"/Users/", "ghp_", "sk-", "lsec-canary-", "secret-value", "raw leak"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("finding leaks raw tool output %q: %#v", forbidden, finding)
			}
		}
		if finding.Code != "external_advisory_failed" || finding.Severity != "block" {
			t.Fatalf("finding = %#v, want blocking external advisory failure", finding)
		}
		if !strings.Contains(finding.Evidence, finding.Message[:strings.Index(finding.Message, " ")]) || !strings.Contains(finding.Evidence, "status=") {
			t.Fatalf("finding evidence = %q, want provider and status", finding.Evidence)
		}
	}
}

func TestRefreshExternalAdvisoriesFailsClosedOnMalformedJSON(t *testing.T) {
	bin := t.TempDir()
	writeFakeTool(t, bin, "socket", `#!/bin/sh
echo 'not json'
`)
	t.Setenv("PATH", bin)

	_, findings := RefreshExternalAdvisories(context.Background(), []DependencyRef{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		Exact:     true,
	}})

	if firstFindingSeverity(findings, "external_advisory_failed") != "block" {
		t.Fatalf("findings = %#v, want blocking external_advisory_failed", findings)
	}
}

func writeFakeTool(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func hasAdvisory(advisories []Advisory, source, severity, advisoryType string) bool {
	for _, advisory := range advisories {
		if advisory.Source == source && advisory.Severity == severity && advisory.Type == advisoryType {
			return true
		}
	}
	return false
}
