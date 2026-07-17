package lsec

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEvidenceBundleKeepsLLMInputSecretFree(t *testing.T) {
	report := RunReport{
		RunID: "run-1",
		Findings: []Finding{{
			Code: "credential_path_reference", File: "setup.py", Message: "path reference only",
		}},
	}

	bundle := BuildEvidenceBundle(report)
	if bundle.RunID != "run-1" {
		t.Fatalf("run id = %q, want run-1", bundle.RunID)
	}
	if bundle.Sandbox.FakeEnvironment != nil {
		t.Fatal("fake environment should not be populated until sandbox evidence exists")
	}
}

func TestEvidenceBundleIncludesDecisionContext(t *testing.T) {
	report := RunReport{
		RunID:    "run-1",
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky, Reasons: []string{"needs review"}},
	}

	body, err := json.Marshal(BuildEvidenceBundle(report))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["decision"].(map[string]any); !ok {
		t.Fatalf("bundle JSON = %s, want decision object", body)
	}
}

func TestEvidenceBundlePreservesSandboxEvidenceRoundTrip(t *testing.T) {
	report := RunReport{
		RunID: "run-sandbox-roundtrip",
		Sandbox: SandboxEvidence{
			Enabled: true,
			Mode:    string(SandboxModeFakeCanary),
			FileEvents: []FileEvent{{
				Operation: "read",
				Path:      "/Users/alice/.npmrc",
			}},
			CanaryEvents: []CanaryEvent{{
				Kind:   "env",
				Marker: "lsec-canary-npm-token",
			}},
		},
	}

	bundle := BuildEvidenceBundle(report)
	body := evidenceJSON(t, bundle)
	for _, forbidden := range []string{"/Users/alice", "lsec-canary-npm-token"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("bundle contains unredacted sandbox value %q: %s", forbidden, body)
		}
	}

	roundTrip := bundle.RunReport()

	if !roundTrip.Sandbox.Enabled {
		t.Fatalf("sandbox evidence = %#v, want enabled sandbox evidence", roundTrip.Sandbox)
	}
	if got := roundTrip.Sandbox.FileEvents[0].Path; got != ".npmrc" {
		t.Fatalf("sandbox file path = %q, want basename only", got)
	}
	if got := roundTrip.Sandbox.CanaryEvents[0].Marker; got != "[redacted-secret]" {
		t.Fatalf("sandbox canary marker = %q, want redacted marker", got)
	}
}

func TestSanitizeRunReportForPersistenceRedactsSandboxEvidence(t *testing.T) {
	report := RunReport{
		RunID: "run-sandbox-persist",
		Sandbox: SandboxEvidence{
			Enabled: true,
			Mode:    string(SandboxModeFakeCanary),
			ProcessEvents: []ProcessEvent{{
				Executable: "/Users/alice/bin/tool",
				Args:       []string{"--token=lsec-canary-openai-api-key", "/Users/alice/project/package"},
			}, {
				Executable: "node",
				Args:       []string{"install.js", "--token", "SECRET_TOKEN"},
			}},
			FileEvents: []FileEvent{{
				Operation: "read",
				Path:      "/Users/alice/.ssh/id_rsa",
			}},
			CanaryEvents: []CanaryEvent{{
				Kind:        "network",
				Marker:      "lsec-canary-github-token",
				Destination: "https://example.invalid/collect?token=lsec-canary-github-token",
			}},
			GeneratedFiles: []GeneratedFile{{
				Path: "/Users/alice/.codex/config.toml",
			}},
			FakeEnvironment: map[string]string{
				"HOME":           "/Users/alice/fake-home",
				"OPENAI_API_KEY": "lsec-canary-openai-api-key",
			},
		},
	}

	body, err := json.Marshal(sanitizeRunReportForPersistence(report))
	if err != nil {
		t.Fatal(err)
	}
	log := string(body)
	for _, forbidden := range []string{"/Users/alice", "lsec-canary-openai-api-key", "lsec-canary-github-token", "SECRET_TOKEN"} {
		if strings.Contains(log, forbidden) {
			t.Fatalf("persistent report contains unredacted sandbox value %q: %s", forbidden, log)
		}
	}
	if !strings.Contains(log, "[redacted-secret]") {
		t.Fatalf("persistent report = %s, want redacted sandbox marker", log)
	}
}

func TestEvidenceBundleIncludesStableEvidenceHash(t *testing.T) {
	report := RunReport{
		RunID: "run-1",
		Findings: []Finding{{
			Code: "network_api", File: "setup.py", Message: "network call",
		}},
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky, Reasons: []string{"needs review"}},
	}

	first := evidenceHashFromJSON(t, BuildEvidenceBundle(report))
	second := evidenceHashFromJSON(t, BuildEvidenceBundle(report))
	if first != second {
		t.Fatalf("hashes differ for same evidence: %q vs %q", first, second)
	}

	report.Findings[0].Code = "credential_path_reference"
	changed := evidenceHashFromJSON(t, BuildEvidenceBundle(report))
	if changed == first {
		t.Fatalf("hash did not change after evidence changed: %q", first)
	}
}

func TestEvidenceBundleRedactsLocalArtifactAndFindingPaths(t *testing.T) {
	report := RunReport{
		RunID: "run-redact",
		Analysis: CommandAnalysis{
			Raw:          []string{"pip", "install", "/Users/alice/project/example"},
			PackageSpecs: []PackageSpec{{Raw: "/Users/alice/project/example", Name: "example"}},
		},
		Artifacts: []Artifact{{
			Path:      "/Users/alice/.local-sec/staging/run-redact/example-1.0.0.tgz",
			SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Kind:      "tar",
			Ecosystem: "npm",
			Name:      "example",
			Version:   "1.0.0",
		}},
		Findings: []Finding{{
			Code:     "credential_path_reference",
			Severity: "prompt",
			File:     "/Users/alice/.local-sec/staging/run-redact/extract/example/package/index.js",
			Message:  "path reference only",
			Evidence: "read /Users/alice/.npmrc and /private/tmp/local-sec/token.txt",
		}},
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky, Reasons: []string{"needs review"}},
	}

	bundle := BuildEvidenceBundle(report)

	if got := bundle.Artifacts[0].Path; got != "example-1.0.0.tgz" {
		t.Fatalf("artifact path = %q, want basename only", got)
	}
	if got := bundle.Findings[0].File; got != "index.js" {
		t.Fatalf("finding file = %q, want basename only", got)
	}
	if got := bundle.Analysis.Raw[2]; got != "example" {
		t.Fatalf("raw command path = %q, want basename only", got)
	}
	if got := bundle.Analysis.PackageSpecs[0].Raw; got != "[redacted-local-package-spec]" {
		t.Fatalf("package spec raw path = %q, want local package spec marker", got)
	}
	artifact := bundle.Artifacts[0]
	if artifact.SHA256 != report.Artifacts[0].SHA256 || artifact.Ecosystem != "npm" || artifact.Name != "example" || artifact.Version != "1.0.0" || artifact.Kind != "tar" {
		t.Fatalf("artifact identity = %#v, want package identity and hash preserved", artifact)
	}
	if bundle.Decision.Verdict != VerdictPrompt || bundle.Decision.Lane != LaneRisky {
		t.Fatalf("decision = %#v, want verdict and lane preserved", bundle.Decision)
	}
	if strings.Contains(evidenceJSON(t, bundle), "/Users/alice") {
		t.Fatalf("bundle contains unredacted local path: %s", evidenceJSON(t, bundle))
	}
	if strings.Contains(evidenceJSON(t, bundle), "/private/tmp") {
		t.Fatalf("bundle contains unredacted temporary path: %s", evidenceJSON(t, bundle))
	}
	if report.Artifacts[0].Path != "/Users/alice/.local-sec/staging/run-redact/example-1.0.0.tgz" {
		t.Fatalf("report artifact path mutated to %q", report.Artifacts[0].Path)
	}
	if report.Analysis.PackageSpecs[0].Raw != "/Users/alice/project/example" {
		t.Fatalf("report package spec mutated to %q", report.Analysis.PackageSpecs[0].Raw)
	}
}

func TestEvidenceBundleRedactsLocalPackageSpecFields(t *testing.T) {
	report := RunReport{
		RunID: "run-redact-package-specs",
		Analysis: CommandAnalysis{
			PackageSpecs: []PackageSpec{
				{Raw: "../secret-project", Name: "../secret-project", LocalPath: true},
				{Raw: "./pkg", Name: "./pkg", LocalPath: true},
				{Raw: "file:../pkg", Name: "file:../pkg", LocalPath: true},
				{Raw: "workspace:../pkg", Name: "workspace:../pkg", Version: "workspace:../pkg", LocalPath: true},
				{Raw: "dist/pkg.whl", Name: "dist/pkg.whl"},
				{Raw: "packages/pkg.tgz", Name: "packages/pkg.tgz"},
				{Raw: "vendor/pkg.tar.gz", Name: "vendor/pkg.tar.gz"},
				{Raw: "react@1.2.3", Name: "react", Version: "1.2.3"},
				{Raw: "@scope/pkg@1.2.3", Name: "@scope/pkg", Version: "1.2.3"},
				{Raw: "requests==1.2.3", Name: "requests", Version: "1.2.3"},
			},
		},
	}

	bundle := BuildEvidenceBundle(report)
	body := evidenceJSON(t, bundle)

	for _, forbidden := range []string{"../secret-project", "./pkg", "file:../pkg", "workspace:../pkg", "dist/pkg.whl", "packages/pkg.tgz", "vendor/pkg.tar.gz"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("bundle contains unredacted local package spec %q: %s", forbidden, body)
		}
	}
	if got := strings.Count(body, "[redacted-local-package-spec]"); got < 11 {
		t.Fatalf("bundle JSON = %s, want local package spec redaction markers", body)
	}
	for _, want := range []string{"react", "@scope/pkg", "requests", "1.2.3"} {
		if !strings.Contains(body, want) {
			t.Fatalf("bundle JSON = %s, want normal package value %q preserved", body, want)
		}
	}
}

func TestEvidenceBundleRedactsLocalURIPathsInStructuredFields(t *testing.T) {
	for _, uri := range []string{
		"file:/Users/alice/.local-sec/staging/evidence.txt",
		"file:///Users/alice/.local-sec/staging/evidence.txt",
		"path:/private/tmp/local-sec/staging/evidence.txt",
	} {
		report := RunReport{
			RunID: "run-redact-structured-uris",
			Analysis: CommandAnalysis{
				LockfilePath: uri,
			},
			Artifacts: []Artifact{{
				Path: uri,
			}},
			Findings: []Finding{{
				File: uri,
			}},
			Sandbox: SandboxEvidence{
				FileEvents: []FileEvent{{
					Operation: "read",
					Path:      uri,
				}},
				NetworkEvents: []NetworkEvent{{
					Protocol:    "file",
					Destination: uri,
				}},
				CanaryEvents: []CanaryEvent{{
					Kind:        "network",
					Marker:      "marker",
					Path:        uri,
					Destination: uri,
				}},
				GeneratedFiles: []GeneratedFile{{
					Path: uri,
				}},
			},
		}

		bundle := BuildEvidenceBundle(report)
		body := evidenceJSON(t, bundle)

		for _, forbidden := range []string{"/Users/", "/private/tmp"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("bundle contains unredacted local URI path %q for %q: %s", forbidden, uri, body)
			}
		}
		if !strings.Contains(body, "evidence.txt") {
			t.Fatalf("bundle JSON = %s, want redacted basename for %q", body, uri)
		}
	}
}

func TestEvidenceBundleRedactsMessagesAndDecisionReasons(t *testing.T) {
	report := RunReport{
		RunID: "run-redact-messages",
		Analysis: CommandAnalysis{
			RiskFlags: []RiskFlag{{
				Code:     "credential_reference",
				Severity: "prompt",
				Message:  "read ghp_abcdefghijklmnopqrstuvwxyz123456 from /Users/alice/.npmrc",
			}},
		},
		Findings: []Finding{{
			Code:     "canary_exfiltration",
			Severity: "block",
			Message:  "posted lsec-canary-openai-api-key with sk-abcdefghijklmnopqrstuvwxyz from /Users/alice/project/setup.py",
		}},
		Decision: Decision{
			Verdict: VerdictBlock,
			Lane:    LaneBlock,
			Reasons: []string{"blocked /Users/alice/project ghp_abcdefghijklmnopqrstuvwxyz123456 sk-abcdefghijklmnopqrstuvwxyz lsec-canary-openai-api-key"},
		},
	}

	body := evidenceJSON(t, BuildEvidenceBundle(report))
	for _, forbidden := range []string{"/Users/", "ghp_", "sk-", "lsec-canary-"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("bundle contains unredacted message value %q: %s", forbidden, body)
		}
	}
}

func TestEvidenceRedactsArtifactDependencyRawAcrossPromptBundleAndPersistence(t *testing.T) {
	report := RunReport{
		RunID: "run-redact-dependency-raw",
		Artifacts: []Artifact{{
			Path:      "/Users/alice/.local-sec/staging/example-1.0.0.tgz",
			SHA256:    strings.Repeat("c", 64),
			Kind:      "tar",
			Ecosystem: "npm",
			Name:      "example",
			Version:   "1.0.0",
			Dependencies: []DependencyRef{{
				Ecosystem: "npm",
				Name:      "left-pad",
				Version:   "1.3.0",
				Raw:       "left-pad@file:/Users/alice/project/left-pad?token=ghp_abcdefghijklmnopqrstuvwxyz123456&key=sk-abcdefghijklmnopqrstuvwxyz lsec-canary-dependency",
				Exact:     true,
			}, {
				Ecosystem: "npm",
				Name:      "pkg",
				Version:   "2.0.0",
				Raw:       "pkg@file:///Users/alice/project/pkg",
				Exact:     true,
			}, {
				Ecosystem: "generic",
				Name:      "local-path",
				Version:   "3.0.0",
				Raw:       "path:/private/tmp/local-sec/canary.txt",
				Exact:     true,
			}},
		}},
	}

	bundle := BuildEvidenceBundle(report)
	prompt, _, err := BuildLLMReviewPrompt(EvidenceBundle{
		RunID:     report.RunID,
		Artifacts: report.Artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	persistentReport := sanitizeRunReportForPersistence(report)
	persistentBundle := sanitizeEvidenceBundleForPersistence(EvidenceBundle{
		RunID:     report.RunID,
		Artifacts: report.Artifacts,
	})

	for label, body := range map[string]string{
		"bundle":                     evidenceJSON(t, bundle),
		"prompt":                     prompt,
		"persistent report":          mustJSON(t, persistentReport),
		"persistent evidence bundle": evidenceJSON(t, persistentBundle),
	} {
		for _, forbidden := range []string{"/Users/", "/private/tmp", "ghp_", "sk-", "lsec-canary-"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s contains unredacted dependency raw value %q: %s", label, forbidden, body)
			}
		}
		for _, want := range []string{"npm", "left-pad", "1.3.0", "pkg", "2.0.0", "generic", "local-path", "3.0.0"} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s = %s, want preserved dependency metadata %q", label, body, want)
			}
		}
		if !strings.Contains(body, `"exact":true`) && !strings.Contains(body, `"exact": true`) {
			t.Fatalf("%s = %s, want preserved exact dependency metadata", label, body)
		}
	}

	dep := bundle.Artifacts[0].Dependencies[0]
	if dep.Ecosystem != "npm" || dep.Name != "left-pad" || dep.Version != "1.3.0" || !dep.Exact {
		t.Fatalf("dependency metadata = %#v, want non-sensitive fields preserved", dep)
	}
	if report.Artifacts[0].Dependencies[0].Raw == bundle.Artifacts[0].Dependencies[0].Raw {
		t.Fatalf("source dependency raw was not distinct from redacted value: %q", bundle.Artifacts[0].Dependencies[0].Raw)
	}
}

func TestEvidenceRedactsAdvisoriesAcrossPromptBundleAndPersistence(t *testing.T) {
	report := RunReport{
		RunID: "run-redact-advisory",
		Advisories: []Advisory{{
			Source:    "socket",
			ID:        "socket-malware",
			Ecosystem: "npm",
			Name:      "left-pad",
			Version:   "1.3.0",
			Severity:  "critical",
			Type:      "malware",
			Summary:   "read /Users/alice/project/setup.py file:/Users/alice/.npmrc lsec-canary-advisory API_KEY=sk-abcdefghijklmnopqrstuvwxyz",
			URL:       "file:/Users/alice/.local-sec/advisory.json?token=ghp_abcdefghijklmnopqrstuvwxyz123456",
		}},
	}

	bundle := BuildEvidenceBundle(report)
	prompt, _, err := BuildLLMReviewPrompt(EvidenceBundle{
		RunID:      report.RunID,
		Advisories: report.Advisories,
	})
	if err != nil {
		t.Fatal(err)
	}
	persistentReport := sanitizeRunReportForPersistence(report)
	persistentBundle := sanitizeEvidenceBundleForPersistence(EvidenceBundle{
		RunID:      report.RunID,
		Advisories: report.Advisories,
	})

	for label, body := range map[string]string{
		"bundle":                     evidenceJSON(t, bundle),
		"prompt":                     prompt,
		"persistent report":          mustJSON(t, persistentReport),
		"persistent evidence bundle": evidenceJSON(t, persistentBundle),
	} {
		for _, forbidden := range []string{"/Users/", "file:/Users/", "ghp_", "sk-", "lsec-canary-"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s contains unredacted advisory value %q: %s", label, forbidden, body)
			}
		}
		for _, want := range []string{"socket", "socket-malware", "npm", "left-pad", "1.3.0", "critical", "malware"} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s = %s, want preserved advisory metadata %q", label, body, want)
			}
		}
	}

	if report.Advisories[0].Summary == bundle.Advisories[0].Summary {
		t.Fatalf("source advisory summary was not distinct from redacted value: %q", bundle.Advisories[0].Summary)
	}
}

func TestEvidenceBundleMarshalRedactsSandboxPathsAndProcessArgs(t *testing.T) {
	bundle := EvidenceBundle{
		RunID: "run-sandbox-redact",
		Sandbox: SandboxEvidence{
			Enabled: true,
			ProcessEvents: []ProcessEvent{{
				Executable: "/Users/alice/bin/tool",
				Args:       []string{"-m", "pip", "install", "/Users/alice/project/example", "--config=/Users/alice/project/config.toml"},
			}, {
				Executable: `C:\Users\alice\bin\tool.exe`,
			}},
			FileEvents: []FileEvent{{
				Operation: "read",
				Path:      "/Users/alice/.ssh/id_rsa",
			}},
			NetworkEvents: []NetworkEvent{{
				Protocol:    "https",
				Destination: "https://example.invalid/collect?path=keep-destination",
			}},
			CanaryEvents: []CanaryEvent{{
				Kind:        "file",
				Marker:      "marker-is-not-a-path-field",
				Path:        "/private/tmp/local-sec/canary.txt",
				Destination: "https://example.invalid/canary",
			}},
			GeneratedFiles: []GeneratedFile{{
				Path:   "/private/tmp/local-sec/generated/report.json",
				SHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			}},
		},
	}

	body := evidenceJSON(t, bundle)

	for _, forbidden := range []string{"/Users/alice", "/private/tmp"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("bundle contains unredacted local path prefix %q: %s", forbidden, body)
		}
	}
	for _, forbidden := range []string{
		"/Users/alice/.ssh",
		"/Users/alice/project",
		"/private/tmp/local-sec/canary.txt",
		"/private/tmp/local-sec/generated",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("bundle contains unredacted sandbox path %q: %s", forbidden, body)
		}
	}
	for _, want := range []string{
		"https://example.invalid",
		"marker-is-not-a-path-field",
		"id_rsa",
		"example",
		"config.toml",
		"canary.txt",
		"report.json",
		"tool",
		"tool.exe",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("bundle JSON = %s, want %q", body, want)
		}
	}
}

func TestEvidenceBundleRedactsSplitSecretArgsFromAnalysisRaw(t *testing.T) {
	report := RunReport{
		RunID: "run-sandbox-raw-secret",
		Analysis: CommandAnalysis{
			Raw: []string{"curl", "--token", "real-secret", "https://example.test/upload"},
		},
	}

	bundle := BuildEvidenceBundle(report)
	persistentBundle := sanitizeEvidenceBundleForPersistence(bundle)
	body := evidenceJSON(t, persistentBundle)

	if strings.Contains(body, "real-secret") {
		t.Fatalf("bundle contains unredacted split secret arg: %s", body)
	}
	if !strings.Contains(body, "--token") {
		t.Fatalf("bundle JSON = %s, want preserved secret flag", body)
	}
	if !strings.Contains(body, "[redacted-secret]") {
		t.Fatalf("bundle JSON = %s, want redacted secret placeholder", body)
	}
	if got := persistentBundle.Analysis.Raw; len(got) != 4 || got[1] != "--token" || got[2] != "[redacted-secret]" {
		t.Fatalf("analysis raw = %#v, want secret value redacted with command shape preserved", got)
	}
}

func TestEvidenceBundleRedactsCommonPersonalPathsInTextAndArgs(t *testing.T) {
	bundle := EvidenceBundle{
		RunID: "run-common-paths",
		Findings: []Finding{{
			Code:     "credential_path_reference",
			Severity: "prompt",
			Message:  "path reference only",
			Evidence: strings.Join([]string{
				"read /tmp/local-sec/token.txt",
				"read /var/folders/aa/bb/T/key.json",
				"read /home/alice/.config/pip/pip.conf",
				"read /root/.ssh/id_rsa",
				`read C:\Users\alice\AppData\Roaming\npmrc`,
				"read C:/Users/alice/AppData/Roaming/npmrc",
			}, " "),
		}},
		Sandbox: SandboxEvidence{
			Enabled: true,
			ProcessEvents: []ProcessEvent{{
				Args: []string{
					"--cache=/tmp/local-sec/cache",
					"--state=/var/folders/aa/bb/T/state.json",
					"--home=/home/alice/project",
					`--config=C:\Users\alice\AppData\Roaming\config.toml`,
				},
			}},
			NetworkEvents: []NetworkEvent{{
				Protocol:    "https",
				Destination: "https://example.invalid/collect?path=/tmp/not-redacted-structured-network",
			}},
		},
	}

	body := evidenceJSON(t, bundle)

	for _, forbidden := range []string{
		"/tmp/local-sec",
		"/var/folders",
		"/home/alice",
		"/root/.ssh",
		`C:\Users\alice`,
		"C:/Users/alice",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("bundle contains unredacted personal path %q: %s", forbidden, body)
		}
	}
	for _, want := range []string{
		"token.txt",
		"key.json",
		"pip.conf",
		"id_rsa",
		"npmrc",
		"cache",
		"state.json",
		"project",
		"config.toml",
		"https://example.invalid",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("bundle JSON = %s, want %q", body, want)
		}
	}
}

func TestEvidenceBundleRedactsGenericUnixPathsAndNetworkURLDetails(t *testing.T) {
	bundle := EvidenceBundle{
		RunID: "run-generic-paths",
		Findings: []Finding{{
			Code:     "credential_path_reference",
			Severity: "prompt",
			Message:  "read /opt/project/secret.py and keep https://example.invalid/path",
			Evidence: "loaded /workspace/pkg/setup.py from https://example.invalid/artifacts/pkg/setup.py",
		}},
		Sandbox: SandboxEvidence{
			Enabled: true,
			ProcessEvents: []ProcessEvent{{
				Args: []string{"--config=/opt/project/secret.py", "/workspace/pkg/setup.py"},
			}},
			FakeEnvironment: map[string]string{
				"CONFIG_PATH": "/opt/project/secret.py",
				"DOCS_URL":    "https://example.invalid/workspace/pkg/setup.py",
			},
		},
		Decision: Decision{
			Verdict: VerdictPrompt,
			Lane:    LaneRisky,
			Reasons: []string{"review /workspace/pkg/setup.py before running"},
		},
	}

	body := evidenceJSON(t, bundle)

	for _, forbidden := range []string{"/opt/project", " /workspace/pkg", "=/workspace/pkg", "\"/workspace/pkg"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("bundle contains unredacted generic path prefix %q: %s", forbidden, body)
		}
	}
	for _, want := range []string{
		"secret.py",
		"setup.py",
		"https://example.invalid",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("bundle JSON = %s, want %q", body, want)
		}
	}
	for _, forbidden := range []string{"/path", "/artifacts/pkg", "/workspace/pkg"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("bundle contains unredacted URL detail %q: %s", forbidden, body)
		}
	}
}

func TestEvidenceBundleRedactsNetworkURLPathQueryAndFragment(t *testing.T) {
	bundle := EvidenceBundle{
		RunID: "run-redact-network-url",
		Findings: []Finding{{
			Code:     "network_api",
			Severity: "prompt",
			Message:  "posted to https://api.example.invalid/tmp/project?token=ghp_abcdefghijklmnopqrstuvwxyz123456#lsec-canary-openai-api-key",
			Evidence: "callback http://user:pass@callback.invalid/private/path?api_key=sk-abcdefghijklmnopqrstuvwxyz",
		}},
		Sandbox: SandboxEvidence{
			Enabled: true,
			NetworkEvents: []NetworkEvent{{
				Protocol:    "https",
				Destination: "https://example.invalid/collect?path=/tmp/secret&token=lsec-canary-openai-api-key#frag",
			}},
			CanaryEvents: []CanaryEvent{{
				Kind:        "network",
				Marker:      "lsec-canary-openai-api-key",
				Destination: "https://canary.invalid/leak/lsec-canary-openai-api-key?token=ghp_abcdefghijklmnopqrstuvwxyz123456",
			}},
		},
	}

	body := evidenceJSON(t, bundle)
	for _, want := range []string{"https://api.example.invalid", "http://callback.invalid", "https://example.invalid", "https://canary.invalid"} {
		if !strings.Contains(body, want) {
			t.Fatalf("bundle JSON = %s, want sanitized URL %q", body, want)
		}
	}
	for _, forbidden := range []string{"/tmp/project", "/private/path", "/collect", "/leak", "token=", "api_key=", "#frag", "user:pass", "ghp_", "sk-", "lsec-canary-"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("bundle contains unredacted network URL detail %q: %s", forbidden, body)
		}
	}
}

func TestEvidenceVersionRedactionAcrossBundleAndHandoffs(t *testing.T) {
	t.Setenv("PATH", "")
	paths := pathsFromRoot(t.TempDir())
	store := NewStore(paths)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	report := versionRedactionReport()
	bundle := BuildEvidenceBundle(report)
	prompt, _, err := BuildLLMReviewPrompt(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent("preflight", report); err != nil {
		t.Fatal(err)
	}
	events, err := os.ReadFile(paths.Events)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := PrepareRemoteSandboxRequest(store, report.RunID, time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	notification, err := PlanNotification(store, report.RunID, time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	for label, body := range map[string]string{
		"bundle JSON":          evidenceJSON(t, bundle),
		"event JSONL":          string(events),
		"remote request":       mustJSON(t, remote),
		"LLM prompt":           prompt,
		"notification payload": mustJSON(t, notification),
	} {
		assertNoRawVersionEvidence(t, label, body)
	}

	if bundle.Version.AgeDays != report.Version.AgeDays || !bundle.Version.Found || !bundle.Version.MatureCandidateSelected {
		t.Fatalf("version metadata = %#v, want age and booleans preserved", bundle.Version)
	}
	if !bundle.Version.Selected.PublishedAt.Equal(report.Version.Selected.PublishedAt) || !bundle.Version.Selected.Yanked || !bundle.Version.Latest.Deprecated {
		t.Fatalf("registry metadata = %#v, want timestamps and flags preserved", bundle.Version)
	}
	if got := bundle.Version.Candidates[0].Version; got != "1.2.3" {
		t.Fatalf("safe candidate version = %q, want 1.2.3", got)
	}
	if got := bundle.Version.Skipped[1].AdvisoryIDs[0]; got != "OSV-2026-1234" {
		t.Fatalf("safe advisory ID = %q, want OSV-2026-1234", got)
	}
	if !strings.Contains(report.Version.Requested, "curl-split-secret") {
		t.Fatalf("source report was mutated: %#v", report.Version)
	}
}

func TestEvidenceHashStableForIdenticalRedactedEvidence(t *testing.T) {
	firstBundle := EvidenceBundle{
		RunID: "run-redact",
		Artifacts: []Artifact{{
			Path:      "/Users/alice/.local-sec/staging/run-redact/example-1.0.0.tgz",
			SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Kind:      "tar",
			Ecosystem: "npm",
			Name:      "example",
			Version:   "1.0.0",
		}},
		Findings: []Finding{{
			Code:     "network_api",
			Severity: "prompt",
			File:     "/Users/alice/project/index.js",
			Evidence: "read /Users/alice/.npmrc and /private/tmp/local-sec/token.txt",
		}},
		Decision: Decision{Verdict: VerdictPrompt, Lane: LaneRisky, Reasons: []string{"needs review"}},
		Sandbox: SandboxEvidence{
			Enabled:       true,
			ProcessEvents: []ProcessEvent{{Args: []string{"cat", "/Users/alice/project/index.js"}}},
			FileEvents:    []FileEvent{{Operation: "read", Path: "/Users/alice/.npmrc"}},
		},
	}
	secondBundle := firstBundle
	secondBundle.Artifacts = append([]Artifact(nil), firstBundle.Artifacts...)
	secondBundle.Findings = append([]Finding(nil), firstBundle.Findings...)
	secondBundle.Sandbox.ProcessEvents = append([]ProcessEvent(nil), firstBundle.Sandbox.ProcessEvents...)
	secondBundle.Sandbox.FileEvents = append([]FileEvent(nil), firstBundle.Sandbox.FileEvents...)
	secondBundle.Artifacts[0].Path = "/private/tmp/local-sec/staging/run-redact/example-1.0.0.tgz"
	secondBundle.Findings[0].File = "/private/tmp/local-sec/staging/run-redact/extract/example/package/index.js"
	secondBundle.Findings[0].Evidence = "read /Users/bob/.npmrc and /private/tmp/other/token.txt"
	secondBundle.Sandbox.ProcessEvents[0].Args = []string{"cat", "/private/tmp/local-sec/index.js"}
	secondBundle.Sandbox.FileEvents[0].Path = "/private/tmp/local-sec/.npmrc"

	first := evidenceBundleHash(redactEvidenceBundle(firstBundle))
	second := evidenceBundleHash(redactEvidenceBundle(secondBundle))
	if first != second {
		t.Fatalf("hashes differ for identical redacted evidence: %q vs %q", first, second)
	}
}

func evidenceHashFromJSON(t *testing.T, bundle EvidenceBundle) string {
	t.Helper()

	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	got, _ := doc["evidence_sha256"].(string)
	if !isSHA256Hex(got) {
		t.Fatalf("evidence_sha256 = %q in %s, want 64 hex characters", got, body)
	}
	return got
}

func evidenceJSON(t *testing.T, bundle EvidenceBundle) string {
	t.Helper()

	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()

	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func versionRedactionReport() RunReport {
	return RunReport{
		RunID: "run-version-redaction",
		Version: VersionInfo{
			Requested:               "curl --token curl-split-secret https://curl-user:curl-pass@packages.example.test/request.tgz?token=curl-query-token#curl-fragment",
			Selected:                RegistryVersion{Version: "wget --api-key wget-split-secret https://wget-user:wget-pass@packages.example.test/selected.tgz?token=wget-query-token#wget-fragment", PublishedAt: time.Date(2026, 7, 1, 2, 3, 4, 0, time.UTC), Yanked: true},
			Latest:                  RegistryVersion{Version: "file:///Users/alice/.cache/latest-version.txt", PublishedAt: time.Date(2026, 7, 2, 2, 3, 4, 0, time.UTC), Deprecated: true},
			AgeDays:                 30,
			MatureCandidateSelected: true,
			Candidates: []RegistryVersion{
				{Version: "1.2.3", PublishedAt: time.Date(2026, 6, 1, 2, 3, 4, 0, time.UTC)},
				{Version: "path:/private/tmp/local-sec/candidate.tgz?token=candidate-query-token", PublishedAt: time.Date(2026, 6, 2, 2, 3, 4, 0, time.UTC)},
			},
			Skipped: []VersionSkip{
				{Version: "https://skip-user:skip-pass@packages.example.test/skipped.tgz?token=skip-query-token#skip-fragment", Reason: "wget --password skip-split-secret /Users/alice/private/skip.txt", AdvisoryIDs: []string{"https://advisories.example.test/skip?token=skip-id-token", `C:/Users/alice/private/skip-id.txt`}},
				{Version: "1.2.2", Reason: "maturity window", AdvisoryIDs: []string{"OSV-2026-1234"}},
			},
			Maintainers: []string{
				"alice@example.test",
				"https://users:maint-pass@packages.example.test/maintainer?token=maintainer-token",
				"/Users/alice/.npmrc",
			},
			Found: true,
		},
	}
}

func assertNoRawVersionEvidence(t *testing.T, label, body string) {
	t.Helper()
	for _, forbidden := range []string{
		"curl-user", "curl-pass", "curl-query-token", "curl-fragment",
		"wget-user", "wget-pass", "wget-query-token", "wget-fragment",
		"skip-user", "skip-pass", "skip-query-token", "skip-fragment", "skip-id-token",
		"curl-split-secret", "wget-split-secret", "skip-split-secret",
		"maint-pass", "maintainer-token",
		"/Users/alice", "/private/tmp", "C:/Users/alice",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("%s contains raw version evidence %q: %s", label, forbidden, body)
		}
	}
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		return !('0' <= r && r <= '9') && !('a' <= r && r <= 'f')
	}) == -1
}
