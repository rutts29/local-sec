package lsec

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	testFixtureID    = "npm-benign-lifecycle-v1"
	testEvidenceHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testArtifactHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func validMacOSDetonationJob() MacOSDetonationJob {
	return MacOSDetonationJob{
		Schema:         MacOSDetonationJobSchema,
		Version:        MacOSDetonationSchemaVersion,
		RunID:          "run-20260702-001",
		FixtureID:      testFixtureID,
		EvidenceSHA256: testEvidenceHash,
		Package: MacOSDetonationPackage{
			Ecosystem: "npm",
			Name:      "@fixture/example",
			Version:   "1.2.3",
		},
		ArtifactSHA256: testArtifactHash,
		ExpectedVM: MacOSDetonationVMRequirement{
			Provider: "fixture-provider",
			ImageID:  "macos-15-fixture-v1",
		},
		FixtureOnly:    true,
		CreatedAt:      time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC),
		TimeoutSeconds: 300,
		SafetyPolicy: MacOSDetonationSafetyPolicy{
			DisposableVM:            true,
			NoHostMounts:            true,
			NoSharedFolders:         true,
			NoClipboard:             true,
			NoRealCredentials:       true,
			NoRealHome:              true,
			NoShellHistory:          true,
			NoAgentData:             true,
			SyntheticHomeGenerated:  true,
			CanariesGeneratedInVM:   true,
			BoundedOutputs:          true,
			DestroyOrRevertAfterRun: true,
		},
	}
}

func validMacOSDetonationResult() MacOSDetonationResult {
	return MacOSDetonationResult{
		Schema:         MacOSDetonationResultSchema,
		Version:        MacOSDetonationSchemaVersion,
		RunID:          "run-20260702-001",
		FixtureID:      testFixtureID,
		EvidenceSHA256: testEvidenceHash,
		ArtifactSHA256: testArtifactHash,
		VM: MacOSDetonationVMIdentity{
			Provider:   "fixture-provider",
			ImageID:    "macos-15-fixture-v1",
			InstanceID: "vm-fixture-001",
		},
		FixtureOnly: true,
		StartedAt:   time.Date(2026, 7, 2, 10, 0, 1, 0, time.UTC),
		FinishedAt:  time.Date(2026, 7, 2, 10, 1, 1, 0, time.UTC),
		State:       MacOSDetonationStateComplete,
		Processes: []MacOSDetonationProcessSummary{{
			Image:    "node",
			Behavior: "spawned_fixture_helper",
		}},
		Files: []MacOSDetonationFileSummary{{
			Area:      "synthetic_home",
			Name:      "fixture-marker.txt",
			Operation: "created",
		}},
		Network: []MacOSDetonationNetworkSummary{{
			Protocol: "tcp",
			Host:     "sink.invalid",
			Port:     443,
			Outcome:  "sinkholed",
		}},
		Persistence: []MacOSDetonationPersistenceSummary{{
			Mechanism: "launch_agent",
			Target:    "fixture-agent",
			Outcome:   "observed",
		}},
		Canaries: []MacOSDetonationCanarySummary{{
			Name:    "fixture-token",
			Outcome: "read",
		}},
		Findings: []MacOSDetonationFinding{{
			Code:     "fixture_canary_read",
			Severity: "prompt",
			Summary:  "fixture_canary_read",
		}},
		DestroyedOrReverted: true,
	}
}

func TestMacOSDetonationJobRoundTrip(t *testing.T) {
	want := validMacOSDetonationJob()
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMacOSDetonationJobJSON(body)
	if err != nil {
		t.Fatalf("ParseMacOSDetonationJobJSON() error = %v", err)
	}
	if err := ValidateMacOSDetonationJob(got); err != nil {
		t.Fatalf("ValidateMacOSDetonationJob() error = %v", err)
	}
	assertJSONEqual(t, got, want)
}

func TestMacOSDetonationResultRoundTrip(t *testing.T) {
	job := validMacOSDetonationJob()
	want := validMacOSDetonationResult()
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMacOSDetonationResultJSON(body, job)
	if err != nil {
		t.Fatalf("ParseMacOSDetonationResultJSON() error = %v", err)
	}
	if err := ValidateMacOSDetonationResult(got, job); err != nil {
		t.Fatalf("ValidateMacOSDetonationResult() error = %v", err)
	}
	assertJSONEqual(t, got, want)
}

func TestMacOSDetonationJobRejectsInvalidContracts(t *testing.T) {
	tests := map[string]func(*MacOSDetonationJob){
		"schema":                       func(v *MacOSDetonationJob) { v.Schema = "other" },
		"version":                      func(v *MacOSDetonationJob) { v.Version++ },
		"run id":                       func(v *MacOSDetonationJob) { v.RunID = "" },
		"unknown fixture id":           func(v *MacOSDetonationJob) { v.FixtureID = "unknown-fixture" },
		"evidence hash":                func(v *MacOSDetonationJob) { v.EvidenceSHA256 = "ABC" },
		"artifact hash":                func(v *MacOSDetonationJob) { v.ArtifactSHA256 = strings.Repeat("A", 64) },
		"ecosystem":                    func(v *MacOSDetonationJob) { v.Package.Ecosystem = "" },
		"package name":                 func(v *MacOSDetonationJob) { v.Package.Name = "/Users/alice/pkg.tgz" },
		"package url":                  func(v *MacOSDetonationJob) { v.Package.Name = "https://example.test/pkg" },
		"unpinned range":               func(v *MacOSDetonationJob) { v.Package.Version = "^1.2.3" },
		"unpinned tag":                 func(v *MacOSDetonationJob) { v.Package.Version = "latest" },
		"non fixture":                  func(v *MacOSDetonationJob) { v.FixtureOnly = false },
		"fixture ecosystem mismatch":   func(v *MacOSDetonationJob) { v.Package.Ecosystem = "pypi" },
		"fixture name mismatch":        func(v *MacOSDetonationJob) { v.Package.Name = "arbitrary-package" },
		"fixture version mismatch":     func(v *MacOSDetonationJob) { v.Package.Version = "9.9.9" },
		"fixture hash mismatch":        func(v *MacOSDetonationJob) { v.ArtifactSHA256 = strings.Repeat("c", 64) },
		"fixture vm provider mismatch": func(v *MacOSDetonationJob) { v.ExpectedVM.Provider = "other-provider" },
		"fixture vm image mismatch":    func(v *MacOSDetonationJob) { v.ExpectedVM.ImageID = "other-image" },
		"zero created at":              func(v *MacOSDetonationJob) { v.CreatedAt = time.Time{} },
		"zero timeout":                 func(v *MacOSDetonationJob) { v.TimeoutSeconds = 0 },
		"excessive timeout":            func(v *MacOSDetonationJob) { v.TimeoutSeconds = MacOSDetonationMaxTimeoutSeconds + 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			job := validMacOSDetonationJob()
			mutate(&job)
			if err := ValidateMacOSDetonationJob(job); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestMacOSDetonationJobRejectsArbitraryPackageClaimingFixtureOnly(t *testing.T) {
	job := validMacOSDetonationJob()
	job.Package = MacOSDetonationPackage{Ecosystem: "npm", Name: "malicious-package", Version: "1.0.0"}
	job.FixtureOnly = true
	if err := ValidateMacOSDetonationJob(job); err == nil {
		t.Fatal("expected non-catalog package to be rejected")
	}
}

func TestMacOSDetonationJobRequiresEverySafetyInvariant(t *testing.T) {
	tests := map[string]func(*MacOSDetonationSafetyPolicy){
		"disposable vm":     func(v *MacOSDetonationSafetyPolicy) { v.DisposableVM = false },
		"host mounts":       func(v *MacOSDetonationSafetyPolicy) { v.NoHostMounts = false },
		"shared folders":    func(v *MacOSDetonationSafetyPolicy) { v.NoSharedFolders = false },
		"clipboard":         func(v *MacOSDetonationSafetyPolicy) { v.NoClipboard = false },
		"credentials":       func(v *MacOSDetonationSafetyPolicy) { v.NoRealCredentials = false },
		"home":              func(v *MacOSDetonationSafetyPolicy) { v.NoRealHome = false },
		"history":           func(v *MacOSDetonationSafetyPolicy) { v.NoShellHistory = false },
		"agent data":        func(v *MacOSDetonationSafetyPolicy) { v.NoAgentData = false },
		"synthetic home":    func(v *MacOSDetonationSafetyPolicy) { v.SyntheticHomeGenerated = false },
		"vm canaries":       func(v *MacOSDetonationSafetyPolicy) { v.CanariesGeneratedInVM = false },
		"bounded outputs":   func(v *MacOSDetonationSafetyPolicy) { v.BoundedOutputs = false },
		"destroy after run": func(v *MacOSDetonationSafetyPolicy) { v.DestroyOrRevertAfterRun = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			job := validMacOSDetonationJob()
			mutate(&job.SafetyPolicy)
			if err := ValidateMacOSDetonationJob(job); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestMacOSDetonationJobJSONRejectsUnsafeAndUnknownFields(t *testing.T) {
	for _, field := range []string{"local_path", "url", "package_bytes", "command", "env", "mounts"} {
		t.Run(field, func(t *testing.T) {
			body := addJSONField(t, validMacOSDetonationJob(), field, "unsafe")
			if _, err := ParseMacOSDetonationJobJSON(body); err == nil {
				t.Fatal("expected unknown-field error")
			}
		})
	}
	job := validMacOSDetonationJob()
	body, _ := json.Marshal(job)
	body = []byte(strings.Replace(string(body), `"run_id":"run-20260702-001"`, `"run_id":"first","run_id":"second"`, 1))
	if _, err := ParseMacOSDetonationJobJSON(body); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate field error = %v", err)
	}
}

func TestMacOSDetonationResultRejectsInvalidContracts(t *testing.T) {
	job := validMacOSDetonationJob()
	tests := map[string]func(*MacOSDetonationResult){
		"schema":               func(v *MacOSDetonationResult) { v.Schema = "other" },
		"version":              func(v *MacOSDetonationResult) { v.Version++ },
		"run mismatch":         func(v *MacOSDetonationResult) { v.RunID = "other" },
		"fixture mismatch":     func(v *MacOSDetonationResult) { v.FixtureID = "unknown-fixture" },
		"evidence mismatch":    func(v *MacOSDetonationResult) { v.EvidenceSHA256 = strings.Repeat("c", 64) },
		"artifact mismatch":    func(v *MacOSDetonationResult) { v.ArtifactSHA256 = strings.Repeat("d", 64) },
		"vm provider mismatch": func(v *MacOSDetonationResult) { v.VM.Provider = "other-provider" },
		"vm image mismatch":    func(v *MacOSDetonationResult) { v.VM.ImageID = "other-image" },
		"empty vm instance":    func(v *MacOSDetonationResult) { v.VM.InstanceID = "" },
		"invalid vm instance":  func(v *MacOSDetonationResult) { v.VM.InstanceID = "vm instance" },
		"non fixture":          func(v *MacOSDetonationResult) { v.FixtureOnly = false },
		"before creation":      func(v *MacOSDetonationResult) { v.StartedAt = job.CreatedAt.Add(-time.Second) },
		"finished first":       func(v *MacOSDetonationResult) { v.FinishedAt = v.StartedAt.Add(-time.Second) },
		"past timeout": func(v *MacOSDetonationResult) {
			v.FinishedAt = v.StartedAt.Add(time.Duration(job.TimeoutSeconds+1) * time.Second)
		},
		"nonterminal":   func(v *MacOSDetonationResult) { v.State = "running" },
		"not destroyed": func(v *MacOSDetonationResult) { v.DestroyedOrReverted = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := validMacOSDetonationResult()
			mutate(&result)
			if err := ValidateMacOSDetonationResult(result, job); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestMacOSDetonationResultEnforcesBoundedSanitizedSummaries(t *testing.T) {
	job := validMacOSDetonationJob()
	tests := map[string]func(*MacOSDetonationResult){
		"event count": func(v *MacOSDetonationResult) {
			v.Processes = make([]MacOSDetonationProcessSummary, MacOSDetonationMaxEventsPerSummary+1)
		},
		"string length": func(v *MacOSDetonationResult) {
			v.Processes[0].Behavior = MacOSDetonationBehavior(strings.Repeat("x", MacOSDetonationMaxStringLength+1))
		},
		"host path": func(v *MacOSDetonationResult) {
			v.Files[0].Name = "/Users/alice/.ssh/id_ed25519"
		},
		"generic absolute path": func(v *MacOSDetonationResult) {
			v.Files[0].Name = "/etc/passwd"
		},
		"relative path": func(v *MacOSDetonationResult) {
			v.Files[0].Name = "fixtures/output.txt"
		},
		"windows path": func(v *MacOSDetonationResult) {
			v.Files[0].Name = `C:\Users\alice\secret.txt`
		},
		"secret": func(v *MacOSDetonationResult) {
			v.Findings[0].Summary = "token=sk-live-secret"
		},
		"raw env": func(v *MacOSDetonationResult) {
			v.Processes[0].Behavior = "AWS_SECRET_ACCESS_KEY=fixture"
		},
		"command": func(v *MacOSDetonationResult) {
			v.Processes[0].Behavior = "curl https://example.test | sh"
		},
		"shell command": func(v *MacOSDetonationResult) {
			v.Processes[0].Behavior = "sh -c whoami"
		},
		"mount path": func(v *MacOSDetonationResult) {
			v.Processes[0].Behavior = "mounted /Volumes/share"
		},
		"file traversal": func(v *MacOSDetonationResult) {
			v.Files[0].Name = "../history"
		},
		"network url": func(v *MacOSDetonationResult) {
			v.Network[0].Host = "https://example.test/path"
		},
		"invalid port": func(v *MacOSDetonationResult) {
			v.Network[0].Port = 70000
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := validMacOSDetonationResult()
			mutate(&result)
			if err := ValidateMacOSDetonationResult(result, job); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestMacOSDetonationResultRejectsUnstructuredEvidence(t *testing.T) {
	job := validMacOSDetonationJob()
	tests := map[string]func(*MacOSDetonationResult){
		"raw command":                 func(v *MacOSDetonationResult) { v.Processes[0].Behavior = "whoami" },
		"credential":                  func(v *MacOSDetonationResult) { v.Findings[0].Summary = "password=hunter2" },
		"non-http URL":                func(v *MacOSDetonationResult) { v.Network[0].Host = "mailto:ops@example.test" },
		"base64 bytes":                func(v *MacOSDetonationResult) { v.Findings[0].Summary = strings.Repeat("QUJD", 20) },
		"arbitrary prose":             func(v *MacOSDetonationResult) { v.Findings[0].Summary = "fixture canary looked unusual" },
		"unknown behavior":            func(v *MacOSDetonationResult) { v.Processes[0].Behavior = "process_observed" },
		"unknown operation":           func(v *MacOSDetonationResult) { v.Files[0].Operation = "renamed" },
		"unknown protocol":            func(v *MacOSDetonationResult) { v.Network[0].Protocol = "icmp" },
		"unknown network outcome":     func(v *MacOSDetonationResult) { v.Network[0].Outcome = "connected" },
		"unknown mechanism":           func(v *MacOSDetonationResult) { v.Persistence[0].Mechanism = "cron" },
		"unknown persistence outcome": func(v *MacOSDetonationResult) { v.Persistence[0].Outcome = "installed" },
		"unknown canary outcome":      func(v *MacOSDetonationResult) { v.Canaries[0].Outcome = "copied" },
		"unknown severity":            func(v *MacOSDetonationResult) { v.Findings[0].Severity = "critical" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := validMacOSDetonationResult()
			mutate(&result)
			if err := ValidateMacOSDetonationResult(result, job); err == nil {
				t.Fatal("expected structured-evidence validation error")
			}
		})
	}
}

func TestMacOSDetonationResultRejectsAllControlCharacters(t *testing.T) {
	job := validMacOSDetonationJob()
	for value := 0; value <= 0x7f; value++ {
		if value > 0x1f && value != 0x7f {
			continue
		}
		result := validMacOSDetonationResult()
		result.Files[0].Name = "fixture" + string(rune(value)) + "marker"
		if err := ValidateMacOSDetonationResult(result, job); err == nil {
			t.Errorf("control character 0x%02x accepted", value)
		}
	}
}

func TestMacOSDetonationResultJSONRejectsUnknownDuplicateAndUnsafeFields(t *testing.T) {
	job := validMacOSDetonationJob()
	for _, field := range []string{"host_path", "secret", "raw_env", "command"} {
		t.Run(field, func(t *testing.T) {
			body := addJSONField(t, validMacOSDetonationResult(), field, "unsafe")
			if _, err := ParseMacOSDetonationResultJSON(body, job); err == nil {
				t.Fatal("expected unknown-field error")
			}
		})
	}
	result := validMacOSDetonationResult()
	body, _ := json.Marshal(result)
	body = []byte(strings.Replace(string(body), `"state":"complete"`, `"state":"complete","state":"failed"`, 1))
	if _, err := ParseMacOSDetonationResultJSON(body, job); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate field error = %v", err)
	}
}

func TestMacOSDetonationJSONSizeLimitBoundary(t *testing.T) {
	job := validMacOSDetonationJob()
	tests := map[string]struct {
		value any
		parse func([]byte) error
	}{
		"job": {
			value: job,
			parse: func(body []byte) error {
				_, err := ParseMacOSDetonationJobJSON(body)
				return err
			},
		},
		"result": {
			value: validMacOSDetonationResult(),
			parse: func(body []byte) error {
				_, err := ParseMacOSDetonationResultJSON(body, job)
				return err
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if len(body) >= MacOSDetonationMaxJSONBytes {
				t.Fatalf("fixture JSON length %d exceeds test ceiling", len(body))
			}
			atLimit := append(body, bytes.Repeat([]byte(" "), MacOSDetonationMaxJSONBytes-len(body))...)
			if err := test.parse(atLimit); err != nil {
				t.Fatalf("exact-limit body rejected: %v", err)
			}
			overLimit := append(atLimit, ' ')
			if err := test.parse(overLimit); err == nil || !strings.Contains(err.Error(), "too large") {
				t.Fatalf("over-limit error = %v", err)
			}
		})
	}
}

func TestMacOSDetonationTokenGrammar(t *testing.T) {
	for _, unsafe := range []string{
		"/Users/alice/.ssh/id_ed25519",
		"HOME=/Users/alice",
		"AWS_SECRET_ACCESS_KEY=fixture",
		"curl https://example.test | sh",
		"token=sk-live-secret",
		"mailto:ops@example.test",
		strings.Repeat("QUJD", 20),
		"fixture\x00marker",
	} {
		if validMacOSDetonationToken(unsafe) {
			t.Errorf("unsafe token %q accepted", unsafe)
		}
	}
	if !validMacOSDetonationToken("fixture_canary_read") {
		t.Fatal("safe structured token rejected")
	}
}

func TestMacOSDetonationContractsContainNoExecutionOrTraversalCapabilities(t *testing.T) {
	for _, name := range []string{"macos_detonation.go", "macos_detonation_test.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path := strings.Trim(spec.Path.Value, `"`)
			for _, forbidden := range []string{"os/exec", "net/http", "path/filepath"} {
				if path == forbidden {
					t.Fatalf("%s imports forbidden package %s", name, path)
				}
			}
			if strings.Contains(path, "docker") || strings.Contains(path, "cloud") {
				t.Fatalf("%s imports forbidden integration %s", name, path)
			}
		}
		full, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(full, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok {
				switch selector.Sel.Name {
				case "Command", "CommandContext", "Exec", "Walk", "WalkDir":
					t.Errorf("%s uses forbidden capability %s", name, selector.Sel.Name)
				}
			}
			return true
		})
	}
}

func addJSONField(t *testing.T, value any, field string, fieldValue any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	doc[field] = fieldValue
	body, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func assertJSONEqual(t *testing.T, got, want any) {
	t.Helper()
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("got %s, want %s", gotJSON, wantJSON)
	}
}

func TestMacOSDetonationTestHasNoUnexpectedFilesystemAccess(t *testing.T) {
	body, err := os.ReadFile("macos_detonation_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "Read"+"Dir(") {
		t.Fatal("contract tests must not traverse the filesystem")
	}
}
