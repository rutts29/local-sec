package lsec

import "context"

type SandboxMode string

const (
	SandboxModeDisabled      SandboxMode = "disabled"
	SandboxModeFakeCanary    SandboxMode = "fake_canary"
	SandboxModeDockerFixture SandboxMode = "docker_fixture"
)

type SandboxRequest struct {
	Mode      SandboxMode     `json:"mode"`
	Command   []string        `json:"command,omitempty"`
	Root      string          `json:"root,omitempty"`
	WorkDir   string          `json:"work_dir,omitempty"`
	Env       []string        `json:"env,omitempty"`
	Analysis  CommandAnalysis `json:"analysis,omitempty"`
	Version   VersionInfo     `json:"version,omitempty"`
	Artifacts []Artifact      `json:"artifacts,omitempty"`
}

type SandboxResult struct {
	Mode     SandboxMode     `json:"mode"`
	Findings []Finding       `json:"findings,omitempty"`
	Evidence SandboxEvidence `json:"evidence,omitempty"`
}

type SandboxRunner interface {
	RunSandbox(context.Context, SandboxRequest) (SandboxResult, error)
}

func ApplySandboxResult(report RunReport, result SandboxResult) RunReport {
	report.Findings = append(report.Findings, result.Findings...)
	evidence := result.Evidence
	if result.Mode != "" && evidence.Mode == "" {
		evidence.Mode = string(result.Mode)
	}
	if result.Mode != "" && result.Mode != SandboxModeDisabled {
		evidence.Enabled = true
	}
	report.Sandbox = evidence
	report.Decision = DefaultPolicy().Evaluate(report.Analysis, report.Version, report.Findings, report.Advisories)
	return report
}
