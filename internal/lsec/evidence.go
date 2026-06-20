package lsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type EvidenceBundle struct {
	RunID          string          `json:"run_id"`
	EvidenceSHA256 string          `json:"evidence_sha256,omitempty"`
	Analysis       CommandAnalysis `json:"analysis"`
	Version        VersionInfo     `json:"version"`
	Artifacts      []Artifact      `json:"artifacts"`
	Findings       []Finding       `json:"findings"`
	Advisories     []Advisory      `json:"advisories"`
	Decision       Decision        `json:"decision"`
	Sandbox        SandboxEvidence `json:"sandbox,omitempty"`
}

type SandboxEvidence struct {
	Enabled         bool              `json:"enabled"`
	Mode            string            `json:"mode,omitempty"`
	ProcessEvents   []ProcessEvent    `json:"process_events,omitempty"`
	FileEvents      []FileEvent       `json:"file_events,omitempty"`
	NetworkEvents   []NetworkEvent    `json:"network_events,omitempty"`
	CanaryEvents    []CanaryEvent     `json:"canary_events,omitempty"`
	GeneratedFiles  []GeneratedFile   `json:"generated_files,omitempty"`
	FakeEnvironment map[string]string `json:"fake_environment,omitempty"`
}

type ProcessEvent struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args,omitempty"`
}

type FileEvent struct {
	Operation string `json:"operation"`
	Path      string `json:"path"`
}

type NetworkEvent struct {
	Protocol       string `json:"protocol"`
	Destination    string `json:"destination"`
	ContainsCanary bool   `json:"contains_canary,omitempty"`
}

type CanaryEvent struct {
	Kind        string `json:"kind"`
	Marker      string `json:"marker"`
	Path        string `json:"path,omitempty"`
	Destination string `json:"destination,omitempty"`
}

type GeneratedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
}

func BuildEvidenceBundle(report RunReport) EvidenceBundle {
	bundle := EvidenceBundle{
		RunID: report.RunID, Analysis: report.Analysis, Version: report.Version,
		Artifacts: report.Artifacts, Findings: report.Findings, Advisories: report.Advisories,
		Decision: report.Decision,
	}
	bundle.EvidenceSHA256 = evidenceBundleHash(bundle)
	return bundle
}

func (bundle EvidenceBundle) RunReport() RunReport {
	return RunReport{
		RunID: bundle.RunID, Analysis: bundle.Analysis, Version: bundle.Version,
		Artifacts: bundle.Artifacts, Findings: bundle.Findings, Advisories: bundle.Advisories,
		Decision: bundle.Decision,
	}
}

func evidenceBundleHash(bundle EvidenceBundle) string {
	bundle.EvidenceSHA256 = ""
	body, err := json.Marshal(bundle)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
