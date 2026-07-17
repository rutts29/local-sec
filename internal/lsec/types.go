package lsec

import "time"

type Verdict string

const (
	VerdictAllow  Verdict = "allow"
	VerdictPrompt Verdict = "prompt"
	VerdictBlock  Verdict = "block"
)

type RiskLane string

const (
	LaneTrusted RiskLane = "trusted"
	LaneRisky   RiskLane = "risky"
	LaneBlock   RiskLane = "block"
)

type PackageSpec struct {
	Raw       string `json:"raw"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	DirectURL bool   `json:"direct_url,omitempty"`
	VCS       bool   `json:"vcs,omitempty"`
	LocalPath bool   `json:"local_path,omitempty"`
	Range     bool   `json:"range,omitempty"`
}

type RiskFlag struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Evidence string `json:"evidence,omitempty"`
}

type CommandAnalysis struct {
	Raw              []string      `json:"raw"`
	Manager          string        `json:"manager"`
	Action           string        `json:"action"`
	PackageSpecs     []PackageSpec `json:"package_specs"`
	OneShot          bool          `json:"one_shot"`
	Global           bool          `json:"global"`
	DirectURL        bool          `json:"direct_url"`
	VCSDependency    bool          `json:"vcs_dependency"`
	LocalPath        bool          `json:"local_path"`
	VersionRange     bool          `json:"version_range"`
	RemoteShell      bool          `json:"remote_shell"`
	PythonModulePip  bool          `json:"python_module_pip"`
	SourceBuild      bool          `json:"source_build"`
	RequirementsFile bool          `json:"requirements_file"`
	RequirementFiles []string      `json:"requirement_files,omitempty"`
	LockfileInstall  bool          `json:"lockfile_install"`
	LockfilePath     string        `json:"lockfile_path,omitempty"`
	ScopedInstall    bool          `json:"scoped_install"`
	RiskFlags        []RiskFlag    `json:"risk_flags"`
}

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	File     string `json:"file,omitempty"`
	Message  string `json:"message"`
	Evidence string `json:"evidence,omitempty"`
}

type Advisory struct {
	Source    string `json:"source"`
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Severity  string `json:"severity"`
	Type      string `json:"type,omitempty"`
	Summary   string `json:"summary,omitempty"`
	URL       string `json:"url,omitempty"`
}

type Decision struct {
	Verdict Verdict  `json:"verdict"`
	Lane    RiskLane `json:"lane"`
	Reasons []string `json:"reasons"`
}

type LLMReview struct {
	Schema         string   `json:"schema"`
	Version        int      `json:"version"`
	EvidenceSHA256 string   `json:"evidence_sha256"`
	Verdict        Verdict  `json:"verdict"`
	Confidence     string   `json:"confidence"`
	Reasons        []string `json:"reasons"`
	Signals        []string `json:"signals"`
}

type RegistryVersion struct {
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	Yanked      bool      `json:"yanked,omitempty"`
	Deprecated  bool      `json:"deprecated,omitempty"`
}

type VersionSkip struct {
	Version     string   `json:"version"`
	Reason      string   `json:"reason"`
	AdvisoryIDs []string `json:"advisory_ids,omitempty"`
}

type VersionInfo struct {
	Requested               string            `json:"requested"`
	Selected                RegistryVersion   `json:"selected"`
	Latest                  RegistryVersion   `json:"latest"`
	AgeDays                 int               `json:"age_days"`
	MatureCandidateSelected bool              `json:"mature_candidate_selected"`
	Skipped                 []VersionSkip     `json:"skipped,omitempty"`
	Candidates              []RegistryVersion `json:"-"`
	Maintainers             []string          `json:"maintainers,omitempty"`
	Found                   bool              `json:"found"`
}

type RunReport struct {
	RunID      string          `json:"run_id"`
	Analysis   CommandAnalysis `json:"analysis"`
	Version    VersionInfo     `json:"version"`
	Artifacts  []Artifact      `json:"artifacts"`
	Findings   []Finding       `json:"findings"`
	Advisories []Advisory      `json:"advisories"`
	Sandbox    SandboxEvidence `json:"sandbox,omitempty"`
	Decision   Decision        `json:"decision"`
	CreatedAt  time.Time       `json:"created_at"`
}

type Artifact struct {
	Path         string          `json:"path"`
	SHA256       string          `json:"sha256"`
	Kind         string          `json:"kind"`
	Ecosystem    string          `json:"ecosystem,omitempty"`
	Name         string          `json:"name,omitempty"`
	Version      string          `json:"version,omitempty"`
	Dependencies []DependencyRef `json:"dependencies,omitempty"`
}

type DependencyRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Raw       string `json:"raw"`
	Exact     bool   `json:"exact"`
}

type Policy struct {
	MaturityDays int
}
