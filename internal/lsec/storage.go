package lsec

import "time"

type Approval struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Hash      string    `json:"hash,omitempty"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

type AdvisoryCacheEntry struct {
	Ecosystem  string     `json:"ecosystem"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	CheckedAt  time.Time  `json:"checked_at"`
	Advisories []Advisory `json:"advisories"`
}

type Store struct {
	paths Paths
}

type EventSummary struct {
	Kind      string    `json:"kind"`
	RunID     string    `json:"run_id"`
	Verdict   Verdict   `json:"verdict,omitempty"`
	Lane      RiskLane  `json:"lane,omitempty"`
	Command   string    `json:"command,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type PackageSummary struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Hash      string    `json:"hash"`
	Kind      string    `json:"kind"`
	RunID     string    `json:"run_id"`
	Verdict   Verdict   `json:"verdict"`
	Lane      RiskLane  `json:"lane"`
	Approved  bool      `json:"approved"`
	SeenAt    time.Time `json:"seen_at"`
}

type LocalStatus struct {
	Runs             int
	Packages         int
	Approvals        int
	ApprovedPackages int
	ScanRuns         int
	PartialScanRuns  int
	ScanFindings     int
	ScanDiagnostics  int
	Verdicts         map[Verdict]int
	Lanes            map[RiskLane]int
}

func NewStore(paths Paths) Store {
	return Store{paths: paths}
}

func (s Store) eventLog() eventLog {
	return eventLog{path: s.paths.Events}
}
