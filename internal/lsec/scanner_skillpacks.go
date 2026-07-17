package lsec

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed skillpacks/static-scanner.json
var embeddedStaticSkillpackData []byte

type staticScannerConfig struct {
	lifecycleScripts    map[string]bool
	sourceFileNames     map[string]bool
	sourceFileSuffixes  []string
	sourceExtensions    map[string]bool
	credentialPatterns  []string
	networkPatterns     []string
	executionPatterns   []string
	obfuscationPatterns []string
	persistencePatterns []string
	findings            map[string]skillpackFinding
}

type embeddedStaticSkillpack struct {
	Name     string                         `json:"name"`
	Version  string                         `json:"version"`
	Patterns embeddedStaticSkillpackSignals `json:"patterns"`
	Findings map[string]skillpackFinding    `json:"findings"`
}

type embeddedStaticSkillpackSignals struct {
	Credential          []string `json:"credential"`
	Network             []string `json:"network"`
	Execution           []string `json:"execution"`
	Obfuscation         []string `json:"obfuscation"`
	Persistence         []string `json:"persistence"`
	NPMLifecycleScripts []string `json:"npm_lifecycle_scripts"`
	SourceFileNames     []string `json:"source_file_names"`
	SourceFileSuffixes  []string `json:"source_file_suffixes"`
	SourceExtensions    []string `json:"source_extensions"`
}

type skillpackFinding struct {
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	SourceMessage  string `json:"source_message"`
	PackageMessage string `json:"package_message"`
}

var defaultStaticScannerConfig = mustLoadEmbeddedStaticScannerConfig()

func mustLoadEmbeddedStaticScannerConfig() staticScannerConfig {
	var pack embeddedStaticSkillpack
	if err := json.Unmarshal(embeddedStaticSkillpackData, &pack); err != nil {
		panic(fmt.Sprintf("parse embedded static skillpack: %v", err))
	}
	cfg := staticScannerConfig{
		lifecycleScripts: make(map[string]bool),
		sourceFileNames:  make(map[string]bool),
		sourceExtensions: make(map[string]bool),
		findings:         make(map[string]skillpackFinding),
	}
	cfg.merge(pack)
	cfg.validate()
	return cfg
}

func (cfg *staticScannerConfig) merge(pack embeddedStaticSkillpack) {
	cfg.credentialPatterns = appendUniqueStrings(cfg.credentialPatterns, pack.Patterns.Credential...)
	cfg.networkPatterns = appendUniqueStrings(cfg.networkPatterns, pack.Patterns.Network...)
	cfg.executionPatterns = appendUniqueStrings(cfg.executionPatterns, pack.Patterns.Execution...)
	cfg.obfuscationPatterns = appendUniqueStrings(cfg.obfuscationPatterns, pack.Patterns.Obfuscation...)
	cfg.persistencePatterns = appendUniqueStrings(cfg.persistencePatterns, pack.Patterns.Persistence...)
	cfg.sourceFileSuffixes = appendUniqueStrings(cfg.sourceFileSuffixes, pack.Patterns.SourceFileSuffixes...)
	for _, script := range pack.Patterns.NPMLifecycleScripts {
		cfg.lifecycleScripts[strings.ToLower(script)] = true
	}
	for _, name := range pack.Patterns.SourceFileNames {
		cfg.sourceFileNames[strings.ToLower(name)] = true
	}
	for _, ext := range pack.Patterns.SourceExtensions {
		cfg.sourceExtensions[strings.ToLower(ext)] = true
	}
	for code, finding := range pack.Findings {
		cfg.findings[code] = finding
	}
}

func (cfg staticScannerConfig) validate() {
	requiredFindings := []string{
		"npm_lifecycle_script",
		"persistence_write_pattern",
		"credential_exfil_pattern",
		"credential_path_reference",
		"obfuscated_network_payload",
		"obfuscation_pattern",
		"process_execution",
		"network_api",
	}
	for _, code := range requiredFindings {
		if _, ok := cfg.findings[code]; !ok {
			panic("embedded static skillpack missing finding metadata for " + code)
		}
	}
}

func (cfg staticScannerConfig) findingText(code, context string) (string, string) {
	finding := cfg.findings[code]
	message := finding.Message
	if context == "source" && finding.SourceMessage != "" {
		message = finding.SourceMessage
	}
	if context == "package" && finding.PackageMessage != "" {
		message = finding.PackageMessage
	}
	return finding.Severity, message
}
