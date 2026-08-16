package lsec

import (
	"path/filepath"
	"strings"
)

func rewriteCommandForSelectedVersion(command []string, report RunReport) []string {
	if report.Analysis.LockfileInstall {
		return []string{command[0], "ci", "--ignore-scripts"}
	}
	if report.Analysis.Manager == "npm" && report.Analysis.Action == "init" {
		if rewritten, ok := rewriteNPMInitCommand(command, report); ok {
			return rewritten
		}
	}
	if report.Analysis.RequirementsFile {
		if rewritten, ok := rewritePipRequirementsCommand(command, report); ok {
			return rewritten
		}
	}
	if !report.Version.Found || report.Version.Selected.Version == "" || len(report.Analysis.PackageSpecs) == 0 {
		return command
	}
	selectedName := report.Analysis.PackageSpecs[0].Name
	if selectedName == "" {
		return command
	}
	selected := []string{selectedName}
	if staged, ok := stagedInstallSpecs(report); ok {
		selected = staged
	} else {
		switch report.Analysis.Manager {
		case "npm", "npx":
			selected = []string{selectedName + "@" + report.Version.Selected.Version}
		case "pip", "pip3", "uv", "uvx", "pipx":
			selected = []string{selectedName + "==" + report.Version.Selected.Version}
		default:
			return command
		}
	}
	out := append([]string(nil), command...)
	for i, arg := range out {
		if arg == report.Analysis.PackageSpecs[0].Raw {
			out = append(out[:i], append(selected, out[i+1:]...)...)
			break
		}
		if len(selected) != 1 {
			continue
		}
		selectedArg := selected[0]
		if strings.HasPrefix(arg, "--package=") && strings.TrimPrefix(arg, "--package=") == report.Analysis.PackageSpecs[0].Raw {
			out[i] = "--package=" + selectedArg
			break
		}
		if strings.HasPrefix(arg, "--from=") && strings.TrimPrefix(arg, "--from=") == report.Analysis.PackageSpecs[0].Raw {
			out[i] = "--from=" + selectedArg
			break
		}
		if strings.HasPrefix(arg, "--spec=") && strings.TrimPrefix(arg, "--spec=") == report.Analysis.PackageSpecs[0].Raw {
			out[i] = "--spec=" + selectedArg
			break
		}
	}
	if report.Analysis.Manager == "npm" && report.Analysis.Action == "install" {
		out = appendIfMissing(out, "--ignore-scripts")
	}
	if (report.Analysis.Manager == "pip" || report.Analysis.Manager == "pip3") && report.Analysis.Action == "install" {
		if dir, ok := pipWheelhouseDir(report); ok && len(report.Artifacts) > 1 {
			out = insertPipInstallFlags(out, report.Analysis, []string{"--no-index", "--find-links", dir})
		} else {
			out = insertPipInstallFlags(out, report.Analysis, []string{"--no-index", "--no-deps"})
		}
	}
	return out
}

func appendIfMissing(args []string, value string) []string {
	if stringSliceHas(args, value) {
		return args
	}
	return append(args, value)
}

func stringSliceHas(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func rewriteNPMInitCommand(command []string, report RunReport) ([]string, bool) {
	if !report.Version.Found || report.Version.Selected.Version == "" || len(report.Analysis.PackageSpecs) == 0 {
		return nil, false
	}
	selected := report.Analysis.PackageSpecs[0].Name
	if selected == "" {
		return nil, false
	}
	selected += "@" + report.Version.Selected.Version
	out := []string{command[0], "exec", selected}
	for i := 2; i < len(command); i++ {
		if command[i] == report.Analysis.PackageSpecs[0].Raw {
			out = append(out, command[i+1:]...)
			return out, true
		}
	}
	return nil, false
}

func rewritePipRequirementsCommand(command []string, report RunReport) ([]string, bool) {
	if report.Analysis.Manager != "pip" && report.Analysis.Manager != "pip3" {
		return nil, false
	}
	if len(report.Artifacts) == 0 {
		return nil, false
	}
	dir := filepath.Dir(report.Artifacts[0].Path)
	if dir == "." || dir == "" {
		return nil, false
	}
	out := append([]string(nil), command...)
	insert := pipInstallArgIndex(out, report.Analysis)
	if insert < 0 {
		return nil, false
	}
	flags := []string{"--require-hashes", "--no-index", "--find-links", dir}
	out = append(out[:insert], append(flags, out[insert:]...)...)
	return out, true
}

func insertPipInstallFlags(command []string, analysis CommandAnalysis, flags []string) []string {
	insert := pipInstallArgIndex(command, analysis)
	if insert < 0 {
		return command
	}
	out := append([]string(nil), command...)
	for i := len(flags) - 1; i >= 0; i-- {
		if stringSliceHas(out, flags[i]) {
			continue
		}
		out = append(out[:insert], append([]string{flags[i]}, out[insert:]...)...)
	}
	return out
}

func pipInstallArgIndex(command []string, analysis CommandAnalysis) int {
	if analysis.PythonModulePip || isPythonPip(command) {
		for i := 0; i < len(command); i++ {
			if command[i] == "install" {
				return i + 1
			}
		}
		return -1
	}
	if len(command) >= 2 && command[1] == "install" {
		return 2
	}
	return -1
}

func stagedInstallSpecs(report RunReport) ([]string, bool) {
	if len(report.Artifacts) == 0 {
		return nil, false
	}
	switch report.Analysis.Manager {
	case "npm":
		artifact, ok := stagedNPMInstallArtifact(report.Analysis, report.Version, report.Artifacts)
		if !ok {
			return nil, false
		}
		return []string{artifact.Path}, true
	case "pip", "pip3":
		if len(report.Artifacts) == 1 && report.Artifacts[0].Kind == "wheel" {
			return []string{report.Artifacts[0].Path}, true
		}
	}
	return nil, false
}

func pipWheelhouseDir(report RunReport) (string, bool) {
	if len(report.Artifacts) == 0 {
		return "", false
	}
	dir := filepath.Dir(report.Artifacts[0].Path)
	if dir == "." || dir == "" {
		return "", false
	}
	for _, artifact := range report.Artifacts {
		if artifact.Kind != "wheel" || filepath.Dir(artifact.Path) != dir {
			return "", false
		}
	}
	return dir, true
}
