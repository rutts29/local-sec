package lsec

import (
	"path/filepath"
	"regexp"
	"strings"
)

var protectedCommands = map[string]bool{
	"npm": true, "npx": true, "pip": true, "pip3": true, "python": true, "python3": true,
	"uv": true, "uvx": true, "pipx": true, "curl": true, "wget": true,
}

var versionedPythonExecutablePattern = regexp.MustCompile(`^python3\.[0-9]+$`)

func Classify(args []string) CommandAnalysis {
	out := CommandAnalysis{Raw: append([]string(nil), args...)}
	if len(args) == 0 {
		return out
	}

	cmd := filepath.Base(args[0])
	if moduleIdx, ok := pythonPipModuleIndex(args); ok {
		out.Manager = "pip"
		out.Action = actionAt(args, moduleIdx+2)
		out.PythonModulePip = true
		out.PackageSpecs = parsePackageArgs(args[moduleIdx+3:])
		markRisk(&out)
		return out
	}

	if !protectedCommands[cmd] {
		out.Manager = cmd
		return out
	}
	out.Manager = cmd

	switch cmd {
	case "npm":
		classifyNPM(&out, args[1:])
	case "npx":
		out.Action = "exec"
		out.OneShot = true
		out.PackageSpecs = parseOneShotPackageArgs(args[1:])
	case "pip", "pip3":
		out.Action = actionAt(args, 1)
		if out.Action == "install" {
			out.PackageSpecs = parsePackageArgs(args[2:])
		}
	case "uv":
		classifyUV(&out, args[1:])
	case "uvx":
		out.Action = "tool run"
		out.OneShot = true
		out.PackageSpecs = parseUVToolRunPackageArgs(args[1:])
	case "pipx":
		classifyPipx(&out, args[1:])
	case "curl", "wget":
		out.Action = "download"
		out.PackageSpecs = parseDownloaderPackageArgs(args[1:])
		out.RemoteShell = hasPipeToShell(args)
		if !out.RemoteShell {
			out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "remote_download", Severity: "prompt", Message: "remote downloader command requires review"})
		}
	}

	markRisk(&out)
	return out
}

func classifyNPM(out *CommandAnalysis, args []string) {
	out.Action = actionAt(args, 0)
	switch out.Action {
	case "i", "install", "add":
		out.Action = "install"
		out.PackageSpecs = parsePackageArgs(args[1:])
		if len(out.PackageSpecs) == 0 {
			out.LockfileInstall = true
			out.LockfilePath = "package-lock.json"
		}
	case "exec":
		out.OneShot = true
		out.PackageSpecs = parseOneShotPackageArgs(args[1:])
	case "init", "create", "innit":
		out.Action = "init"
		out.OneShot = true
		if spec, ok := npmInitPackageSpec(args[1:]); ok {
			out.PackageSpecs = []PackageSpec{spec}
		}
	}
}

func classifyUV(out *CommandAnalysis, args []string) {
	out.Action = actionAt(args, 0)
	switch out.Action {
	case "add":
		out.PackageSpecs = parsePackageArgs(args[1:])
	case "pip":
		if len(args) > 1 {
			out.Action = "pip " + args[1]
		}
		if len(args) > 1 && args[1] == "install" {
			out.PackageSpecs = parsePackageArgs(args[2:])
		}
	case "tool":
		if len(args) > 1 && args[1] == "run" {
			out.Action = "tool run"
			out.OneShot = true
			out.PackageSpecs = parseUVToolRunPackageArgs(args[2:])
		}
	}
}

func classifyPipx(out *CommandAnalysis, args []string) {
	out.Action = actionAt(args, 0)
	if out.Action == "run" {
		out.OneShot = true
		out.PackageSpecs = parsePipxRunPackageArgs(args[1:])
		return
	}
	if out.Action == "install" {
		out.PackageSpecs = parsePackageArgs(args[1:])
	}
}

func isPythonPip(args []string) bool {
	_, ok := pythonPipModuleIndex(args)
	return ok
}

func pythonPipModuleIndex(args []string) (int, bool) {
	if len(args) < 4 {
		return 0, false
	}
	base := filepath.Base(args[0])
	if !isPythonExecutableName(base) {
		return 0, false
	}
	for i := 1; i+1 < len(args); i++ {
		if args[i] == "-m" && (args[i+1] == "pip" || args[i+1] == "pip3") {
			return i, true
		}
		if args[i] == "--" || !strings.HasPrefix(args[i], "-") {
			return 0, false
		}
		if pythonInterpreterFlagTakesValue(args[i]) {
			i++
		}
	}
	return 0, false
}

func isPythonExecutableName(name string) bool {
	return name == "python" || name == "python3" || name == "py" || versionedPythonExecutablePattern.MatchString(name)
}

func pythonInterpreterFlagTakesValue(flag string) bool {
	return flag == "-c" || flag == "-W" || flag == "-X"
}

func actionAt(args []string, idx int) string {
	if len(args) <= idx {
		return ""
	}
	return args[idx]
}

func parsePackageArgs(args []string) []PackageSpec {
	var specs []PackageSpec
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if flagTakesValue(arg) {
				skipNext = true
			}
			continue
		}
		if arg == "|" || arg == "sh" || arg == "bash" || arg == "zsh" {
			continue
		}
		specs = append(specs, ParsePackageSpec(arg))
	}
	return specs
}

func parseDownloaderPackageArgs(args []string) []PackageSpec {
	var specs []PackageSpec
	for _, arg := range args {
		lower := strings.ToLower(arg)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			specs = append(specs, ParsePackageSpec(arg))
		}
	}
	return specs
}

func parseOneShotPackageArgs(args []string) []PackageSpec {
	var flagged []PackageSpec
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--package" || arg == "-p":
			if i+1 < len(args) {
				flagged = append(flagged, ParsePackageSpec(args[i+1]))
				i++
			}
		case strings.HasPrefix(arg, "--package="):
			flagged = append(flagged, ParsePackageSpec(strings.TrimPrefix(arg, "--package=")))
		}
	}
	if len(flagged) > 0 {
		return flagged
	}
	for _, arg := range args {
		if arg == "--" {
			return nil
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return []PackageSpec{ParsePackageSpec(arg)}
	}
	return nil
}

func parseUVToolRunPackageArgs(args []string) []PackageSpec {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--from":
			if i+1 < len(args) {
				return []PackageSpec{ParsePackageSpec(args[i+1])}
			}
		case strings.HasPrefix(arg, "--from="):
			return []PackageSpec{ParsePackageSpec(strings.TrimPrefix(arg, "--from="))}
		}
	}
	return parseOneShotPackageArgs(args)
}

func parsePipxRunPackageArgs(args []string) []PackageSpec {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--spec":
			if i+1 < len(args) {
				return []PackageSpec{ParsePackageSpec(args[i+1])}
			}
		case strings.HasPrefix(arg, "--spec="):
			return []PackageSpec{ParsePackageSpec(strings.TrimPrefix(arg, "--spec="))}
		}
	}
	return parsePackageArgs(args)
}

func npmInitPackageSpec(args []string) (PackageSpec, bool) {
	for _, arg := range args {
		if arg == "--" {
			return PackageSpec{}, false
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		spec := ParsePackageSpec(arg)
		spec.Name = npmCreatePackageName(spec.Name)
		return spec, spec.Name != ""
	}
	return PackageSpec{}, false
}

func npmCreatePackageName(initializer string) string {
	if initializer == "" {
		return ""
	}
	if strings.HasPrefix(initializer, "@") {
		withoutScope := strings.TrimPrefix(initializer, "@")
		parts := strings.SplitN(withoutScope, "/", 2)
		if parts[0] == "" {
			return initializer
		}
		if len(parts) == 1 || parts[1] == "" {
			return "@" + parts[0] + "/create"
		}
		return "@" + parts[0] + "/create-" + parts[1]
	}
	return "create-" + initializer
}

func ParsePackageSpec(raw string) PackageSpec {
	spec := PackageSpec{Raw: raw, Name: raw}
	lower := strings.ToLower(raw)
	spec.DirectURL = strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".whl")
	spec.VCS = isVCSSpec(raw)
	spec.LocalPath = isLocalPathSpec(raw)
	if spec.DirectURL || spec.VCS || spec.LocalPath {
		return spec
	}
	if strings.Contains(raw, "==") {
		parts := strings.SplitN(raw, "==", 2)
		spec.Name = trimExtras(parts[0])
		spec.Version = exactSpecVersion(parts[1])
		return spec
	}
	if name, ok := splitPythonRangeSpec(raw); ok {
		spec.Name = trimExtras(name)
		spec.Range = true
		return spec
	}
	if strings.Contains(raw, "@") && !strings.HasPrefix(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		spec.Name = parts[0]
		version := exactSpecVersion(parts[1])
		spec.Version = version
		spec.Range = version == "" && isNPMRangeSpec(parts[1])
		return spec
	}
	if strings.HasPrefix(raw, "@") {
		if idx := strings.LastIndex(raw[1:], "@"); idx >= 0 {
			pos := idx + 1
			spec.Name = raw[:pos]
			versionText := raw[pos+1:]
			version := exactSpecVersion(versionText)
			spec.Version = version
			spec.Range = version == "" && isNPMRangeSpec(versionText)
		}
	}
	spec.Name = trimExtras(spec.Name)
	return spec
}

func isVCSSpec(raw string) bool {
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"git+", "git://", "ssh://", "git@", "github:", "gitlab:", "bitbucket:", "gist:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, marker := range []string{"github.com/", "gitlab.com/", "bitbucket.org/"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if strings.HasPrefix(raw, "@") || strings.Contains(raw, "://") {
		return false
	}
	parts := strings.Split(raw, "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != "" && !strings.ContainsAny(raw, " \t")
}

func splitPythonRangeSpec(raw string) (string, bool) {
	for _, op := range []string{"~=", ">=", "<=", "!=", "===", ">", "<"} {
		if idx := strings.Index(raw, op); idx > 0 {
			return raw[:idx], true
		}
	}
	return "", false
}

func isNPMRangeSpec(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	if strings.ContainsAny(version, "^~<>=*| ") {
		return true
	}
	lower := strings.ToLower(version)
	return strings.Contains(lower, "x")
}

func exactSpecVersion(version string) string {
	version = strings.TrimSpace(version)
	if exactVersionPattern.MatchString(version) {
		return version
	}
	return ""
}

func trimExtras(name string) string {
	if i := strings.Index(name, "["); i >= 0 {
		return name[:i]
	}
	return name
}

func isLocalPathSpec(raw string) bool {
	lower := strings.ToLower(raw)
	return raw == "." ||
		raw == ".." ||
		strings.HasPrefix(raw, "./") ||
		strings.HasPrefix(raw, "../") ||
		strings.HasPrefix(raw, "/") ||
		strings.HasPrefix(raw, "~/") ||
		strings.HasPrefix(lower, "file:") ||
		strings.HasPrefix(lower, "workspace:") ||
		isBareArchiveFileSpec(lower)
}

func isBareArchiveFileSpec(lower string) bool {
	if strings.Contains(lower, "://") || strings.ContainsAny(lower, `/\`) {
		return false
	}
	for _, suffix := range []string{".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".whl"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func flagTakesValue(flag string) bool {
	switch flag {
	case "-r", "--requirement", "-c", "--constraint", "-d", "--dest", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host", "--cert", "--client-cert", "--spec", "--python", "-w", "--workspace", "--prefix", "--cache", "--userconfig", "--registry":
		return true
	}
	return false
}

func markRisk(out *CommandAnalysis) {
	for _, arg := range out.Raw {
		switch arg {
		case "-g", "--global":
			out.Global = true
		}
	}
	if hasRequirementsFileFlag(out) {
		out.RequirementsFile = true
		out.RequirementFiles = requirementFiles(out.Raw)
	}
	if hasConstraintFileFlag(out) {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "constraint_file_unsupported", Severity: "block", Message: "constraint files change dependency resolution and are not supported yet"})
	}
	if hasNPMScopedInstallFlag(out) {
		out.ScopedInstall = true
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "npm_scope_flag_unsupported", Severity: "block", Message: "npm workspace or prefix install changes the audited install scope and is not supported yet"})
	}
	if hasAlternatePackageSourceFlag(out) {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "alternate_package_source", Severity: "block", Message: "alternate registries or indexes change the audited package source and are not supported yet"})
	}
	if hasEditableInstallFlag(out) {
		out.LocalPath = true
	}
	for _, spec := range out.PackageSpecs {
		if spec.DirectURL {
			out.DirectURL = true
		}
		if spec.VCS {
			out.VCSDependency = true
		}
		if spec.LocalPath {
			out.LocalPath = true
		}
		if spec.Range {
			out.VersionRange = true
		}
	}
	if hasNPMAliasSpec(out) {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "npm_alias_dependency", Severity: "block", Message: "npm alias specs change the audited package identity and are not supported yet"})
	}
	if out.OneShot {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "one_shot_exec", Severity: "prompt", Message: "one-shot remote execution requires review"})
		if len(out.PackageSpecs) == 0 {
			out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "one_shot_package_unknown", Severity: "block", Message: "one-shot execution package identity could not be audited"})
		}
	}
	if out.Global {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "global_install", Severity: "prompt", Message: "global installs require review"})
	}
	if unsupportedMultiPackageBatch(out) {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "multi_package_batch", Severity: "block", Message: "multi-package installs are not fully gated by this MVP; run one package at a time"})
	}
	if unsupportedMultiDownloader(out) {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "multi_downloader_url", Severity: "block", Message: "multi-URL downloader commands are not supported; download one URL at a time"})
	}
	if out.DirectURL {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "direct_url_dependency", Severity: sourceSpecSeverity(out), Message: "direct URL artifacts require review"})
	}
	if hasPlaintextDownloaderURL(*out) {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "plaintext_http_download", Severity: "block", Message: "plain HTTP downloader URLs are blocked"})
	}
	if out.VCSDependency {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "vcs_dependency", Severity: sourceSpecSeverity(out), Message: "VCS dependencies require review"})
	}
	if out.LocalPath {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "local_path_dependency", Severity: "block", Message: "local path or editable installs can execute unchecked build hooks and are not supported yet"})
	}
	if out.VersionRange {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "version_range_dependency", Severity: "block", Message: "version ranges need a range-aware resolver before safe exact pinning and are not supported yet"})
	}
	if hasSourceBuildSignal(out.Raw) {
		out.SourceBuild = true
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "source_build", Severity: "prompt", Message: "source builds require review"})
	}
	if out.RemoteShell {
		out.RiskFlags = append(out.RiskFlags, RiskFlag{Code: "remote_shell", Severity: "block", Message: "downloader piped to shell is blocked"})
	}
}

func hasPlaintextDownloaderURL(out CommandAnalysis) bool {
	if out.Manager != "curl" && out.Manager != "wget" {
		return false
	}
	for _, spec := range out.PackageSpecs {
		if strings.HasPrefix(strings.ToLower(spec.Raw), "http://") {
			return true
		}
	}
	return false
}

func sourceSpecSeverity(out *CommandAnalysis) string {
	switch out.Manager {
	case "npm", "npx", "pip", "pip3", "uv", "pipx":
		return "block"
	default:
		return "prompt"
	}
}

func hasEditableInstallFlag(out *CommandAnalysis) bool {
	if out.Manager != "pip" && out.Manager != "pip3" && out.Manager != "uv" {
		return false
	}
	for _, arg := range out.Raw {
		if arg == "-e" || arg == "--editable" {
			return true
		}
	}
	return false
}

func hasAlternatePackageSourceFlag(out *CommandAnalysis) bool {
	for _, arg := range out.Raw {
		switch out.Manager {
		case "npm", "npx":
			if arg == "--registry" || arg == "--userconfig" || strings.HasPrefix(arg, "--registry=") || strings.HasPrefix(arg, "--userconfig=") {
				return true
			}
		case "pip", "pip3", "uv", "uvx", "pipx":
			if arg == "-i" || arg == "--index-url" || arg == "--extra-index-url" || arg == "-f" || arg == "--find-links" || arg == "--no-index" || arg == "--trusted-host" || strings.HasPrefix(arg, "--index-url=") || strings.HasPrefix(arg, "--extra-index-url=") || strings.HasPrefix(arg, "--find-links=") || strings.HasPrefix(arg, "--trusted-host=") {
				return true
			}
		}
	}
	return false
}

func hasNPMScopedInstallFlag(out *CommandAnalysis) bool {
	if out.Manager != "npm" || out.Action != "install" {
		return false
	}
	for _, arg := range out.Raw {
		switch {
		case arg == "-w", arg == "--workspace", arg == "--workspaces", arg == "--prefix":
			return true
		case strings.HasPrefix(arg, "--workspace="), strings.HasPrefix(arg, "--prefix="):
			return true
		}
	}
	return false
}

func hasNPMAliasSpec(out *CommandAnalysis) bool {
	if out.Manager != "npm" && out.Manager != "npx" {
		return false
	}
	for _, spec := range out.PackageSpecs {
		lower := strings.ToLower(spec.Raw)
		if strings.Contains(lower, "@npm:") || strings.HasPrefix(lower, "npm:") {
			return true
		}
	}
	return false
}

func requirementFiles(args []string) []string {
	var files []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-r" || arg == "--requirement":
			if i+1 < len(args) {
				files = append(files, args[i+1])
				i++
			}
		case strings.HasPrefix(arg, "-r") && len(arg) > 2:
			files = append(files, arg[2:])
		case strings.HasPrefix(arg, "--requirement="):
			files = append(files, strings.TrimPrefix(arg, "--requirement="))
		}
	}
	return files
}

func hasRequirementsFileFlag(out *CommandAnalysis) bool {
	if out.Manager != "pip" && out.Manager != "pip3" && out.Manager != "uv" {
		return false
	}
	if out.Manager == "uv" && !strings.HasPrefix(out.Action, "pip install") {
		return false
	}
	for _, arg := range out.Raw {
		if arg == "-r" || arg == "--requirement" || strings.HasPrefix(arg, "-r") && len(arg) > 2 || strings.HasPrefix(arg, "--requirement=") {
			return true
		}
	}
	return false
}

func hasConstraintFileFlag(out *CommandAnalysis) bool {
	if out.Manager != "pip" && out.Manager != "pip3" && out.Manager != "uv" {
		return false
	}
	if out.Manager == "uv" && !strings.HasPrefix(out.Action, "pip install") {
		return false
	}
	for _, arg := range out.Raw {
		if arg == "-c" || arg == "--constraint" || strings.HasPrefix(arg, "-c") && len(arg) > 2 || strings.HasPrefix(arg, "--constraint=") {
			return true
		}
	}
	return false
}

func unsupportedMultiPackageBatch(out *CommandAnalysis) bool {
	if len(out.PackageSpecs) <= 1 {
		return false
	}
	if out.OneShot {
		return true
	}
	switch out.Manager {
	case "npm":
		return out.Action == "install"
	case "pip", "pip3":
		return out.Action == "install"
	case "uv":
		return out.Action == "add" || strings.HasPrefix(out.Action, "pip install")
	}
	return false
}

func unsupportedMultiDownloader(out *CommandAnalysis) bool {
	return (out.Manager == "curl" || out.Manager == "wget") && len(out.PackageSpecs) > 1
}

func hasSourceBuildSignal(args []string) bool {
	joined := strings.Join(args, " ")
	return strings.Contains(joined, "--no-binary=:all:") ||
		strings.Contains(joined, "--no-binary :all:") ||
		strings.Contains(joined, ".tar.gz") ||
		strings.Contains(joined, ".zip")
}

func hasPipeToShell(args []string) bool {
	joined := strings.Join(args, " ")
	matched, _ := regexp.MatchString(`\|\s*(sh|bash|zsh)\b`, joined)
	return matched
}
