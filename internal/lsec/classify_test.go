package lsec

import (
	"strings"
	"testing"
)

func TestClassifyPythonModulePipInstall(t *testing.T) {
	got := Classify([]string{"python3", "-m", "pip", "install", "dspy"})

	if got.Manager != "pip" {
		t.Fatalf("manager = %q, want pip", got.Manager)
	}
	if !got.PythonModulePip {
		t.Fatal("expected python -m pip to be marked")
	}
	if got.Action != "install" {
		t.Fatalf("action = %q, want install", got.Action)
	}
	if len(got.PackageSpecs) != 1 || got.PackageSpecs[0].Name != "dspy" {
		t.Fatalf("package specs = %#v, want dspy", got.PackageSpecs)
	}
}

func TestClassifyPythonModulePipWithInterpreterFlags(t *testing.T) {
	got := Classify([]string{"python3", "-I", "-m", "pip", "install", "dspy"})

	if got.Manager != "pip" {
		t.Fatalf("manager = %q, want pip", got.Manager)
	}
	if !got.PythonModulePip {
		t.Fatal("expected python -m pip to be marked")
	}
	if got.Action != "install" {
		t.Fatalf("action = %q, want install", got.Action)
	}
	if len(got.PackageSpecs) != 1 || got.PackageSpecs[0].Name != "dspy" {
		t.Fatalf("package specs = %#v, want dspy", got.PackageSpecs)
	}
}

func TestClassifyVersionedPythonModulePip(t *testing.T) {
	got := Classify([]string{"python3.14", "-m", "pip", "install", "dspy"})

	if got.Manager != "pip" {
		t.Fatalf("manager = %q, want pip", got.Manager)
	}
	if !got.PythonModulePip {
		t.Fatal("expected versioned python -m pip to be marked")
	}
	if len(got.PackageSpecs) != 1 || got.PackageSpecs[0].Name != "dspy" {
		t.Fatalf("package specs = %#v, want dspy", got.PackageSpecs)
	}
}

func TestClassifyPythonScriptWithPipArgsIsNotModulePip(t *testing.T) {
	got := Classify([]string{"python3", "script.py", "-m", "pip", "install", "dspy"})

	if got.Manager != "python3" {
		t.Fatalf("manager = %q, want python3", got.Manager)
	}
	if got.PythonModulePip {
		t.Fatal("did not expect script arguments to be classified as python -m pip")
	}
}

func TestClassifyOneShotCommands(t *testing.T) {
	tests := [][]string{
		{"npx", "create-vite@latest"},
		{"uvx", "ruff"},
		{"pipx", "run", "black"},
		{"npm", "exec", "typescript"},
		{"npm", "init", "vite@latest"},
	}

	for _, tt := range tests {
		got := Classify(tt)
		if !got.OneShot {
			t.Fatalf("%v was not classified as one-shot: %#v", tt, got)
		}
	}
}

func TestClassifyOneShotPackageFlagsUsePackageValue(t *testing.T) {
	tests := []struct {
		args     []string
		wantName string
	}{
		{args: []string{"npx", "--package=create-vite", "vite"}, wantName: "create-vite"},
		{args: []string{"npx", "--package", "create-vite", "vite"}, wantName: "create-vite"},
		{args: []string{"npx", "-p", "create-vite", "vite"}, wantName: "create-vite"},
		{args: []string{"npm", "exec", "--package=create-vite", "--", "vite"}, wantName: "create-vite"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			got := Classify(tt.args)

			if !got.OneShot {
				t.Fatalf("analysis = %#v, want one-shot command", got)
			}
			if len(got.PackageSpecs) != 1 {
				t.Fatalf("package specs = %#v, want exactly one package from package flag", got.PackageSpecs)
			}
			if got.PackageSpecs[0].Name != tt.wantName {
				t.Fatalf("package spec = %#v, want %q", got.PackageSpecs[0], tt.wantName)
			}
		})
	}
}

func TestClassifyOneShotWithoutAuditablePackageBlocks(t *testing.T) {
	tests := [][]string{
		{"npx", "--", "create-vite"},
		{"npm", "exec", "--", "create-vite"},
		{"uvx", "--", "ruff"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt, " "), func(t *testing.T) {
			got := Classify(tt)

			if !got.OneShot {
				t.Fatalf("analysis = %#v, want one-shot command", got)
			}
			if len(got.PackageSpecs) != 0 {
				t.Fatalf("package specs = %#v, want none for unauditable separator form", got.PackageSpecs)
			}
			if !hasRiskFlag(got.RiskFlags, "one_shot_package_unknown", "block") {
				t.Fatalf("expected blocking one_shot_package_unknown risk flag: %#v", got.RiskFlags)
			}
		})
	}
}

func TestClassifyOneShotMultiplePackagesBlocks(t *testing.T) {
	got := Classify([]string{"npx", "--package", "left-pad", "--package", "is-odd", "node"})

	if len(got.PackageSpecs) != 2 {
		t.Fatalf("package specs = %#v, want two package flag values", got.PackageSpecs)
	}
	if !hasRiskFlag(got.RiskFlags, "multi_package_batch", "block") {
		t.Fatalf("expected blocking multi_package_batch risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyUVXFromUsesPackageValue(t *testing.T) {
	tests := []struct {
		args     []string
		wantName string
	}{
		{args: []string{"uvx", "--from", "ruff", "ruff-lsp"}, wantName: "ruff"},
		{args: []string{"uvx", "--from=ruff", "ruff-lsp"}, wantName: "ruff"},
		{args: []string{"uv", "tool", "run", "--from", "ruff", "ruff-lsp"}, wantName: "ruff"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			got := Classify(tt.args)

			if !got.OneShot {
				t.Fatalf("analysis = %#v, want one-shot command", got)
			}
			if len(got.PackageSpecs) != 1 {
				t.Fatalf("package specs = %#v, want exactly one --from package", got.PackageSpecs)
			}
			if got.PackageSpecs[0].Name != tt.wantName {
				t.Fatalf("package spec = %#v, want %q", got.PackageSpecs[0], tt.wantName)
			}
		})
	}
}

func TestClassifyPipxRunSpecUsesSpecPackage(t *testing.T) {
	tests := []struct {
		args     []string
		wantName string
	}{
		{args: []string{"pipx", "run", "--spec", "rich", "rich-cli"}, wantName: "rich"},
		{args: []string{"pipx", "run", "--spec=rich", "rich-cli"}, wantName: "rich"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			got := Classify(tt.args)

			if !got.OneShot {
				t.Fatalf("analysis = %#v, want one-shot pipx run", got)
			}
			if len(got.PackageSpecs) != 1 || got.PackageSpecs[0].Name != tt.wantName {
				t.Fatalf("package specs = %#v, want %s from --spec", got.PackageSpecs, tt.wantName)
			}
		})
	}
}

func TestClassifyPipxRunSpecVCSBlocks(t *testing.T) {
	got := Classify([]string{"pipx", "run", "--spec", "git+https://github.com/example/pkg.git", "tool"})

	if !hasRiskFlag(got.RiskFlags, "vcs_dependency", "block") {
		t.Fatalf("expected blocking vcs_dependency risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyNPMDistTagIsNotPinnedVersion(t *testing.T) {
	tests := [][]string{
		{"npx", "create-vite@latest"},
		{"npm", "install", "left-pad@next"},
		{"npm", "init", "vite@latest"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt, " "), func(t *testing.T) {
			got := Classify(tt)

			if len(got.PackageSpecs) != 1 {
				t.Fatalf("package specs = %#v, want one", got.PackageSpecs)
			}
			if got.PackageSpecs[0].Version != "" {
				t.Fatalf("version = %q, want empty so resolver can select a mature exact version", got.PackageSpecs[0].Version)
			}
		})
	}
}

func TestClassifyNPMInitMapsInitializerToCreatePackage(t *testing.T) {
	tests := []struct {
		args        []string
		wantName    string
		wantVersion string
	}{
		{args: []string{"npm", "init", "vite@latest"}, wantName: "create-vite"},
		{args: []string{"npm", "create", "vite@1.2.3"}, wantName: "create-vite", wantVersion: "1.2.3"},
		{args: []string{"npm", "innit", "@usr/foo@2.0.0"}, wantName: "@usr/create-foo", wantVersion: "2.0.0"},
		{args: []string{"npm", "init", "@usr"}, wantName: "@usr/create"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			got := Classify(tt.args)

			if !got.OneShot || got.Action != "init" {
				t.Fatalf("analysis = %#v, want one-shot npm init", got)
			}
			if len(got.PackageSpecs) != 1 {
				t.Fatalf("package specs = %#v, want one", got.PackageSpecs)
			}
			if got.PackageSpecs[0].Name != tt.wantName || got.PackageSpecs[0].Version != tt.wantVersion {
				t.Fatalf("package spec = %#v, want name %q version %q", got.PackageSpecs[0], tt.wantName, tt.wantVersion)
			}
		})
	}
}

func TestClassifyNPMRangeIsNotPinnedVersion(t *testing.T) {
	got := Classify([]string{"npm", "install", "left-pad@^1.3.0"})

	if len(got.PackageSpecs) != 1 {
		t.Fatalf("package specs = %#v, want one", got.PackageSpecs)
	}
	if got.PackageSpecs[0].Version != "" {
		t.Fatalf("version = %q, want empty for non-exact range", got.PackageSpecs[0].Version)
	}
	if !hasRiskFlag(got.RiskFlags, "version_range_dependency", "block") {
		t.Fatalf("expected blocking version_range_dependency risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyPipRangeBlocks(t *testing.T) {
	tests := [][]string{
		{"pip", "install", "requests>=2"},
		{"python3", "-m", "pip", "install", "httpx~=0.27"},
		{"uv", "pip", "install", "pydantic<3"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt, " "), func(t *testing.T) {
			got := Classify(tt)

			if len(got.PackageSpecs) != 1 {
				t.Fatalf("package specs = %#v, want one", got.PackageSpecs)
			}
			if got.PackageSpecs[0].Name == got.PackageSpecs[0].Raw {
				t.Fatalf("package spec = %#v, want parsed package name separate from range", got.PackageSpecs[0])
			}
			if !hasRiskFlag(got.RiskFlags, "version_range_dependency", "block") {
				t.Fatalf("expected blocking version_range_dependency risk flag: %#v", got.RiskFlags)
			}
		})
	}
}

func TestClassifyCurlPipeToShell(t *testing.T) {
	got := Classify([]string{"curl", "-fsSL", "https://example.invalid/install.sh", "|", "sh"})

	if !got.RemoteShell {
		t.Fatalf("expected remote shell classification: %#v", got)
	}
	if got.Manager != "curl" {
		t.Fatalf("manager = %q, want curl", got.Manager)
	}
}

func TestClassifyBlocksPlainHTTPDownloaderURL(t *testing.T) {
	got := Classify([]string{"curl", "http://example.invalid/install.sh"})

	if !hasRiskFlag(got.RiskFlags, "plaintext_http_download", "block") {
		t.Fatalf("expected blocking plaintext_http_download risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyDownloaderIgnoresOutputFlagValue(t *testing.T) {
	got := Classify([]string{"curl", "-fsSL", "-o", "install.sh", "https://example.invalid/install.sh"})

	if len(got.PackageSpecs) != 1 || got.PackageSpecs[0].Raw != "https://example.invalid/install.sh" {
		t.Fatalf("package specs = %#v, want only downloader URL", got.PackageSpecs)
	}
}

func TestClassifyMultipleDownloaderURLsBlocks(t *testing.T) {
	got := Classify([]string{"curl", "https://example.invalid/a.sh", "https://example.invalid/b.sh"})

	if !hasRiskFlag(got.RiskFlags, "multi_downloader_url", "block") {
		t.Fatalf("expected blocking multi_downloader_url risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyPipRequirementsFileDetectsFile(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "split short flag", args: []string{"python3", "-m", "pip", "install", "-r", "requirements.txt"}, want: "requirements.txt"},
		{name: "compact short flag", args: []string{"pip", "install", "-rrequirements.txt"}, want: "requirements.txt"},
		{name: "equals long flag", args: []string{"pip", "install", "--requirement=requirements.txt"}, want: "requirements.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.args)

			if !got.RequirementsFile {
				t.Fatalf("expected requirements file flag: %#v", got)
			}
			if len(got.RequirementFiles) != 1 || got.RequirementFiles[0] != tt.want {
				t.Fatalf("requirement files = %#v, want %s", got.RequirementFiles, tt.want)
			}
			if hasRiskFlag(got.RiskFlags, "requirements_file", "block") {
				t.Fatalf("requirements files should be parsed before policy blocks: %#v", got.RiskFlags)
			}
		})
	}
}

func TestClassifyPipConstraintFileBlocks(t *testing.T) {
	tests := [][]string{
		{"pip", "install", "-c", "constraints.txt", "requests"},
		{"pip", "install", "-cconstraints.txt", "requests"},
		{"python3", "-m", "pip", "install", "--constraint=constraints.txt", "requests"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt, " "), func(t *testing.T) {
			got := Classify(tt)

			if !hasRiskFlag(got.RiskFlags, "constraint_file_unsupported", "block") {
				t.Fatalf("expected blocking constraint_file_unsupported risk flag: %#v", got.RiskFlags)
			}
		})
	}
}

func TestClassifyMultiPackageInstallBlocks(t *testing.T) {
	got := Classify([]string{"npm", "install", "lodash", "left-pad"})

	if !hasRiskFlag(got.RiskFlags, "multi_package_batch", "block") {
		t.Fatalf("expected blocking multi_package_batch risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyBareNPMInstallRequiresLockfileAudit(t *testing.T) {
	got := Classify([]string{"npm", "install"})

	if !got.LockfileInstall {
		t.Fatalf("expected lockfile install classification: %#v", got)
	}
	if got.LockfilePath != "package-lock.json" {
		t.Fatalf("lockfile path = %q, want package-lock.json", got.LockfilePath)
	}
}

func TestClassifyNPMWorkspaceInstallBlocksInsteadOfAuditingWorkspaceName(t *testing.T) {
	got := Classify([]string{"npm", "install", "-w", "app"})

	if len(got.PackageSpecs) != 0 {
		t.Fatalf("package specs = %#v, want none; workspace name must not be audited as package", got.PackageSpecs)
	}
	if !hasRiskFlag(got.RiskFlags, "npm_scope_flag_unsupported", "block") {
		t.Fatalf("expected blocking npm_scope_flag_unsupported risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyNPMPrefixInstallBlocksInsteadOfAuditingPath(t *testing.T) {
	got := Classify([]string{"npm", "install", "--prefix", "/tmp/app"})

	if len(got.PackageSpecs) != 0 {
		t.Fatalf("package specs = %#v, want none; prefix path must not be audited as package", got.PackageSpecs)
	}
	if !hasRiskFlag(got.RiskFlags, "npm_scope_flag_unsupported", "block") {
		t.Fatalf("expected blocking npm_scope_flag_unsupported risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyPipAlternateIndexBlocks(t *testing.T) {
	tests := [][]string{
		{"pip", "install", "--index-url", "https://example.invalid/simple", "requests"},
		{"pip", "install", "--extra-index-url=https://example.invalid/simple", "requests"},
		{"python3", "-m", "pip", "install", "--find-links", "https://example.invalid/wheels", "requests"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt, " "), func(t *testing.T) {
			got := Classify(tt)

			if !hasRiskFlag(got.RiskFlags, "alternate_package_source", "block") {
				t.Fatalf("expected blocking alternate_package_source risk flag: %#v", got.RiskFlags)
			}
		})
	}
}

func TestClassifyNPMAlternateRegistryBlocks(t *testing.T) {
	tests := [][]string{
		{"npm", "install", "--registry", "https://registry.example.invalid", "left-pad"},
		{"npm", "install", "--registry=https://registry.example.invalid", "left-pad"},
		{"npx", "--registry", "https://registry.example.invalid", "create-vite"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt, " "), func(t *testing.T) {
			got := Classify(tt)

			if !hasRiskFlag(got.RiskFlags, "alternate_package_source", "block") {
				t.Fatalf("expected blocking alternate_package_source risk flag: %#v", got.RiskFlags)
			}
		})
	}
}

func TestClassifyPipVCSInstallBlocks(t *testing.T) {
	got := Classify([]string{"pip", "install", "git+https://github.com/example/pkg.git"})

	if !got.VCSDependency {
		t.Fatalf("expected VCS dependency classification: %#v", got)
	}
	if !hasRiskFlag(got.RiskFlags, "vcs_dependency", "block") {
		t.Fatalf("expected blocking vcs_dependency risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyNPMVCSShorthandsBlock(t *testing.T) {
	tests := [][]string{
		{"npm", "install", "github:user/repo"},
		{"npm", "install", "gitlab:user/repo"},
		{"npm", "install", "git://github.com/user/repo.git"},
		{"npm", "install", "git@github.com:user/repo.git"},
		{"npm", "install", "user/repo"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt, " "), func(t *testing.T) {
			got := Classify(tt)

			if !got.VCSDependency {
				t.Fatalf("expected VCS dependency classification: %#v", got)
			}
			if !hasRiskFlag(got.RiskFlags, "vcs_dependency", "block") {
				t.Fatalf("expected blocking vcs_dependency risk flag: %#v", got.RiskFlags)
			}
		})
	}
}

func TestClassifyNpxSourceSpecsBlock(t *testing.T) {
	tests := [][]string{
		{"npx", "git+https://github.com/example/pkg.git"},
		{"npx", "https://example.invalid/pkg.tgz"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt, " "), func(t *testing.T) {
			got := Classify(tt)

			if !hasRiskFlag(got.RiskFlags, "vcs_dependency", "block") && !hasRiskFlag(got.RiskFlags, "direct_url_dependency", "block") {
				t.Fatalf("expected blocking source risk flag: %#v", got.RiskFlags)
			}
		})
	}
}

func TestClassifyNPMAliasSpecBlocks(t *testing.T) {
	got := Classify([]string{"npm", "install", "alias-name@npm:real-package@1.2.3"})

	if !hasRiskFlag(got.RiskFlags, "npm_alias_dependency", "block") {
		t.Fatalf("expected blocking npm_alias_dependency risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyPipDirectURLInstallBlocks(t *testing.T) {
	got := Classify([]string{"python3", "-m", "pip", "install", "https://example.invalid/pkg.whl"})

	if !got.DirectURL {
		t.Fatalf("expected direct URL classification: %#v", got)
	}
	if !hasRiskFlag(got.RiskFlags, "direct_url_dependency", "block") {
		t.Fatalf("expected blocking direct_url_dependency risk flag: %#v", got.RiskFlags)
	}
}

func TestClassifyLocalPathInstallsBlock(t *testing.T) {
	tests := [][]string{
		{"pip", "install", "."},
		{"pip", "install", "-e", "."},
		{"python3", "-m", "pip", "install", "file:///tmp/pkg"},
		{"npm", "install", "../pkg"},
		{"npm", "install", "file:../pkg"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt, " "), func(t *testing.T) {
			got := Classify(tt)

			if !hasRiskFlag(got.RiskFlags, "local_path_dependency", "block") {
				t.Fatalf("expected blocking local_path_dependency risk flag: %#v", got.RiskFlags)
			}
		})
	}
}

func TestClassifyBareLocalArchivesBlock(t *testing.T) {
	tests := [][]string{
		{"pip", "install", "pkg.zip"},
		{"pip", "install", "pkg.tar.bz2"},
		{"pip", "install", "pkg.tar.xz"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt, " "), func(t *testing.T) {
			got := Classify(tt)

			if !hasRiskFlag(got.RiskFlags, "local_path_dependency", "block") {
				t.Fatalf("expected blocking local_path_dependency risk flag: %#v", got.RiskFlags)
			}
		})
	}
}

func hasRiskFlag(flags []RiskFlag, code, severity string) bool {
	for _, flag := range flags {
		if flag.Code == code && flag.Severity == severity {
			return true
		}
	}
	return false
}
