package lsec

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func Doctor(paths Paths, stdout io.Writer) error {
	fmt.Fprintln(stdout, "local-sec doctor")
	checkPathOrder(paths, stdout)
	checkShims(paths, stdout)
	checkTools(stdout)
	return nil
}

func checkPathOrder(paths Paths, stdout io.Writer) {
	pathDirs := filepath.SplitList(os.Getenv("PATH"))
	if len(pathDirs) > 0 && filepath.Clean(pathDirs[0]) == filepath.Clean(paths.Bin) {
		fmt.Fprintln(stdout, "ok: shim directory is first in PATH")
		return
	}
	fmt.Fprintf(stdout, "warn: %s is not first in PATH\n", paths.Bin)
}

func checkShims(paths Paths, stdout io.Writer) {
	for _, command := range phaseOneShimCommands {
		target := filepath.Join(paths.Bin, command)
		info, err := os.Stat(target)
		if err != nil {
			fmt.Fprintf(stdout, "missing shim: %s\n", command)
			continue
		}
		if info.Mode()&0o111 == 0 {
			fmt.Fprintf(stdout, "warn: shim is not executable: %s\n", target)
			continue
		}
		if !shimInvokesGuard(target, command) {
			fmt.Fprintf(stdout, "warn: shim does not invoke local-sec guard: %s\n", command)
			continue
		}
		fmt.Fprintf(stdout, "ok: shim %s\n", command)
	}
}

func shimInvokesGuard(path, command string) bool {
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(body)
	return strings.Contains(text, "LSEC_SHIM_DIR=") &&
		strings.Contains(text, " guard "+command+" ") &&
		strings.Contains(text, "\"$@\"")
}

func checkTools(stdout io.Writer) {
	required := []string{"sqlite3"}
	for _, tool := range required {
		if _, err := exec.LookPath(tool); err != nil {
			fmt.Fprintf(stdout, "missing required local tool: %s\n", tool)
		} else {
			fmt.Fprintf(stdout, "ok: %s\n", tool)
		}
	}
	checkOptionalToolCapabilities(stdout, "current scan/advisory tools:", []toolCapability{
		{name: "osv-scanner", state: "active scan/advisory", role: "npm lockfile advisory scan", next: "install only if you want npm lockfile provider coverage"},
		{name: "pip-audit", state: "active scan/advisory", role: "pinned Python requirements advisory scan", next: "install only if you want pinned requirements coverage"},
		{name: "grype", state: "active scan/advisory", role: "accepted CycloneDX SBOM advisory scan", next: "install only if you want SBOM advisory coverage"},
		{name: "syft", state: "active scan/inventory", role: "project SBOM inventory via CycloneDX JSON", next: "install only if you want Syft inventory enrichment"},
		{name: "cargo", state: "active scan/audit", role: "cargo vet audit when plugin installed", next: "install cargo-vet plugin only if you want Rust audit evidence"},
		{name: "bumblebee", state: "active scan/endpoint", role: "endpoint tool detection probe", next: "install only if you want endpoint correlation hooks"},
	})
	checkOptionalToolCapabilities(stdout, "advisory amplifiers:", []toolCapability{
		{name: "socket", state: "preflight amplifier", role: "optional package preflight enrichment", next: "authenticate only if you want Socket enrichment"},
		{name: "snyk", state: "preflight amplifier", role: "optional npm preflight enrichment", next: "authenticate only if you want Snyk enrichment"},
	})
	checkOptionalToolCapabilities(stdout, "runtime/local evidence tools:", []toolCapability{
		{name: "docker", state: "fixture/local evidence", role: "docker-fixture sandbox runner", next: "use only for controlled fixture runs"},
		{name: "ollama", state: "fixture/local evidence", role: "local review helper", next: "treat output as advisory evidence"},
	})
	if runtime.GOOS == "darwin" {
		checkMacOSEndpointApps(stdout, "/Applications")
	}
	fmt.Fprintf(stdout, "protected commands: %s\n", strings.Join(phaseOneShimCommands, ", "))
}

type toolCapability struct {
	name  string
	state string
	role  string
	next  string
}

func checkOptionalToolCapabilities(stdout io.Writer, heading string, tools []toolCapability) {
	fmt.Fprintln(stdout, heading)
	for _, tool := range tools {
		if _, err := exec.LookPath(tool.name); err != nil {
			fmt.Fprintf(stdout, "optional missing: %s [%s] role: %s; next: %s\n", tool.name, tool.state, tool.role, tool.next)
		} else {
			fmt.Fprintf(stdout, "ok: %s [%s] role: %s; next: %s\n", tool.name, tool.state, tool.role, tool.next)
		}
	}
}

func checkMacOSEndpointApps(stdout io.Writer, appRoot string) {
	fmt.Fprintln(stdout, "macOS endpoint apps:")
	for _, app := range []string{"BlockBlock.app", "LuLu.app", "KnockKnock.app"} {
		if _, err := os.Stat(filepath.Join(appRoot, app)); err != nil {
			fmt.Fprintf(stdout, "optional missing: %s [detected-only] role: endpoint context app; next: no local-sec action yet\n", app)
			continue
		}
		fmt.Fprintf(stdout, "ok: %s [detected-only] role: endpoint context app; next: no local-sec action yet\n", app)
	}
}
