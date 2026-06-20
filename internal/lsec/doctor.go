package lsec

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	advisory := []string{"socket", "snyk", "osv-scanner", "pip-audit", "syft", "grype", "bumblebee", "ollama", "docker"}
	for _, tool := range required {
		if _, err := exec.LookPath(tool); err != nil {
			fmt.Fprintf(stdout, "missing required local tool: %s\n", tool)
		} else {
			fmt.Fprintf(stdout, "ok: %s\n", tool)
		}
	}
	for _, tool := range advisory {
		if _, err := exec.LookPath(tool); err != nil {
			fmt.Fprintf(stdout, "optional missing: %s\n", tool)
		} else {
			fmt.Fprintf(stdout, "ok: %s\n", tool)
		}
	}
	fmt.Fprintf(stdout, "protected commands: %s\n", strings.Join(phaseOneShimCommands, ", "))
}
