package lsec

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var phaseOneShimCommands = []string{
	"npm", "npx", "pip", "pip3", "python", "python3", "py",
	"python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14",
	"uv", "uvx", "pipx", "curl", "wget",
}

func InstallShims(paths Paths, stdout io.Writer) error {
	if err := paths.Ensure(); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	for _, command := range phaseOneShimCommands {
		target := filepath.Join(paths.Bin, command)
		body := fmt.Sprintf("#!/bin/sh\nexport LSEC_SHIM_DIR=%q\nexec %q guard %s \"$@\"\n", paths.Bin, exe, command)
		if err := os.WriteFile(target, []byte(body), 0o700); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "installed shim %s\n", target)
	}
	fmt.Fprintf(stdout, "add %s before package-manager directories in PATH\n", paths.Bin)
	return nil
}
