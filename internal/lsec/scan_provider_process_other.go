//go:build !unix

package lsec

import (
	"os"
	"os/exec"
)

func configureProviderProcess(cmd *exec.Cmd) {}

func killProviderProcessTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	return cmd.Process.Kill()
}
