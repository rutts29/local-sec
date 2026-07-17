//go:build unix

package lsec

import (
	"os"
	"syscall"
)

func providerInputLinkRejection(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "link_count_unavailable"
	}
	if stat.Nlink != 1 {
		return "link_count"
	}
	return ""
}
