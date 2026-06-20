package lsec

import (
	"fmt"
	"io"
)

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func PrintVersion(w io.Writer) {
	fmt.Fprintf(w, "lsec %s commit=%s date=%s\n", Version, Commit, Date)
}
