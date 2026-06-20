package main

import (
	"fmt"
	"os"

	"local-sec/internal/lsec"
)

func main() {
	if err := lsec.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "lsec:", err)
		os.Exit(1)
	}
}
