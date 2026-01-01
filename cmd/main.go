// Package main is the entry point for secscanner CLI.
package main

import (
	"os"

	"github.com/security-cli/secscanner/cmd/cli"
)

// Version information (set via ldflags at build time)
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	cli.SetVersionInfo(version, commit, buildDate)

	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
