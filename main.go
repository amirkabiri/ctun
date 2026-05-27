package main

import (
	"ctun/cmd/dump"
	"ctun/cmd/iface"
	"ctun/cmd/ping"
	"ctun/cmd/run"
	"ctun/cmd/secret"
	"ctun/cmd/version"
	"ctun/internal/flog"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "ctun",
	Short:   "KCP transport over raw TCP packet.",
	Long:    `ctun is a bidirectional packet-level proxy using KCP and raw socket transport with encryption.`,
	Version: version.Version,
}

func main() {
	rootCmd.AddCommand(run.Cmd)
	rootCmd.AddCommand(dump.Cmd)
	rootCmd.AddCommand(ping.Cmd)
	rootCmd.AddCommand(secret.Cmd)
	rootCmd.AddCommand(iface.Cmd)
	rootCmd.AddCommand(version.Cmd)

	if err := rootCmd.Execute(); err != nil {
		flog.Errorf("%v", err)
		os.Exit(1)
	}
}
