package main

import (
	"fmt"

	"github.com/quocln/routewise/internal/config"
	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running daemon",
	Long: `Stop the running VPN routing daemon by sending SIGTERM.

The daemon will:
1. Stop VPN monitoring
2. Remove all managed routes
3. Clean up and exit

Examples:
  sudo routewise stop`,
	RunE: runStop,
}

func init() {
	rootCmd.AddCommand(stopCmd)
}

func runStop(cmd *cobra.Command, args []string) error {
	// Load config to get PID file location
	cfg, err := loadConfig()
	if err != nil {
		// Use default PID file location
		cfg = config.DefaultConfig()
	}

	outcome, pid, err := stopDaemon(cfg.Daemon.PidFile)
	if err != nil {
		return err
	}
	switch outcome {
	case daemonNotRunning:
		fmt.Println("Daemon not running")
		return nil
	case daemonStalePID:
		fmt.Println("Stale PID file removed (process was not routewise)")
		return nil
	}

	fmt.Printf("Sent SIGTERM to process %d\n", pid)

	// Wait briefly for process to exit, then check if it actually stopped
	if waitForDaemonExit(cfg.Daemon.PidFile, 1) {
		fmt.Println("Daemon stopped")
	} else {
		fmt.Println("Daemon is still shutting down...")
	}

	return nil
}
