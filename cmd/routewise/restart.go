package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/quocln/routewise/internal/config"
	"github.com/spf13/cobra"
)

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the daemon",
	Long: `Restart the VPN routing daemon.

If managed by launchd, uses launchctl kickstart.
Otherwise stops and starts the daemon directly.

Examples:
  sudo routewise restart`,
	RunE: runRestart,
}

func init() {
	rootCmd.AddCommand(restartCmd)
}

// manualStartArgs are the arguments a manual restart starts the daemon with.
// It keeps the --config the user ran restart with, or the new daemon would
// read a different config than the one it replaces.
func manualStartArgs() []string {
	args := []string{"start"}
	if cfgFile != "" {
		args = append(args, "--config", cfgFile)
	}
	return args
}

func runRestart(cmd *cobra.Command, args []string) error {
	// Check if managed by the service manager (launchd on macOS)
	if service.Managed() {
		fmt.Printf("Restarting via %s...\n", service.ManagerName())
		if err := service.Restart(os.Stdout, os.Stderr); err != nil {
			return err
		}
		fmt.Printf("Daemon restarted via %s\n", service.ManagerName())
		return nil
	}

	// Manual restart
	cfg, err := loadConfig()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Stop if running. A failure to signal is not fatal here: the start below
	// reports a daemon that is still holding the PID file.
	if outcome, pid, _ := stopDaemon(cfg.Daemon.PidFile); outcome == daemonSignalled {
		fmt.Printf("Stopping daemon (PID %d)...\n", pid)
		// Wait for stop (max 5s)
		waitForDaemonExit(cfg.Daemon.PidFile, 10)
	}

	// Start daemon
	fmt.Println("Starting daemon...")
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	startCmd := exec.Command(executable, manualStartArgs()...)
	startCmd.Stdout = os.Stdout
	startCmd.Stderr = os.Stderr

	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}

	return nil
}
