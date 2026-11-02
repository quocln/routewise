package main

import (
	"runtime"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Install or remove the helper as a system service",
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install this executable as the helper and start it",
	Long: `Install this executable as the RouteWise helper service and start it.

The executable is copied to a system location, a service definition is
written, a starter configuration is created when none exists, and the service
is enabled at boot and started. Running it again replaces the installed
executable and restarts the service; the configuration is kept.

Linux (systemd) and Windows (service control manager); macOS installs the
helper with "sudo make install". Requires root on Linux and an elevated
(Run as administrator) prompt on Windows.

Examples:
  sudo ./routewise service install
  .\routewise.exe service install`,
	Args: cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error { return installService() },
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove the helper service",
	Long: `Stop the RouteWise helper service, disable it at boot, and remove its
service definition and installed executable. The configuration, the database
(including the access history) and the logs are kept.

Linux (systemd) and Windows only. Requires root on Linux and an elevated
prompt on Windows.

Examples:
  sudo routewise service uninstall
  routewise.exe service uninstall`,
	Args: cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error { return uninstallService() },
}

func init() {
	serviceCmd.AddCommand(serviceInstallCmd, serviceUninstallCmd)
	// macOS installs the helper with `sudo make install`, so the command would
	// only ever answer "unsupported" there.
	if runtime.GOOS != "darwin" {
		rootCmd.AddCommand(serviceCmd)
	}
}
