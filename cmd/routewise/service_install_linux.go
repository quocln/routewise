//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/quocln/routewise/internal/configdb"
	"github.com/quocln/routewise/internal/platform"
)

const (
	installedBinaryDir = "/usr/lib/routewise"
	installedBinary    = installedBinaryDir + "/routewise"
	unitDir            = "/etc/systemd/system"
	unitPath           = unitDir + "/" + helperUnitName
)

// requireRoot refuses to continue unless the process is root: the install
// writes under /etc and /usr/lib and drives systemd.
func requireRoot(action string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s needs root; run it with sudo", action)
	}
	return nil
}

// systemctl runs one systemctl command, passing its output through so a
// failure explains itself.
func systemctl(args ...string) error {
	cmd := exec.Command(systemctlPath(), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w", args[0], err)
	}
	return nil
}

// installService copies this executable to its system location, writes the
// unit, seeds the configuration, and enables and starts the service. Running it
// again over a live service stops it, swaps the executable atomically and
// starts it again.
func installService() error {
	if err := requireRoot("service install"); err != nil {
		return err
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return fmt.Errorf("systemd is not running on this machine: %w", platform.ErrUnsupported)
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this executable: %w", err)
	}

	// Stopping first keeps the helper from running a half-replaced install and
	// lets it remove its own routes and DNS state on the way out.
	// A first install has nothing to stop, so a failure here is expected.
	_ = exec.Command(systemctlPath(), "stop", helperUnitName).Run()

	if self != installedBinary {
		if err := installExecutable(self, installedBinary); err != nil {
			return err
		}
		fmt.Printf("Installed %s\n", installedBinary)
	}

	configPath := platform.ConfigFile()
	for _, dir := range []string{platform.ConfigDir(), platform.DataDir(), platform.LogDir()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	seeded, err := seedConfig(configPath, filepath.Join(platform.DataDir(), configdb.FileName),
		starterConfig(platform.PidFile(), platform.LogFile()))
	if err != nil {
		return err
	}
	if seeded {
		fmt.Printf("Created %s\n", configPath)
	} else {
		fmt.Println("Keeping the existing configuration")
	}

	err = replaceFile(unitPath, 0o644, func(w io.Writer) error {
		_, err := io.WriteString(w, systemdUnit(installedBinary, configPath))
		return err
	})
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", unitPath)

	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "--now", helperUnitName); err != nil {
		return err
	}
	fmt.Println("RouteWise helper service installed and started")
	return nil
}

// uninstallService stops and disables the service and removes its unit and
// executable. The configuration, database and logs stay, so a later install
// picks up where this one left off.
func uninstallService() error {
	if err := requireRoot("service uninstall"); err != nil {
		return err
	}
	// Both fail harmlessly when the unit is already gone, which keeps a repeated
	// uninstall quiet instead of an error.
	if _, err := os.Stat(unitPath); err == nil {
		if err := systemctl("disable", "--now", helperUnitName); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect %s: %w", unitPath, err)
	}

	for _, path := range []string{unitPath, installedBinary} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	// Leaves the directory in place when something else was put in it.
	_ = os.Remove(installedBinaryDir)

	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	fmt.Printf("RouteWise helper service removed; %s, %s and %s are kept\n",
		platform.ConfigDir(), platform.DataDir(), platform.LogDir())
	return nil
}
