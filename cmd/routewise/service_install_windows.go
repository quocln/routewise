//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/quocln/routewise/internal/configdb"
	"github.com/quocln/routewise/internal/platform"
	"github.com/quocln/routewise/internal/resolverfiles"
)

// requireRoot refuses to continue unless the process is elevated: the install
// writes under Program Files and drives the service control manager.
func requireRoot(action string) error {
	if !isPrivileged() {
		return fmt.Errorf("%s needs an elevated prompt; run it from a terminal started with \"Run as administrator\"", action)
	}
	return nil
}

// installPlan is the plan for this machine.
func installPlan() (windowsInstallPlan, error) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return windowsInstallPlan{}, fmt.Errorf("find the Program Files folder: %w", err)
	}
	return newWindowsInstallPlan(programFiles, platform.DataDir(), platform.LogDir(), platform.RunDir(), platform.ConfigFile()), nil
}

// retry runs fn until it succeeds or the attempts run out. A just-stopped
// service, or a virus scanner still holding the file it exited from, keeps an
// executable locked for a moment after the process is gone.
func retry(attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		time.Sleep(delay)
	}
	return err
}

// commandLine renders the service's command line with the quoting the service
// control manager parses.
func commandLine(exe string, args []string) string {
	line := syscall.EscapeArg(exe)
	for _, a := range args {
		line += " " + syscall.EscapeArg(a)
	}
	return line
}

// installService copies this executable to Program Files, creates the data
// directories with an access list that keeps Users read-only, seeds the
// configuration, registers the service (LocalSystem, automatic start, restart
// on failure) and starts it. Running it again over a live service stops it,
// swaps the executable and starts it again.
func installService() (err error) {
	if err := requireRoot("service install"); err != nil {
		return err
	}
	plan, err := installPlan()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this executable: %w", err)
	}

	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service control manager: %w", err)
	}
	defer scm.Disconnect()

	existing, err := scm.OpenService(helperServiceName)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fmt.Errorf("open service %s: %w", helperServiceName, err)
	}
	if err == nil {
		defer existing.Close()
		// Stopping first keeps the helper from running a half-replaced install and
		// lets it remove its own routes and DNS rules on the way out.
		if err := stopService(existing); err != nil {
			return err
		}
		// A reinstall that fails past this point must not leave the helper
		// stopped: bring the service it replaces back up.
		defer func() {
			if err == nil {
				return
			}
			if startErr := startService(existing); startErr != nil {
				fmt.Printf("Warning: could not restart the existing service after the failed install: %v\n", startErr)
			}
		}()
	}

	for _, dir := range plan.Dirs {
		if err := ensureProtectedDir(dir.Path, dir.SDDL); err != nil {
			return err
		}
	}

	if !samePath(self, plan.ExePath) {
		if err := retry(10, 300*time.Millisecond, func() error { return installExecutable(self, plan.ExePath) }); err != nil {
			return err
		}
		fmt.Printf("Installed %s\n", plan.ExePath)
		if err := installWintun(filepath.Dir(self), plan.InstallDir); err != nil {
			return err
		}
	}

	configPath := platform.ConfigFile()
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

	helper := existing
	if helper == nil {
		helper, err = scm.CreateService(helperServiceName, plan.ExePath, mgr.Config{
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
			DisplayName:  helperServiceDisplayName,
			Description:  helperServiceDescription,
			// An empty account is LocalSystem, which the route table and DNS
			// changes need.
			ServiceStartName: "",
			Dependencies:     helperServiceDependencies,
		}, plan.Args...)
		if err != nil {
			return fmt.Errorf("create service %s: %w", helperServiceName, err)
		}
		defer helper.Close()
		fmt.Printf("Created service %s\n", helperServiceName)
	} else if err := updateService(helper, plan); err != nil {
		return err
	}

	if err := configureRecovery(helper); err != nil {
		return err
	}
	if err := startService(helper); err != nil {
		return err
	}
	fmt.Println("RouteWise helper service installed and started")
	return nil
}

// wintunDLL is the Wintun driver library the built-in VPNs load from beside
// the helper's executable.
const wintunDLL = "wintun.dll"

// installWintun copies wintun.dll from beside the source executable into the
// install directory. Without it the helper still routes for external VPNs, but
// built-in VPNs cannot start, so a missing library is reported, not fatal.
func installWintun(srcDir, installDir string) error {
	src := filepath.Join(srcDir, wintunDLL)
	if _, err := os.Lstat(src); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("Warning: %s is not next to this executable; built-in VPNs will not start until it is installed in %s\n", wintunDLL, installDir)
		return nil
	}
	dst := filepath.Join(installDir, wintunDLL)
	if err := retry(10, 300*time.Millisecond, func() error { return installExecutable(src, dst) }); err != nil {
		return err
	}
	fmt.Printf("Installed %s\n", dst)
	return nil
}

// updateService points an existing service at the installed executable and
// restores the settings an install owns, leaving any it does not own (such as
// a dependency the administrator added) alone.
func updateService(s *mgr.Service, plan windowsInstallPlan) error {
	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("read service configuration: %w", err)
	}
	cfg.BinaryPathName = commandLine(plan.ExePath, plan.Args)
	cfg.StartType = mgr.StartAutomatic
	cfg.DisplayName = helperServiceDisplayName
	cfg.Description = helperServiceDescription
	cfg.Dependencies = withDependencies(cfg.Dependencies, helperServiceDependencies)
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("update service %s: %w", helperServiceName, err)
	}
	fmt.Printf("Updated service %s\n", helperServiceName)
	return nil
}

// configureRecovery restarts the service after a failure: quickly at first,
// then backing off, with the failure count forgotten after a day. A daemon that
// exits with an error code is restarted too, not only one that crashes.
func configureRecovery(s *mgr.Service) error {
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	if err := s.SetRecoveryActions(actions, uint32((24 * time.Hour).Seconds())); err != nil {
		return fmt.Errorf("set the service's restart-on-failure actions: %w", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("set restart-on-failure for exit codes: %w", err)
	}
	return nil
}

// uninstallService stops the service, deletes it and removes the installed
// executable. The configuration, database and logs stay, so a later install
// picks up where this one left off.
func uninstallService() error {
	if err := requireRoot("service uninstall"); err != nil {
		return err
	}
	plan, err := installPlan()
	if err != nil {
		return err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service control manager: %w", err)
	}
	defer scm.Disconnect()

	// A missing service keeps a repeated uninstall quiet instead of an error.
	s, err := scm.OpenService(helperServiceName)
	switch {
	case err == nil:
		defer s.Close()
		if err := stopService(s); err != nil {
			return err
		}
		if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return fmt.Errorf("delete service %s: %w", helperServiceName, err)
		}
	case !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		return fmt.Errorf("open service %s: %w", helperServiceName, err)
	}

	// A helper that crashed or was killed never removed its split-DNS rules, and
	// each would keep sending its domain to a forwarder that is gone.
	if err := resolverfiles.NewSystem("127.0.0.1", 53).RemoveAll(); err != nil {
		fmt.Printf("Warning: could not remove RouteWise's DNS rules: %v\n", err)
	}

	self, _ := os.Executable()
	// The stopped service no longer holds the Wintun library.
	if err := os.Remove(filepath.Join(plan.InstallDir, wintunDLL)); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("Note: could not delete %s: %v\n", wintunDLL, err)
	}
	err = retry(10, 300*time.Millisecond, func() error {
		if err := os.Remove(plan.ExePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
	switch {
	case err != nil && samePath(self, plan.ExePath):
		// Windows cannot delete a running executable, and this one is it.
		fmt.Printf("Note: %s is running this command and could not be deleted; delete %s once it exits\n", plan.ExePath, plan.InstallDir)
	case err != nil:
		return fmt.Errorf("remove %s: %w", plan.ExePath, err)
	default:
		// Leaves the directory in place when something else was put in it.
		_ = os.Remove(plan.InstallDir)
	}

	fmt.Printf("RouteWise helper service removed; %s, %s and %s are kept\n",
		platform.ConfigDir(), platform.DataDir(), platform.LogDir())
	return nil
}

// samePath reports whether two Windows paths name the same file, ignoring case
// and the difference between '/' and '\'.
func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
