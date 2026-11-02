//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// helperUnitName is the systemd unit `routewise service install` writes for
// the helper.
const helperUnitName = "routewise.service"

// systemctlPath returns the systemctl binary by absolute path, like the helper
// does for its other system tools, so a PATH under sudo cannot substitute
// another binary. Merged-/usr systems have it in /usr/bin; older ones in /bin.
func systemctlPath() string {
	for _, path := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return "/usr/bin/systemctl"
}

// systemdControl controls the helper through systemctl and /proc.
type systemdControl struct{}

func newServiceControl() serviceControl { return systemdControl{} }

func (systemdControl) ManagerName() string { return "systemd" }

// Managed reports whether the installed helper unit is active. Only that exact
// unit counts.
func (systemdControl) Managed() bool {
	return exec.Command(systemctlPath(), "is-active", "--quiet", helperUnitName).Run() == nil
}

func (systemdControl) Restart(stdout, stderr io.Writer) error {
	restart := exec.Command(systemctlPath(), "restart", helperUnitName)
	restart.Stdout = stdout
	restart.Stderr = stderr
	if err := restart.Run(); err != nil {
		return fmt.Errorf("systemctl restart: %w", err)
	}
	return nil
}

// ProcessName reads the kernel's name for the process (/proc/PID/comm), which
// is the executable's file name truncated to 15 characters.
func (systemdControl) ProcessName(pid int) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (systemdControl) Terminate(process *os.Process) error {
	return process.Signal(syscall.SIGTERM)
}
