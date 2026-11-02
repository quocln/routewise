//go:build darwin

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

// System tools are run by absolute path, like the helper does, so a PATH
// under sudo cannot substitute another binary.
const (
	psPath        = "/bin/ps"
	launchctlPath = "/bin/launchctl"
)

// helperLaunchdLabel is the label scripts/install.sh gives the installed
// helper's launchd job; it lives in the system domain.
const helperLaunchdLabel = "com.routewise.helper"

// launchdControl controls the helper through launchd and ps.
type launchdControl struct{}

func newServiceControl() serviceControl { return launchdControl{} }

func (launchdControl) ManagerName() string { return "launchd" }

// Managed reports whether the installed helper job is loaded in launchd's
// system domain. Only that exact job counts: a substring match on
// "com.routewise" would also accept an unrelated job.
func (launchdControl) Managed() bool {
	return exec.Command(launchctlPath, "print", "system/"+helperLaunchdLabel).Run() == nil
}

func (launchdControl) Restart(stdout, stderr io.Writer) error {
	kickstart := exec.Command(launchctlPath, "kickstart", "-k", "system/"+helperLaunchdLabel)
	kickstart.Stdout = stdout
	kickstart.Stderr = stderr
	if err := kickstart.Run(); err != nil {
		return fmt.Errorf("launchctl kickstart: %w", err)
	}
	return nil
}

func (launchdControl) ProcessName(pid int) (string, error) {
	output, err := exec.Command(psPath, "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (launchdControl) Terminate(process *os.Process) error {
	return process.Signal(syscall.SIGTERM)
}
