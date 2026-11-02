package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quocln/routewise/internal/daemon"
)

// stopPollInterval is how often a stopping daemon's PID file is re-checked.
var stopPollInterval = 500 * time.Millisecond

// stopOutcome says what stopDaemon found and did.
type stopOutcome int

const (
	daemonNotRunning stopOutcome = iota // no live process in the PID file
	daemonStalePID                      // the PID was not routewise; the file was removed
	daemonSignalled                     // SIGTERM was sent
)

// stopDaemon asks the daemon named in pidFile to exit (SIGTERM on macOS) after
// checking the PID really belongs to routewise: a PID file outlives its process
// and the PID may since have been reused.
func stopDaemon(pidFile string) (outcome stopOutcome, pid int, err error) {
	pid, running := daemon.CheckPIDFile(pidFile)
	if !running {
		return daemonNotRunning, 0, nil
	}
	if !verifyProcess(pid, "routewise") {
		daemon.RemovePIDFile(pidFile)
		return daemonStalePID, pid, nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return daemonSignalled, pid, fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := service.Terminate(process); err != nil {
		if os.IsPermission(err) {
			return daemonSignalled, pid, fmt.Errorf("permission denied - try with sudo")
		}
		daemon.RemovePIDFile(pidFile)
		return daemonSignalled, pid, fmt.Errorf("send signal: %w", err)
	}
	return daemonSignalled, pid, nil
}

// waitForDaemonExit polls the PID file up to attempts times, sleeping before
// each check, and reports whether the daemon is gone.
func waitForDaemonExit(pidFile string, attempts int) bool {
	for i := 0; i < attempts; i++ {
		time.Sleep(stopPollInterval)
		if _, running := daemon.CheckPIDFile(pidFile); !running {
			return true
		}
	}
	return false
}

// verifyProcess checks if the process with the given PID matches the expected name.
func verifyProcess(pid int, expectedName string) bool {
	comm, err := service.ProcessName(pid)
	if err != nil {
		return false
	}
	return strings.Contains(filepath.Base(comm), expectedName)
}
