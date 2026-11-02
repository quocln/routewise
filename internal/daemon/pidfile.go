// Package daemon implements the core daemon logic for VPN routing.
package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// WritePIDFile atomically creates a PID file using O_EXCL.
// If a PID file already exists, checks if the process is still running.
// Returns error if another daemon instance is active.
func WritePIDFile(path string) error {
	pid := os.Getpid()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if os.IsExist(err) {
			// PID file exists — check if stale
			existingPid, running := CheckPIDFile(path)
			if running {
				return fmt.Errorf("daemon already running (pid %d)", existingPid)
			}
			// Stale PID file — remove and retry
			os.Remove(path)
			f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				return fmt.Errorf("create PID file: %w", err)
			}
		} else {
			return fmt.Errorf("create PID file: %w", err)
		}
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%d\n", pid)
	return err
}

// RemovePIDFile removes the PID file.
func RemovePIDFile(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil // Already removed
	}
	return err
}

// CheckPIDFile checks if a process is running from the PID file.
// Returns the PID and whether the process is running.
func CheckPIDFile(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}

	pidStr := string(data)
	// Trim newline if present
	if len(pidStr) > 0 && pidStr[len(pidStr)-1] == '\n' {
		pidStr = pidStr[:len(pidStr)-1]
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, false
	}

	return pid, processExists(pid)
}

// EnsurePIDFileDir ensures the directory for the PID file exists.
func EnsurePIDFileDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create PID directory: %w", err)
	}
	return nil
}
