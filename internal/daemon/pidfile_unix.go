//go:build unix

package daemon

import (
	"errors"
	"os"
	"syscall"
)

// processExists probes for process without delivering anything (signal 0). A
// caller that is not root gets EPERM for the root-owned helper: the process
// exists, it just may not be signalled. Reading that as "stopped" would let an
// unprivileged CLI conclude it owns the config file while the helper is still
// writing it.
func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
