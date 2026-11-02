//go:build windows

package daemon

import (
	"errors"

	"golang.org/x/sys/windows"
)

// stillActive is the exit code GetExitCodeProcess reports for a process that
// has not exited (STILL_ACTIVE).
const stillActive = 259

// processExists reports whether process pid is running. os.FindProcess is not
// used: it opens the process with rights a standard user lacks for the service. Go's Signal(0) is not
// supported on Windows, so the process is opened with the least access that
// can read its exit code. Access denied means the process exists but belongs to
// a more privileged account (the service seen from a standard user), which
// counts as running for the same reason the Unix probe counts EPERM.
func processExists(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer windows.CloseHandle(handle)
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return false
	}
	return code == stillActive
}
