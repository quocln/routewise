//go:build windows

package main

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// scmControl controls the helper through the Windows service control manager
// and reads other processes with the Win32 process API.
type scmControl struct{}

func newServiceControl() serviceControl { return scmControl{} }

func (scmControl) ManagerName() string { return "Windows Service Control Manager" }

// Managed reports whether the helper service exists and is running. A missing
// service, or one this user cannot query, is not managed.
func (scmControl) Managed() bool {
	s, err := openHelperService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer s.Close()
	status, err := s.Query()
	return err == nil && status.State == svc.Running
}

// Restart stops the service, waits for it to stop, and starts it again. The
// manager prints nothing of its own, so stdout gets a one-line progress note.
func (scmControl) Restart(stdout, _ io.Writer) error {
	s, err := openHelperService(windows.SERVICE_QUERY_STATUS | windows.SERVICE_START | windows.SERVICE_STOP)
	if err != nil {
		return err
	}
	defer s.Close()
	fmt.Fprintf(stdout, "Stopping service %s...\n", helperServiceName)
	if err := stopService(s); err != nil {
		return err
	}
	return startService(s)
}

// ProcessName returns the file name of the executable of process pid
// (QueryFullProcessImageName gives the full path; the caller takes its base).
func (scmControl) ProcessName(pid int) (string, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(process)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(process, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// Terminate asks process to exit cleanly. When process is the helper service
// the manager stops it, which runs the daemon's graceful stop. Any other
// process (a foreground helper) has no way to be told to stop from outside its
// console, so it is terminated; the next start recovers the route journal it
// leaves behind.
func (scmControl) Terminate(process *os.Process) error {
	if s, err := openHelperService(windows.SERVICE_QUERY_STATUS | windows.SERVICE_STOP); err == nil {
		defer s.Close()
		if status, err := s.Query(); err == nil && status.ProcessId == uint32(process.Pid) {
			return stopService(s)
		}
	}
	return process.Kill()
}
