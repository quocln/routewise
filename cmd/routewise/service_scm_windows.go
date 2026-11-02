//go:build windows

package main

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// scmWait is how long a start or stop is waited for, and scmPoll how often the
// state is re-read.
const (
	scmWait = 40 * time.Second
	scmPoll = 250 * time.Millisecond
)

// openHelperService opens the installed helper service with the given access
// rights. The service control manager itself is opened for connection only:
// mgr.Connect asks for all access, which a standard user is refused even when
// they only want to read a status. It returns errServiceMissing when the
// service is not installed.
func openHelperService(access uint32) (*mgr.Service, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, fmt.Errorf("connect to the service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	name, err := syscall.UTF16PtrFromString(helperServiceName)
	if err != nil {
		return nil, err
	}
	handle, err := windows.OpenService(scm, name, access)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, errServiceMissing
		}
		return nil, fmt.Errorf("open service %s: %w", helperServiceName, err)
	}
	return &mgr.Service{Name: helperServiceName, Handle: handle}, nil
}

// errServiceMissing says the helper service is not installed.
var errServiceMissing = errors.New("the RouteWise service is not installed")

// waitForState polls the service until it reaches state or scmWait passes. A
// service that stops while it was being waited on to run has failed to start;
// the exit code is reported so the log can be found.
func waitForState(s *mgr.Service, state svc.State) error {
	deadline := time.Now().Add(scmWait)
	for {
		status, err := s.Query()
		if err != nil {
			return fmt.Errorf("query service: %w", err)
		}
		if status.State == state {
			return nil
		}
		if state == svc.Running && status.State == svc.Stopped {
			return fmt.Errorf("the service stopped right after starting (exit code %d, service exit code %d); see service.log in the log folder",
				status.Win32ExitCode, status.ServiceSpecificExitCode)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for the service to reach state %d (now %d)", state, status.State)
		}
		time.Sleep(scmPoll)
	}
}

// stopService asks the service to stop and waits for it. A service that is
// already stopped is not an error.
func stopService(s *mgr.Service) error {
	status, err := s.Control(svc.Stop)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return nil
		}
		return fmt.Errorf("stop service: %w", err)
	}
	if status.State == svc.Stopped {
		return nil
	}
	return waitForState(s, svc.Stopped)
}

// startService starts the service and waits for it to run.
func startService(s *mgr.Service) error {
	if err := s.Start(); err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return nil
		}
		return fmt.Errorf("start service: %w", err)
	}
	return waitForState(s, svc.Running)
}
