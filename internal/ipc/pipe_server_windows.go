//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// errPipeServerUntrusted is returned by Dial when the process serving the pipe
// is not the helper.
var errPipeServerUntrusted = errors.New("the RouteWise pipe is served by a process that is not the RouteWise helper")

// verifyPipeServer closes conn and returns an error unless the process serving
// it is the helper; see pipeServerTrusted.
func verifyPipeServer(conn net.Conn) error {
	handle, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("cannot identify the pipe server")
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(handle.Fd()), &pid); err != nil {
		return fmt.Errorf("identify the pipe server: %w", err)
	}
	// An unqueryable service (not installed, or no right to query it) is not an
	// error here: the server may still be a foreground helper.
	servicePID, _ := serviceProcessID()
	server, known := identifyProcess(pid)
	if !pipeServerTrusted(pid, servicePID, server, known) {
		return errPipeServerUntrusted
	}
	return nil
}

// serviceProcessID returns the process id of the running helper service, or 0
// when it is not running. Querying needs only SERVICE_QUERY_STATUS, which
// standard users have on the helper service.
func serviceProcessID() (uint32, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString(ServiceName)
	if err != nil {
		return 0, err
	}
	service, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(service)

	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err := windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed); err != nil {
		return 0, err
	}
	return status.ProcessId, nil
}
