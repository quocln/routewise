package main

import (
	"io"
	"os"
)

// serviceControl is how the CLI reaches the OS's own supervision of the
// installed helper: asking its service manager to restart it, and reading and
// signalling its process. macOS uses launchd and ps; other systems report
// platform.ErrUnsupported until they are ported.
type serviceControl interface {
	// ManagerName names the service manager in messages, for example "launchd".
	ManagerName() string
	// Managed reports whether the service manager has the installed helper
	// loaded.
	Managed() bool
	// Restart restarts the installed helper through the service manager,
	// writing the manager's own output to stdout and stderr.
	Restart(stdout, stderr io.Writer) error
	// ProcessName returns the executable name of the process with pid.
	ProcessName(pid int) (string, error)
	// Terminate asks process to exit cleanly.
	Terminate(process *os.Process) error
}

// service is the serviceControl of the running OS.
var service = newServiceControl()
