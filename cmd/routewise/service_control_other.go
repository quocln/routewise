//go:build !darwin && !linux && !windows

package main

import (
	"io"
	"os"

	"github.com/quocln/routewise/internal/platform"
)

// unsupportedControl reports every operation as unsupported: this OS has no
// service manager integration yet, and no helper to find by process name.
type unsupportedControl struct{}

func newServiceControl() serviceControl { return unsupportedControl{} }

func (unsupportedControl) ManagerName() string { return "the service manager" }

func (unsupportedControl) Managed() bool { return false }

func (unsupportedControl) Restart(io.Writer, io.Writer) error {
	return platform.Unsupported("service restart")
}

func (unsupportedControl) ProcessName(int) (string, error) {
	return "", platform.Unsupported("process lookup")
}

func (unsupportedControl) Terminate(*os.Process) error {
	return platform.Unsupported("process termination")
}
