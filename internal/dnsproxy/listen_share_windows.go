//go:build windows

package dnsproxy

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// shareListener is a variable so forwarder.go can test for its presence on
// every OS. It sets SO_REUSEADDR before the bind. Windows refuses to bind a
// specific address on a port that a service already holds on the wildcard
// address (the Internet Connection Sharing DNS proxy behind Hyper-V's Default
// Switch holds 0.0.0.0:53) unless the later socket asks to share.
var shareListener = func(_, _ string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return sockErr
}
