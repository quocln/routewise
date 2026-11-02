//go:build linux

package ipc

import (
	"fmt"
	"net"
	"os"
)

// DefaultAddress is the helper's Unix socket path.
const DefaultAddress = "/run/routewise.sock"

// Listen creates the helper's endpoint at address, replacing a stale socket
// file. The socket is root-owned and world-connectable (mode 0666): there is no
// group every desktop user shares the way macOS has staff, so connecting is
// open and the daemon's peer authorizer, fed by the kernel-reported uid, is
// what limits routing changes to root and the active seat user. Everyone else
// gets read-only status. A failure to set the mode is fatal and leaves no
// socket behind.
func Listen(address string) (net.Listener, error) {
	// Remove stale socket file
	os.Remove(address)

	listener, err := net.Listen("unix", address)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(address, 0666); err != nil {
		listener.Close()
		os.Remove(address)
		return nil, fmt.Errorf("set socket permissions: %w", err)
	}
	return listener, nil
}

// Remove deletes the endpoint left at address, if any.
func Remove(address string) { os.Remove(address) }
