//go:build darwin

package ipc

import (
	"fmt"
	"net"
	"os"
)

// DefaultAddress is the helper's Unix socket path.
const DefaultAddress = "/var/run/routewise.sock"

// staffGID is the macOS "staff" group, which every interactive user belongs to.
const staffGID = 20

// Listen creates the helper's endpoint at address, replacing a stale socket
// file, and restricts it to root and the staff group (mode 0660). Permissions
// are the only access control, so a failure to set them is fatal and leaves no
// socket behind.
func Listen(address string) (net.Listener, error) {
	// Remove stale socket file
	os.Remove(address)

	listener, err := net.Listen("unix", address)
	if err != nil {
		return nil, err
	}

	// Set socket permissions: root owner, staff group (gid 20), rw for owner+group
	// This allows GUI apps running as user to connect while maintaining security
	// Permissions are the ONLY access control — failure must be fatal
	if err := os.Chown(address, 0, staffGID); err != nil {
		listener.Close()
		os.Remove(address)
		return nil, fmt.Errorf("set socket group: %w", err)
	}
	if err := os.Chmod(address, 0660); err != nil {
		listener.Close()
		os.Remove(address)
		return nil, fmt.Errorf("set socket permissions: %w", err)
	}
	return listener, nil
}

// Remove deletes the endpoint left at address, if any.
func Remove(address string) { os.Remove(address) }
