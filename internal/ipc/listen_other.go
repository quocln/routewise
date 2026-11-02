//go:build !darwin && !linux && !windows

package ipc

import (
	"net"

	"github.com/quocln/routewise/internal/platform"
)

// DefaultAddress is empty: no endpoint location is defined for this platform.
const DefaultAddress = ""

// Listen reports that the helper's transport is not implemented here.
func Listen(string) (net.Listener, error) { return nil, platform.Unsupported("helper IPC listener") }

// Remove does nothing: Listen never creates an endpoint on this platform.
func Remove(string) {}
