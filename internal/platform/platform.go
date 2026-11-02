// Package platform holds the few operating-system facts that more than one
// package needs, and the error every platform seam returns on a system it has
// no implementation for. The seams themselves live in the package that
// consumes them (route, resolverfiles, dns, vpnclient, tunnelnet, dnswatch,
// ipc, daemon); each has a darwin implementation and a stub elsewhere that
// reports ErrUnsupported instead of pretending to work.
package platform

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrUnsupported is wrapped by every error a stub implementation returns, so
// callers can tell "not ported to this OS" from a real failure.
var ErrUnsupported = errors.ErrUnsupported

// Unsupported reports that feature has no implementation on this OS.
func Unsupported(feature string) error {
	return fmt.Errorf("%s is not supported on %s: %w", feature, runtime.GOOS, ErrUnsupported)
}
