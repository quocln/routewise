//go:build !darwin && !linux && !windows

package dns

import (
	"context"

	"github.com/quocln/routewise/internal/platform"
)

// systemDNSConfig reports that reading the system's resolver configuration is
// not implemented for this OS.
func systemDNSConfig(context.Context) (string, error) {
	return "", platform.Unsupported("system DNS configuration")
}
