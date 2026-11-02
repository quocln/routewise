//go:build !darwin && !linux && !windows

package resolverfiles

import (
	"context"

	"github.com/quocln/routewise/internal/platform"
)

// FlushSystemCache fails with platform.ErrUnsupported: this OS has no DNS cache
// RouteWise knows how to empty.
func FlushSystemCache(context.Context) error {
	return platform.Unsupported("flushing the DNS cache")
}

// DefaultDir is empty: this platform has no per-domain resolver directory.
const DefaultDir = ""

// NewSystem returns a Configurator whose Apply fails with
// platform.ErrUnsupported, since split DNS is not implemented for this OS.
// RemoveAll and Active succeed: nothing was ever written.
func NewSystem(string, int) Configurator { return unsupported{} }

type unsupported struct{}

func (unsupported) Active() []string { return nil }

func (unsupported) Apply([]string) ([]string, error) {
	return nil, platform.Unsupported("split DNS configuration")
}

func (unsupported) RemoveAll() error { return nil }
