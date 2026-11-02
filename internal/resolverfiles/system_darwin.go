//go:build darwin

package resolverfiles

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

const (
	// The daemon runs as root, so it never resolves these tools through PATH.
	dscacheutilPath = "/usr/bin/dscacheutil"
	killallPath     = "/usr/bin/killall"
	// flushLimit bounds both commands, so a wedged tool cannot hang the request.
	flushLimit = 5 * time.Second
)

// FlushSystemCache empties this Mac's DNS caches: the directory service's, then
// mDNSResponder's, which forgets its answers on SIGHUP. Both are attempted even
// when the first fails.
func FlushSystemCache(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, flushLimit)
	defer cancel()
	var errs []error
	if err := exec.CommandContext(ctx, dscacheutilPath, "-flushcache").Run(); err != nil {
		errs = append(errs, fmt.Errorf("dscacheutil -flushcache: %w", err))
	}
	if err := exec.CommandContext(ctx, killallPath, "-HUP", "mDNSResponder").Run(); err != nil {
		errs = append(errs, fmt.Errorf("killall -HUP mDNSResponder: %w", err))
	}
	return errors.Join(errs...)
}

// DefaultDir is where macOS looks for per-domain resolver configuration.
const DefaultDir = "/etc/resolver"

// NewSystem returns the split-DNS configuration of this Mac: resolver files in
// DefaultDir that point at nameserver:port.
func NewSystem(nameserver string, port int) Configurator {
	return New(DefaultDir, nameserver, port)
}
