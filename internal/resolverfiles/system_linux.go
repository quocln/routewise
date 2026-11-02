//go:build linux

package resolverfiles

import (
	"fmt"
	"net/netip"
)

// DefaultDir is empty: systemd-resolved is configured over D-Bus, not through
// a directory of per-domain files.
const DefaultDir = ""

// NewSystem returns the split-DNS configuration of this Linux host: a dummy
// link in systemd-resolved that sends the forwarded domains to nameserver:port.
// A nameserver that is not an IP address yields a Configurator whose Apply
// reports that.
func NewSystem(nameserver string, port int) Configurator {
	addr, err := netip.ParseAddr(nameserver)
	if err != nil {
		return invalid{fmt.Errorf("forwarder address %q: %w", nameserver, err)}
	}
	return newResolved(newResolvedBackend(), netip.AddrPortFrom(addr, uint16(port)))
}

// invalid is the Configurator of a malformed forwarder address: it configures
// nothing and says why.
type invalid struct{ err error }

func (invalid) Active() []string                   { return nil }
func (i invalid) Apply([]string) ([]string, error) { return nil, i.err }
func (invalid) RemoveAll() error                   { return nil }
