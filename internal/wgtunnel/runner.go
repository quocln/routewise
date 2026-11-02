package wgtunnel

import (
	"context"
	"net/netip"

	"github.com/quocln/routewise/internal/tunnelnet"
)

// CommandRunner executes an external command and returns its combined output.
// name must be an absolute path.
type CommandRunner = tunnelnet.CommandRunner

// ExecRunner runs real commands via os/exec, refusing non-absolute names.
type ExecRunner = tunnelnet.ExecRunner

// assignAddresses mirrors wg-quick: each IPv4 address is added as a
// point-to-point alias whose peer is itself, then the interface is brought up.
// The prefix length of the .conf is ignored and every address is a /32, so
// the OS installs no connected-subnet route: routing belongs to the caller, and
// a route nobody listed must never appear. IPv6 addresses are skipped (the
// helper's routing is IPv4 only).
func assignAddresses(ctx context.Context, links tunnelnet.Links, name string, addrs []netip.Prefix) error {
	for _, p := range addrs {
		if !p.Addr().Is4() {
			continue
		}
		a := p.Addr().String()
		if err := links.AddAlias(ctx, name, a+"/32", a); err != nil {
			return err
		}
	}
	return links.Up(ctx, name)
}
