//go:build darwin

package tunnelnet

import (
	"context"
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

// IfconfigPath is absolute on purpose: the helper runs as root and must never
// resolve a system tool through PATH.
const IfconfigPath = "/sbin/ifconfig"

// CreateTUN opens a new utun device with the given MTU. The kernel picks the
// interface name; read it back with Name.
func CreateTUN(mtu int) (tun.Device, error) { return tun.CreateTUN("utun", mtu) }

// AddAlias adds local as a point-to-point alias of iface whose peer is peer
// (`ifconfig iface inet local peer alias`). Giving the interface itself as the
// peer, as wg-quick does on macOS, installs no connected-subnet route: routing
// belongs to the caller, and a route nobody listed must never appear.
func AddAlias(ctx context.Context, run CommandRunner, iface, local, peer string) error {
	if out, err := run.Run(ctx, IfconfigPath, iface, "inet", local, peer, "alias"); err != nil {
		return fmt.Errorf("ifconfig %s inet %s: %w: %s", iface, local, err, out)
	}
	return nil
}

// Up brings iface up (`ifconfig iface up`).
func Up(ctx context.Context, run CommandRunner, iface string) error {
	if out, err := run.Run(ctx, IfconfigPath, iface, "up"); err != nil {
		return fmt.Errorf("ifconfig %s up: %w: %s", iface, err, out)
	}
	return nil
}
