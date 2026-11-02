//go:build linux

package tunnelnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

// TunNamePattern is the name template of the helper's own TUN devices; the
// kernel replaces %d with the first free number (rwtun0, rwtun1, ...). The
// helper recognizes its tunnels by this prefix, so no VPN client's device
// (tun0, wg0) can be taken for one of them.
const TunNamePattern = "rwtun%d"

// CreateTUN opens a new TUN device with the given MTU. The kernel picks the
// interface name; read it back with Name.
func CreateTUN(mtu int) (tun.Device, error) { return tun.CreateTUN(TunNamePattern, mtu) }

// AddAlias adds local as an address of iface whose peer is peer, over netlink.
// local is an address or an address with prefix length (a bare address is a
// /32). When peer is local's own address, as wg-quick configures, the address
// is plain: a /32 installs no connected route, because routing belongs to the
// caller and a route nobody listed must never appear. The command runner is
// unused; netlink needs no external tool.
func AddAlias(_ context.Context, _ CommandRunner, iface, local, peer string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("look up %s: %w", iface, err)
	}
	addr, err := pointToPointAddr(local, peer)
	if err != nil {
		return fmt.Errorf("address %s on %s: %w", local, iface, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add address %s to %s: %w", local, iface, err)
	}
	return nil
}

// Up brings iface up, over netlink.
func Up(_ context.Context, _ CommandRunner, iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("look up %s: %w", iface, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring %s up: %w", iface, err)
	}
	return nil
}

// pointToPointAddr builds the netlink address for AddAlias.
func pointToPointAddr(local, peer string) (*netlink.Addr, error) {
	prefix := local
	if !strings.Contains(prefix, "/") {
		prefix += "/32"
	}
	lp, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, err
	}
	if !lp.Addr().Is4() {
		return nil, fmt.Errorf("%s is not an IPv4 address", local)
	}
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil {
		return nil, fmt.Errorf("peer: %w", err)
	}
	if !peerAddr.Is4() {
		return nil, fmt.Errorf("peer %s is not an IPv4 address", peer)
	}

	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   net.IP(lp.Addr().AsSlice()),
		Mask: net.CIDRMask(lp.Bits(), 32),
	}}
	if peerAddr != lp.Addr() {
		addr.Peer = &net.IPNet{IP: net.IP(peerAddr.AsSlice()), Mask: net.CIDRMask(32, 32)}
	}
	return addr, nil
}
