package route

import (
	"context"
	"net/netip"
)

// Table is the kernel routing table as the manager needs it: reading the
// default and LAN routes, looking up a destination, and adding or removing the
// host, prefix and default routes RouteWise owns. Every operating system
// supplies one; the macOS implementation drives the BSD route and netstat
// tools. Methods are safe for concurrent use.
type Table interface {
	// Snapshot reads the current IPv4 routing table.
	Snapshot(ctx context.Context) ([]RouteEntry, error)
	// Default returns the gateway and interface of the global default route.
	// The gateway is invalid when the route points straight at an interface.
	Default(ctx context.Context) (gateway netip.Addr, iface string, err error)
	// DefaultGateway returns the gateway of the global default route and fails
	// when the route has none.
	DefaultGateway(ctx context.Context) (netip.Addr, error)
	// LocalGateway returns the LAN gateway and interface even while a VPN owns
	// the global default route; prefer names the interface to choose when
	// several LANs have a default.
	LocalGateway(ctx context.Context, prefer string) (netip.Addr, string, error)
	// Lookup returns the interface and gateway traffic to dest leaves through.
	Lookup(ctx context.Context, dest netip.Addr) (iface string, gateway netip.Addr, err error)

	// AddHost adds a host route via gateway, or through iface when gateway is
	// invalid. A route the kernel already holds is adopted only when it leads
	// through this tunnel.
	AddHost(ctx context.Context, dest, gateway netip.Addr, iface string) error
	// AddPrefix is AddHost for a network route.
	AddPrefix(ctx context.Context, prefix netip.Prefix, gateway netip.Addr, iface string) error
	// AddNet adds a network route using the destination and gateway notation
	// exactly as the kernel table printed them.
	AddNet(ctx context.Context, destRaw, gatewayRaw, iface string) error
	// DeleteHost removes a host route; one that is already gone is not an error.
	DeleteHost(ctx context.Context, dest netip.Addr) error
	// DeleteNet removes a network route given in the kernel's own notation. A
	// destination two VPNs both route (their 0/1 halves) loses only the route
	// through iface, or through gatewayRaw when no interface is known; with
	// neither, every route to the destination goes. The BSD route tool deletes
	// by destination alone and ignores both.
	DeleteNet(ctx context.Context, destRaw, gatewayRaw, iface string) error
	// DropClonedLinkLayer deletes a link-layer entry the kernel cloned for dest
	// on a LAN interface, if there is one. Errors are ignored.
	DropClonedLinkLayer(ctx context.Context, dest netip.Addr)

	// ChangeDefault points the default route at gateway, adding one only when
	// there is none to change.
	ChangeDefault(ctx context.Context, gateway netip.Addr) error
	// ChangeDefaultStrict points the default route at gateway without ever
	// adding or deleting one, so a failure leaves the existing default alone.
	ChangeDefaultStrict(ctx context.Context, gateway netip.Addr) error
	// ReplaceDefault is ChangeDefaultStrict returning the tool's error as is.
	ReplaceDefault(ctx context.Context, gateway netip.Addr) error
	// ChangeDefaultToInterface points the default route at a tunnel interface.
	ChangeDefaultToInterface(ctx context.Context, iface string) error

	// AddIPv6Reject adds a host route that makes connections to addr fail at once.
	AddIPv6Reject(ctx context.Context, addr netip.Addr) error
	// DeleteIPv6Reject removes that route; one that is already gone is not an error.
	DeleteIPv6Reject(ctx context.Context, addr netip.Addr) error
	// AddIPv6RejectAll makes every connection to a global IPv6 address fail, by
	// a reject route for 2000::/3. One that already exists is accepted.
	AddIPv6RejectAll(ctx context.Context) error
	// DeleteIPv6RejectAll removes that route; one that is already gone is not an error.
	DeleteIPv6RejectAll(ctx context.Context) error

	// IsUnreachable reports whether err means the gateway is not on any
	// connected network.
	IsUnreachable(err error) bool
}

// ListRoutes returns all routes from the system routing table.
func ListRoutes() ([]RouteEntry, error) {
	return systemTable().Snapshot(context.Background())
}
