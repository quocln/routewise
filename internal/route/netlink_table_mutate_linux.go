//go:build linux

package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ipNet converts a prefix to the form netlink takes.
func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// newRoute builds a unicast route in the main table, stamped as ours: through
// gateway when there is one (the kernel picks the interface that reaches it),
// otherwise straight out of iface.
func newRoute(h *netlink.Handle, dst netip.Prefix, gateway netip.Addr, iface string) (*netlink.Route, error) {
	r := &netlink.Route{Dst: ipNet(dst), Table: unix.RT_TABLE_MAIN, Protocol: ownedProtocol, Type: unix.RTN_UNICAST}
	switch {
	case gateway.IsValid():
		r.Gw = net.IP(gateway.AsSlice())
	case iface != "":
		link, err := h.LinkByName(iface)
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", iface, err)
		}
		r.LinkIndex = link.Attrs().Index
		r.Scope = netlink.SCOPE_LINK
	default:
		return nil, fmt.Errorf("either gateway or interface must be specified")
	}
	return r, nil
}

// addUnicast adds a route and reports whether the kernel already had one for
// that destination, which the caller decides whether to adopt.
func addUnicast(h *netlink.Handle, dst netip.Prefix, gateway netip.Addr, iface string) (exists bool, err error) {
	r, err := newRoute(h, dst, gateway, iface)
	if err != nil {
		return false, err
	}
	err = h.RouteAdd(r)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, unix.EEXIST):
		return true, nil
	}
	return false, fmt.Errorf("add route %s: %w", dst, err)
}

// leadsThroughTunnel reports whether an existing route's interface (or, for a
// tunnel with no interface name, its gateway) is the one being added for.
func leadsThroughTunnel(iface string, gateway netip.Addr, gotIface string, gotGW netip.Addr) bool {
	switch {
	case iface != "":
		return gotIface == iface
	case gateway.IsValid():
		return gotGW == gateway
	}
	return false
}

// AddHost adds a host route via gateway, or through iface when gateway is
// invalid. A route the kernel already holds is adopted only when it leads
// through this tunnel.
func (t *netlinkTable) AddHost(ctx context.Context, dest, gateway netip.Addr, iface string) error {
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	dest = dest.Unmap()
	exists, err := addUnicast(h, netip.PrefixFrom(dest, dest.BitLen()), gateway, iface)
	if err != nil || !exists {
		return err
	}
	gotIface, gotGW, err := t.Lookup(ctx, dest)
	if err != nil {
		return fmt.Errorf("%s already has a route that could not be verified (%v): %w", dest, err, ErrRouteOwnedElsewhere)
	}
	if !leadsThroughTunnel(iface, gateway, gotIface, gotGW) {
		return fmt.Errorf("%s is already routed through %s, not this tunnel: %w", dest, gotIface, ErrRouteOwnedElsewhere)
	}
	return nil
}

// AddPrefix is AddHost for a network route. The existing route is the one for
// exactly this destination and mask, not the longest match for it.
func (t *netlinkTable) AddPrefix(ctx context.Context, prefix netip.Prefix, gateway netip.Addr, iface string) error {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return fmt.Errorf("addPrefixRoute: %s is not an IPv4 prefix", prefix)
	}
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	prefix = prefix.Masked()
	exists, err := addUnicast(h, prefix, gateway, iface)
	if err != nil || !exists {
		return err
	}
	routes, err := listMain(h, netlink.FAMILY_V4, &netlink.Route{Dst: ipNet(prefix)}, netlink.RT_FILTER_DST)
	if err != nil {
		return fmt.Errorf("%s already has a route that could not be verified (%v): %w", prefix, err, ErrRouteOwnedElsewhere)
	}
	namer := newIfaceNamer(h)
	var otherIface string
	for _, r := range routes {
		gw, index := nexthop(r)
		name, nerr := namer.name(index)
		if nerr != nil {
			return fmt.Errorf("%s already has a route that could not be verified (%v): %w", prefix, nerr, ErrRouteOwnedElsewhere)
		}
		if leadsThroughTunnel(iface, gateway, name, addrOf(gw)) {
			return nil
		}
		otherIface = name
	}
	if otherIface == "" {
		return fmt.Errorf("%s already has a route that could not be found in the table: %w", prefix, ErrRouteOwnedElsewhere)
	}
	return fmt.Errorf("%s is already routed through %s, not this tunnel: %w", prefix, otherIface, ErrRouteOwnedElsewhere)
}

// AddNet adds a network route from the destination and gateway as the table
// printed them, to restore a route taken away. One that already exists is
// accepted.
func (t *netlinkTable) AddNet(ctx context.Context, destRaw, gatewayRaw, iface string) error {
	dst, err := parseRouteDest(destRaw)
	if err != nil {
		return fmt.Errorf("addNetRoute: %w", err)
	}
	var gateway netip.Addr
	if gatewayRaw != "" {
		if gateway, err = netip.ParseAddr(gatewayRaw); err != nil {
			return fmt.Errorf("addNetRoute: gateway %q: %w", gatewayRaw, err)
		}
	}
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	_, err = addUnicast(h, dst, gateway, iface)
	return err
}

// deleteUnicast removes the main table route for dst. A route that is already
// gone is not an error. The request matches any scope, as `ip route del` does:
// the library sends the route's scope, and the default (universe) would miss a
// route a VPN client added through its interface alone, which has link scope,
// and report it as already gone. With an interface (or, lacking one, a
// gateway) only the route through it goes: the kernel deletes the first match,
// which with two tunnels' 0/1 halves could be the other tunnel's.
func (t *netlinkTable) deleteUnicast(ctx context.Context, dst netip.Prefix, gateway netip.Addr, iface string) error {
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	r := &netlink.Route{Dst: ipNet(dst), Table: unix.RT_TABLE_MAIN, Scope: netlink.SCOPE_NOWHERE}
	switch {
	case iface != "":
		link, err := h.LinkByName(iface)
		if err != nil {
			var missing netlink.LinkNotFoundError
			if errors.As(err, &missing) {
				return nil // the interface is gone, and its routes with it
			}
			return fmt.Errorf("delete route %s: interface %s: %w", dst, iface, err)
		}
		r.LinkIndex = link.Attrs().Index
	case gateway.IsValid() && !gateway.IsUnspecified():
		r.Gw = net.IP(gateway.AsSlice())
	}
	err = h.RouteDel(r)
	if err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("delete route %s: %w", dst, err)
	}
	return nil
}

// DeleteHost removes a host route; one that is already gone is not an error.
func (t *netlinkTable) DeleteHost(ctx context.Context, dest netip.Addr) error {
	dest = dest.Unmap()
	return t.deleteUnicast(ctx, netip.PrefixFrom(dest, dest.BitLen()), netip.Addr{}, "")
}

// DeleteNet removes a network route given in the table's own notation.
func (t *netlinkTable) DeleteNet(ctx context.Context, destRaw, gatewayRaw, iface string) error {
	dst, err := parseRouteDest(destRaw)
	if err != nil {
		return fmt.Errorf("deleteNetRoute: %w", err)
	}
	gateway, _ := netip.ParseAddr(gatewayRaw) // not an address: no owning gateway
	return t.deleteUnicast(ctx, dst, gateway, iface)
}

// primaryDefault returns the default route the kernel prefers.
func (t *netlinkTable) primaryDefault(h *netlink.Handle) (netlink.Route, error) {
	routes, err := t.defaultRoutes(h)
	if err != nil {
		return netlink.Route{}, err
	}
	if len(routes) == 0 {
		return netlink.Route{}, fmt.Errorf("no default route to change")
	}
	return routes[0], nil
}

// replaceDefault swaps the preferred default route for r, keeping its metric
// and protocol so the replacement lands on that route (a different metric
// would add a second default beside it) and a DHCP client still recognises the
// route as its own.
func replaceDefault(h *netlink.Handle, cur netlink.Route, r *netlink.Route) error {
	r.Dst = ipNet(netip.PrefixFrom(netip.IPv4Unspecified(), 0))
	r.Table = unix.RT_TABLE_MAIN
	r.Type = unix.RTN_UNICAST
	r.Priority = cur.Priority
	r.Protocol = cur.Protocol
	return h.RouteReplace(r)
}

// ReplaceDefault points the existing default route at gateway without ever
// adding or deleting one, returning the kernel's error as is.
func (t *netlinkTable) ReplaceDefault(ctx context.Context, gateway netip.Addr) error {
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	cur, err := t.primaryDefault(h)
	if err != nil {
		return err
	}
	return replaceDefault(h, cur, &netlink.Route{Gw: net.IP(gateway.AsSlice())})
}

// ChangeDefaultStrict is ReplaceDefault with the failure named, so a failure
// leaves the existing default alone and says which change was refused.
func (t *netlinkTable) ChangeDefaultStrict(ctx context.Context, gateway netip.Addr) error {
	if err := t.ReplaceDefault(ctx, gateway); err != nil {
		return fmt.Errorf("change default route to %s: %w", gateway, err)
	}
	return nil
}

// ChangeDefault points the default route at gateway, adding one only when
// there is none to change. The default is never deleted first: if the add then
// failed, the machine would be left with no default route at all.
func (t *netlinkTable) ChangeDefault(ctx context.Context, gateway netip.Addr) error {
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	cur, err := t.primaryDefault(h)
	if err != nil {
		// No default to change: add one.
		if _, addErr := addUnicast(h, netip.PrefixFrom(netip.IPv4Unspecified(), 0), gateway, ""); addErr != nil {
			return fmt.Errorf("set default route to %s: %w", gateway, addErr)
		}
		return nil
	}
	if err := replaceDefault(h, cur, &netlink.Route{Gw: net.IP(gateway.AsSlice())}); err != nil {
		return fmt.Errorf("set default route to %s: %w", gateway, err)
	}
	return nil
}

// ChangeDefaultToInterface points the default route at a tunnel interface,
// restoring a VPN client's own default route. It only changes the route; on
// failure the existing default stays.
func (t *netlinkTable) ChangeDefaultToInterface(ctx context.Context, iface string) error {
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	link, err := h.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("restore default route: interface %s: %w", iface, err)
	}
	cur, err := t.primaryDefault(h)
	if err != nil {
		return fmt.Errorf("set default route to interface %s: %w", iface, err)
	}
	r := &netlink.Route{LinkIndex: link.Attrs().Index, Scope: netlink.SCOPE_LINK}
	if err := replaceDefault(h, cur, r); err != nil {
		return fmt.Errorf("set default route to interface %s: %w", iface, err)
	}
	return nil
}

// rejectRoute is the route that makes connections to addr fail at once: an
// unreachable /128, which answers every connect with "network is unreachable".
func rejectRoute(addr netip.Addr) *netlink.Route {
	return rejectPrefixRoute(netip.PrefixFrom(addr, 128))
}

// rejectPrefixRoute is rejectRoute for a whole network.
func rejectPrefixRoute(prefix netip.Prefix) *netlink.Route {
	return &netlink.Route{
		Dst:      ipNet(prefix),
		Family:   netlink.FAMILY_V6,
		Table:    unix.RT_TABLE_MAIN,
		Type:     unix.RTN_UNREACHABLE,
		Protocol: ownedProtocol,
	}
}

// AddIPv6RejectAll adds the reject route for every global IPv6 address.
func (t *netlinkTable) AddIPv6RejectAll(ctx context.Context) error {
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	if err := h.RouteAdd(rejectPrefixRoute(globalUnicastV6)); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add reject route %s: %w", globalUnicastV6, err)
	}
	return nil
}

// DeleteIPv6RejectAll removes that route, and never a real route to the same
// network: the delete names the unreachable type.
func (t *netlinkTable) DeleteIPv6RejectAll(ctx context.Context) error {
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	route := rejectPrefixRoute(globalUnicastV6)
	existing, err := listMain(h, netlink.FAMILY_V6, route, netlink.RT_FILTER_DST|netlink.RT_FILTER_TYPE)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return nil
	}
	if err := h.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("delete reject route %s: %w", globalUnicastV6, err)
	}
	return nil
}

// AddIPv6Reject adds a host route that makes connections to addr fail at once.
// A route that already exists is accepted, so a leftover of an earlier process
// is adopted.
func (t *netlinkTable) AddIPv6Reject(ctx context.Context, addr netip.Addr) error {
	if err := ValidateBlockableIPv6(addr); err != nil {
		return fmt.Errorf("AddIPv6Reject: %w", err)
	}
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	if err := h.RouteAdd(rejectRoute(addr)); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add reject route %s: %w", addr, err)
	}
	return nil
}

// DeleteIPv6Reject removes the reject host route for addr. A route that is
// already gone is not an error, and a real route to addr is never touched: the
// delete names the unreachable type.
func (t *netlinkTable) DeleteIPv6Reject(ctx context.Context, addr netip.Addr) error {
	if err := ValidateBlockableIPv6(addr); err != nil {
		return fmt.Errorf("DeleteIPv6Reject: %w", err)
	}
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	existing, err := listMain(h, netlink.FAMILY_V6, rejectRoute(addr), netlink.RT_FILTER_DST|netlink.RT_FILTER_TYPE)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return nil
	}
	if err := h.RouteDel(rejectRoute(addr)); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("delete reject route %s: %w", addr, err)
	}
	return nil
}
