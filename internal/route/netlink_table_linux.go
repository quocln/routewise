//go:build linux

package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/quocln/routewise/internal/ifacename"
)

// ownedProtocol is the rtm_protocol value stamped on every route RouteWise
// adds, so `ip route show proto 245` lists exactly what it owns and a sweep can
// tell its routes from the ones a DHCP client, NetworkManager or a VPN client
// installed. 245 (0xf5) is in the range the kernel leaves to administrators and
// is not named in iproute2's rt_protos, so it cannot be mistaken for `static`
// (4), `boot` (3) or a routing daemon.
const ownedProtocol netlink.RouteProtocol = 0xf5

// maxDumpAttempts bounds how often a route dump is repeated when the kernel
// reports the table changed while it was being read.
const maxDumpAttempts = 3

// netlinkTable is the Table of Linux: it reads and writes the main routing
// table of the network namespace its netlink socket belongs to, with no
// external process involved. The socket is opened on first use and shared by
// every method; the netlink handle serialises requests on it.
type netlinkTable struct {
	open func() (*netlink.Handle, error)

	mu sync.Mutex
	h  *netlink.Handle
}

// newNetlinkTable returns a table whose handle comes from open, which lets
// tests point it at another network namespace.
func newNetlinkTable(open func() (*netlink.Handle, error)) *netlinkTable {
	return &netlinkTable{open: open}
}

// systemTable is the table the daemon drives on Linux: the main routing table
// of its own network namespace, over rtnetlink.
func systemTable() Table {
	return newNetlinkTable(func() (*netlink.Handle, error) {
		return netlink.NewHandle(unix.NETLINK_ROUTE)
	})
}

// handle returns the shared netlink handle, opening it on first use. A done
// context fails before any request is made, since netlink calls cannot be
// interrupted once sent.
func (t *netlinkTable) handle(ctx context.Context) (*netlink.Handle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.h != nil {
		return t.h, nil
	}
	h, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open netlink socket: %w", err)
	}
	t.h = h
	return h, nil
}

// close releases the netlink socket. Production keeps it for the life of the
// process; tests that create their own namespace call it on cleanup.
func (t *netlinkTable) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.h != nil {
		t.h.Close()
		t.h = nil
	}
}

// listMain dumps the main table routes of one family that match filter and
// mask (RT_FILTER_TABLE is always added), repeating the dump when the kernel
// says the table moved underneath it.
func listMain(h *netlink.Handle, family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	filter.Table = unix.RT_TABLE_MAIN
	mask |= netlink.RT_FILTER_TABLE
	var routes []netlink.Route
	var err error
	for range maxDumpAttempts {
		routes, err = h.RouteListFiltered(family, filter, mask)
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	return routes, nil
}

// listUnicast is listMain for the IPv4 unicast routes the manager reasons about,
// without the ones that name no output interface.
func listUnicast(h *netlink.Handle) ([]netlink.Route, error) {
	routes, err := listMain(h, netlink.FAMILY_V4, &netlink.Route{Type: unix.RTN_UNICAST}, netlink.RT_FILTER_TYPE)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(routes, hasNoOutputInterface), nil
}

// hasNoOutputInterface reports whether r leaves through no interface the
// library can name: a route that uses a nexthop object (`ip nexthop`) carries
// only an id, which this netlink version does not decode. Such a route is
// skipped (and logged) rather than failing every read of the table.
func hasNoOutputInterface(r netlink.Route) bool {
	if r.LinkIndex != 0 || len(r.MultiPath) > 0 {
		return false
	}
	slog.Debug("skipping route without an output interface (nexthop object?)", "dst", r.Dst, "gateway", r.Gw)
	return true
}

// nexthop returns the gateway and interface index a route sends traffic to.
// A multipath route answers with its first hop.
func nexthop(r netlink.Route) (net.IP, int) {
	if len(r.MultiPath) > 0 {
		return r.MultiPath[0].Gw, r.MultiPath[0].LinkIndex
	}
	return r.Gw, r.LinkIndex
}

// ifaceNamer turns interface indexes into names inside the table's own
// namespace (net.InterfaceByIndex would answer for the process's), remembering
// answers for one operation.
type ifaceNamer struct {
	h       *netlink.Handle
	names   map[int]string
	tunnels map[int]bool
}

func newIfaceNamer(h *netlink.Handle) *ifaceNamer {
	return &ifaceNamer{h: h, names: make(map[int]string), tunnels: make(map[int]bool)}
}

func (n *ifaceNamer) name(index int) (string, error) {
	if name, ok := n.names[index]; ok {
		return name, nil
	}
	link, err := n.h.LinkByIndex(index)
	if err != nil {
		return "", fmt.Errorf("interface %d: %w", index, err)
	}
	name := link.Attrs().Name
	n.names[index] = name
	n.tunnels[index] = ifacename.IsTunnelLinkType(link.Type()) || isTunnelInterface(name)
	return name, nil
}

// isTunnel reports whether the link at index is a tunnel by its type, as read
// through the table's own handle (so a table bound to another namespace answers
// for that namespace), or by the name families a VPN client uses.
func (n *ifaceNamer) isTunnel(index int) bool {
	if _, err := n.name(index); err != nil {
		return false
	}
	return n.tunnels[index]
}

// addrOf converts a netlink address, which is nil for "no gateway", to a
// netip.Addr that is invalid in that case.
func addrOf(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// isDefaultRoute reports whether r is a default route: no destination, or one
// with a zero-length prefix.
func isDefaultRoute(r netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, _ := r.Dst.Mask.Size()
	return ones == 0
}

// defaultRoutes returns the IPv4 default routes of the main table, the one
// with the lowest metric first: that is the route the kernel prefers, so it is
// the global default.
func (t *netlinkTable) defaultRoutes(h *netlink.Handle) ([]netlink.Route, error) {
	routes, err := listUnicast(h)
	if err != nil {
		return nil, err
	}
	routes = slices.DeleteFunc(routes, func(r netlink.Route) bool { return !isDefaultRoute(r) })
	slices.SortStableFunc(routes, func(a, b netlink.Route) int { return a.Priority - b.Priority })
	return routes, nil
}

// Snapshot reads the IPv4 unicast routes of the main table in the notation the
// BSD table uses: "default", a bare address for a host route, otherwise a
// masked CIDR; an interface route's gateway is "link#<index>".
func (t *netlinkTable) Snapshot(ctx context.Context) ([]RouteEntry, error) {
	h, err := t.handle(ctx)
	if err != nil {
		return nil, err
	}
	routes, err := listUnicast(h)
	if err != nil {
		return nil, err
	}
	namer := newIfaceNamer(h)
	entries := make([]RouteEntry, 0, len(routes))
	for _, r := range routes {
		gw, index := nexthop(r)
		iface, err := namer.name(index)
		if err != nil {
			return nil, err
		}
		e := RouteEntry{Destination: "default", Gateway: fmt.Sprintf("link#%d", index), Flags: "U", Interface: iface}
		if gw != nil {
			e.Gateway = gw.String()
			e.Flags += "G"
		}
		if r.Dst != nil {
			if ones, bits := r.Dst.Mask.Size(); ones == bits {
				e.Destination = r.Dst.IP.String()
				e.Flags += "H"
			} else if ones > 0 {
				e.Destination = r.Dst.String()
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Default returns the gateway and interface of the global default route.
func (t *netlinkTable) Default(ctx context.Context) (netip.Addr, string, error) {
	h, err := t.handle(ctx)
	if err != nil {
		return netip.Addr{}, "", err
	}
	gw, iface, _, err := t.globalDefault(h, newIfaceNamer(h))
	return gw, iface, err
}

// globalDefault is Default that also reports the interface index, so a caller
// holding the namer can ask what kind of link the default leaves through.
func (t *netlinkTable) globalDefault(h *netlink.Handle, namer *ifaceNamer) (netip.Addr, string, int, error) {
	routes, err := t.defaultRoutes(h)
	if err != nil {
		return netip.Addr{}, "", 0, fmt.Errorf("get default route: %w", err)
	}
	if len(routes) == 0 {
		return netip.Addr{}, "", 0, fmt.Errorf("default route not found in route table")
	}
	gw, index := nexthop(routes[0])
	iface, err := namer.name(index)
	if err != nil {
		return netip.Addr{}, "", 0, fmt.Errorf("get default route: %w", err)
	}
	return addrOf(gw), iface, index, nil
}

// DefaultGateway returns the gateway of the global default route.
func (t *netlinkTable) DefaultGateway(ctx context.Context) (netip.Addr, error) {
	gw, _, err := t.Default(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	if !gw.IsValid() {
		return netip.Addr{}, fmt.Errorf("default route has no gateway IP")
	}
	return gw, nil
}

// LocalGateway returns the LAN gateway and its interface even while a VPN owns
// the global default route: a tunnel's default route is skipped, and among
// several LAN defaults the one on prefer wins, then the lowest metric.
func (t *netlinkTable) LocalGateway(ctx context.Context, prefer string) (netip.Addr, string, error) {
	h, herr := t.handle(ctx)
	if herr != nil {
		return netip.Addr{}, "", herr
	}
	namer := newIfaceNamer(h)
	gw, iface, index, err := t.globalDefault(h, namer)
	if err == nil && gw.IsValid() && !namer.isTunnel(index) {
		return gw, iface, nil
	}

	routes, listErr := t.defaultRoutes(h)
	if listErr != nil {
		return netip.Addr{}, "", errors.Join(err, listErr)
	}
	var firstGW netip.Addr
	var firstIface string
	for _, r := range routes {
		rgw, index := nexthop(r)
		ip := addrOf(rgw)
		if !ip.Is4() {
			continue
		}
		name, nerr := namer.name(index)
		if nerr != nil || namer.isTunnel(index) {
			continue
		}
		if prefer != "" && name == prefer {
			return ip, name, nil
		}
		if !firstGW.IsValid() {
			firstGW, firstIface = ip, name
		}
	}
	if firstGW.IsValid() {
		return firstGW, firstIface, nil
	}
	if err != nil {
		return netip.Addr{}, "", err
	}
	return netip.Addr{}, "", fmt.Errorf("no LAN default route found")
}

// Lookup asks the kernel which interface and gateway traffic to dest leaves
// through. The gateway is invalid for a route that points at an interface.
func (t *netlinkTable) Lookup(ctx context.Context, dest netip.Addr) (string, netip.Addr, error) {
	if !dest.IsValid() {
		return "", netip.Addr{}, fmt.Errorf("lookup route: invalid address")
	}
	h, err := t.handle(ctx)
	if err != nil {
		return "", netip.Addr{}, err
	}
	routes, err := h.RouteGet(net.IP(dest.Unmap().AsSlice()))
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("lookup route for %s: %w", dest, err)
	}
	if len(routes) == 0 {
		return "", netip.Addr{}, fmt.Errorf("lookup route for %s: no route", dest)
	}
	gw, index := nexthop(routes[0])
	iface, err := newIfaceNamer(h).name(index)
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("lookup route for %s: %w", dest, err)
	}
	return iface, addrOf(gw), nil
}

// DropClonedLinkLayer does nothing: Linux keeps neighbour entries apart from
// routes, so no route is ever cloned for a destination.
func (t *netlinkTable) DropClonedLinkLayer(context.Context, netip.Addr) {}

// IsUnreachable reports whether err means the gateway is not on any connected
// network: the kernel refuses a route through such a gateway with ENETUNREACH.
func (t *netlinkTable) IsUnreachable(err error) bool {
	return errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH)
}
