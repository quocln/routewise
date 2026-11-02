package resolverfiles

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/vishvananda/netlink"
)

// linkAddress is the address given to the dummy link. Resolved ignores a link
// that has no address, and a link-local /32 adds no route to the main table
// and cannot clash with a network the machine is on.
var linkAddress = netip.MustParsePrefix("169.254.53.53/32")

const (
	resolvedName = "org.freedesktop.resolve1"
	resolvedPath = "/org/freedesktop/resolve1"
	managerIface = "org.freedesktop.resolve1.Manager"
	// dbusCallLimit bounds one call to resolved, and configureLimit the whole of
	// Configure (connecting included). The daemon holds its mutation lock while
	// it applies resolver files, so a wedged bus or resolved must cost seconds,
	// never stall every route change behind it.
	dbusCallLimit  = 3 * time.Second
	configureLimit = 6 * time.Second
)

// systemdResolved is the resolvedBackend of a Linux host running
// systemd-resolved. It talks to resolved over D-Bus rather than running
// resolvectl: the calls are typed, need no PATH lookup by a root daemon, and
// the same bus delivers the signal that resolved restarted. The link itself is
// created over netlink, with no dependency on iproute2.
type systemdResolved struct{}

func newResolvedBackend() resolvedBackend { return systemdResolved{} }

// dnsServerEx is one element of SetLinkDNSEx's a(iayqs) argument.
type dnsServerEx struct {
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}

// routeDomain is one element of SetLinkDomains' a(sb) argument.
type routeDomain struct {
	Domain      string
	RoutingOnly bool
}

func (systemdResolved) Configure(server netip.AddrPort, routeDomains []string) error {
	ifindex, err := ensureDummyLink()
	if err != nil {
		return err
	}

	// The connection lives no longer than ctx: the library has no deadline for
	// dialing, authenticating or saying hello, but closes a connection whose
	// context ends, which fails whichever of those is blocked.
	ctx, cancel := context.WithTimeout(context.Background(), configureLimit)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("connect to the system bus: %w", err)
	}
	defer conn.Close()
	manager := conn.Object(resolvedName, resolvedPath)

	family := int32(2) // AF_INET
	if server.Addr().Is6() {
		family = 10 // AF_INET6
	}
	domains := make([]routeDomain, len(routeDomains))
	for i, d := range routeDomains {
		domains[i] = routeDomain{Domain: d, RoutingOnly: true}
	}

	// DNSOverTLS and DNSSEC are off for this link: the forwarder speaks plain
	// DNS and a strict global setting would otherwise make every query fail.
	calls := []struct {
		method string
		args   []any
	}{
		{"SetLinkDNSEx", []any{[]dnsServerEx{{Family: family, Address: server.Addr().AsSlice(), Port: server.Port()}}}},
		{"SetLinkDomains", []any{domains}},
		{"SetLinkDefaultRoute", []any{false}},
		{"SetLinkDNSOverTLS", []any{"no"}},
		{"SetLinkDNSSEC", []any{"no"}},
	}
	for _, c := range calls {
		callCtx, cancelCall := context.WithTimeout(ctx, dbusCallLimit)
		call := manager.CallWithContext(callCtx, managerIface+"."+c.method, 0, append([]any{int32(ifindex)}, c.args...)...)
		cancelCall()
		if call.Err != nil {
			return fmt.Errorf("%s on %s: %w", c.method, LinkName, call.Err)
		}
	}
	return nil
}

// FlushSystemCache empties systemd-resolved's cache. Without resolved it fails,
// since there is no other cache RouteWise knows how to empty.
func FlushSystemCache(ctx context.Context) error {
	// As in Configure, the context bounds the connection, not only the call.
	ctx, cancel := context.WithTimeout(ctx, configureLimit)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("connect to the system bus: %w", err)
	}
	defer conn.Close()

	callCtx, cancelCall := context.WithTimeout(ctx, dbusCallLimit)
	defer cancelCall()
	if call := conn.Object(resolvedName, resolvedPath).CallWithContext(callCtx, managerIface+".FlushCaches", 0); call.Err != nil {
		return fmt.Errorf("FlushCaches: %w", call.Err)
	}
	return nil
}

// ensureDummyLink creates the link if needed, gives it its address, brings it
// up, and returns its index. A link of that name that is not a dummy link is
// someone else's and is left alone.
func ensureDummyLink() (int, error) {
	link, err := netlink.LinkByName(LinkName)
	var missing netlink.LinkNotFoundError
	switch {
	case errors.As(err, &missing):
		link = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: LinkName}}
		if err := netlink.LinkAdd(link); err != nil {
			return 0, fmt.Errorf("create link %s: %w", LinkName, err)
		}
		if link, err = netlink.LinkByName(LinkName); err != nil {
			return 0, fmt.Errorf("look up link %s: %w", LinkName, err)
		}
	case err != nil:
		return 0, fmt.Errorf("look up link %s: %w", LinkName, err)
	}
	if _, ok := link.(*netlink.Dummy); !ok {
		return 0, fmt.Errorf("link %s exists and is a %s link, not RouteWise's", LinkName, link.Type())
	}

	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   linkAddress.Addr().AsSlice(),
		Mask: net.CIDRMask(linkAddress.Bits(), 32),
	}}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return 0, fmt.Errorf("address link %s: %w", LinkName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return 0, fmt.Errorf("bring up link %s: %w", LinkName, err)
	}
	return link.Attrs().Index, nil
}

func (systemdResolved) Remove() error {
	link, err := netlink.LinkByName(LinkName)
	var missing netlink.LinkNotFoundError
	if errors.As(err, &missing) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up link %s: %w", LinkName, err)
	}
	if _, ok := link.(*netlink.Dummy); !ok {
		return nil // not RouteWise's
	}
	if err := netlink.LinkDel(link); err != nil && !errors.As(err, &missing) {
		return fmt.Errorf("delete link %s: %w", LinkName, err)
	}
	return nil
}

func (systemdResolved) WatchRestart(ctx context.Context, fn func()) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("connect to the system bus: %w", err)
	}
	defer conn.Close()
	if err := conn.AddMatchSignal(
		dbus.WithMatchSender("org.freedesktop.DBus"),
		dbus.WithMatchObjectPath("/org/freedesktop/DBus"),
		dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"),
		dbus.WithMatchArg(0, resolvedName),
	); err != nil {
		return fmt.Errorf("watch %s: %w", resolvedName, err)
	}
	signals := make(chan *dbus.Signal, 8)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sig, ok := <-signals:
			if !ok {
				return errors.New("system bus connection closed")
			}
			if sig.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(sig.Body) != 3 {
				continue
			}
			// Body is name, old owner, new owner: a non-empty new owner is
			// resolved coming up.
			if name, _ := sig.Body[0].(string); name != resolvedName {
				continue
			}
			if owner, _ := sig.Body[2].(string); owner != "" {
				fn()
			}
		}
	}
}
