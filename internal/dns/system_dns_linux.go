package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	resolvedName = "org.freedesktop.resolve1"
	resolvedPath = "/org/freedesktop/resolve1"

	// resolvedTimeout bounds one read of resolved's state so a wedged resolved
	// cannot stall a VPN connect.
	resolvedTimeout = 3 * time.Second
)

// errLinkGone marks a link resolved still listed but the kernel no longer has.
var errLinkGone = errors.New("link is gone")

// dnsServerEx is one element of resolved's DNSEx property, a(iiayqs).
type dnsServerEx struct {
	Ifindex int32
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}

// routeDomain is one element of a link's Domains property, a(sb).
type routeDomain struct {
	Domain      string
	RoutingOnly bool
}

// systemDNSConfig returns the DNS servers systemd-resolved holds, global and
// per link, in the `scutil --dns` format parseResolverBlocks reads. Per-link
// servers are what VPN clients publish: openvpn and the AWS VPN Client through
// update-systemd-resolved, wg-quick through resolvconf.
func systemDNSConfig(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, resolvedTimeout)
	defer cancel()

	// A connection whose context ends is closed, which is the only way to bound
	// dialing and the bus handshake.
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("connect to the system bus: %w", err)
	}
	defer conn.Close()
	manager := conn.Object(resolvedName, resolvedPath)

	var servers []dnsServerEx
	if err := getProperty(ctx, manager, "org.freedesktop.resolve1.Manager", "DNSEx", &servers); err != nil {
		return "", fmt.Errorf("read systemd-resolved servers: %w", err)
	}

	entries := make([]resolvedEntry, 0, len(servers))
	links := make(map[int]resolvedLink)
	for _, s := range servers {
		addr, ok := netip.AddrFromSlice(s.Address)
		if !ok {
			continue
		}
		idx := int(s.Ifindex)
		entries = append(entries, resolvedEntry{ifindex: idx, addr: addr.Unmap(), port: s.Port})
		if _, seen := links[idx]; idx == 0 || seen {
			continue
		}
		link, err := readLink(ctx, conn, manager, idx)
		if errors.Is(err, errLinkGone) {
			// A VPN going down removes its link while the servers are read.
			entries = entries[:len(entries)-1]
			continue
		}
		if err != nil {
			return "", err
		}
		links[idx] = link
	}
	return renderResolvedConfig(entries, links), nil
}

// readLink reads the name and routing role of the link with index idx.
func readLink(ctx context.Context, conn *dbus.Conn, manager dbus.BusObject, idx int) (resolvedLink, error) {
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		return resolvedLink{}, fmt.Errorf("link %d: %w: %v", idx, errLinkGone, err)
	}
	var path dbus.ObjectPath
	if err := manager.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.GetLink", 0, int32(idx)).Store(&path); err != nil {
		return resolvedLink{}, fmt.Errorf("systemd-resolved link %s: %w", iface.Name, err)
	}
	obj := conn.Object(resolvedName, path)

	link := resolvedLink{name: iface.Name}
	if err := getProperty(ctx, obj, "org.freedesktop.resolve1.Link", "DefaultRoute", &link.defaultRoute); err != nil {
		return resolvedLink{}, fmt.Errorf("systemd-resolved link %s: %w", iface.Name, err)
	}
	var domains []routeDomain
	if err := getProperty(ctx, obj, "org.freedesktop.resolve1.Link", "Domains", &domains); err != nil {
		return resolvedLink{}, fmt.Errorf("systemd-resolved link %s: %w", iface.Name, err)
	}
	for _, d := range domains {
		link.domains = append(link.domains, routeName(d))
		// "~." routes every name to the link, which makes it a default route
		// whatever DefaultRoute says.
		if d.RoutingOnly && d.Domain == "." {
			link.defaultRoute = true
		}
	}
	return link, nil
}

// routeName writes a routing-only domain with resolved's "~" prefix.
func routeName(d routeDomain) string {
	if d.RoutingOnly {
		return "~" + d.Domain
	}
	return d.Domain
}

// getProperty reads one D-Bus property into dst, honoring ctx.
func getProperty(ctx context.Context, obj dbus.BusObject, iface, name string, dst any) error {
	var v dbus.Variant
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name).Store(&v); err != nil {
		return err
	}
	return v.Store(dst)
}
