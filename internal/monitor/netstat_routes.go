package monitor

import (
	"bufio"
	"bytes"
	"net/netip"
	"strings"

	rtpkg "github.com/quocln/routewise/internal/route"
)

// parseNetstatRoutes reads `netstat -rn -f inet` output (BSD format) into
// route entries. Rows that are not a route (headers, section titles), rows
// whose gateway cannot belong to a tunnel route, and rows VPN detection does
// not read (see detectorDest) are skipped. The file has no
// OS constraint so its tests run everywhere; only macOS calls it in
// production.
func parseNetstatRoutes(output []byte) []routeEntry {
	var entries []routeEntry
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		dest, ok := parseNetstatDest(fields[0])
		if !ok || !detectorDest(dest) {
			continue
		}
		gateway := fields[1]
		netif := fields[3]
		if !isTunnelGateway(gateway, netif) {
			continue
		}
		entries = append(entries, routeEntry{
			Dest:    dest,
			Gateway: gatewayAddr(gateway),
			Iface:   netif,
			Scoped:  strings.Contains(fields[2], "I"),
			// A managed tunnel's owner is found through its utun control
			// socket, which ipsec, tun and tap lack.
			Tunnel: strings.HasPrefix(netif, "utun"),
		})
	}
	return entries
}

// parseNetstatDest parses a Destination column: "default", a network such as
// "0/1" or "128.0/1" (see route.ParseNetstatDest), or a host.
func parseNetstatDest(dest string) (netip.Prefix, bool) {
	if dest == "default" {
		return defaultPrefix, true
	}
	if !strings.Contains(dest, "/") {
		addr, err := netip.ParseAddr(dest)
		if err != nil || !addr.Is4() {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(addr, 32), true
	}
	return rtpkg.ParseNetstatDest(dest)
}

// isTunnelGateway reports whether a route's gateway column can belong to a
// tunnel route on netif: an IPv4 next hop, the interface itself, or a link#N
// reference to it.
func isTunnelGateway(gateway, netif string) bool {
	if addr, err := netip.ParseAddr(gateway); err == nil {
		return addr.Is4()
	}
	return gateway == netif || strings.HasPrefix(gateway, "link#")
}

// gatewayAddr returns the next hop of a tunnel route, or an invalid address
// when the route points at the interface rather than at a next hop.
func gatewayAddr(gateway string) netip.Addr {
	addr, err := netip.ParseAddr(gateway)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}
