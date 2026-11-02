package route

import (
	"net"
	"net/netip"
	"strings"

	"github.com/quocln/routewise/internal/ifacename"
)

// ValidateInterfaceName checks if an interface name is valid.
// Returns error with details if invalid, nil if valid.
func ValidateInterfaceName(name string) error { return ifacename.Validate(name) }

// splitTunnelDestAliases maps the notations macOS netstat/route are known to
// print or accept for the AWS Client VPN catch-all routes to one canonical
// form, so ownership checks and restoration compare like with like.
var splitTunnelDestAliases = map[string]string{
	"0/1":         "0.0.0.0/1",
	"0.0.0.0/1":   "0.0.0.0/1",
	"128/1":       "128.0.0.0/1",
	"128.0/1":     "128.0.0.0/1",
	"128.0.0.0/1": "128.0.0.0/1",
}

// canonicalSplitTunnelDest reports whether raw is one of the AWS VPN
// catch-all destinations and, if so, returns its canonical form.
func canonicalSplitTunnelDest(raw string) (string, bool) {
	canon, ok := splitTunnelDestAliases[raw]
	return canon, ok
}

// interfaceIsUp reports whether the named interface exists and is up.
func interfaceIsUp(name string) bool {
	iface, err := net.InterfaceByName(name)
	return err == nil && iface.Flags&net.FlagUp != 0
}

// isTunnelInterface reports whether name is a point-to-point tunnel interface
// a VPN client would own, never the LAN.
func isTunnelInterface(name string) bool { return ifacename.IsTunnel(name) }

// findRoute returns the first entry whose Destination matches dest exactly.
func findRoute(entries []RouteEntry, dest string) (RouteEntry, bool) {
	for _, e := range entries {
		if e.Destination == dest {
			return e, true
		}
	}
	return RouteEntry{}, false
}

// findSplitTunnelRoutes returns every entry whose destination canonicalizes
// to one of the AWS VPN catch-all routes.
func findSplitTunnelRoutes(entries []RouteEntry) []RouteEntry {
	var found []RouteEntry
	for _, e := range entries {
		if _, ok := canonicalSplitTunnelDest(e.Destination); ok {
			found = append(found, e)
		}
	}
	return found
}

// sameGateway compares two gateway strings as read from the kernel table.
// Point-to-point interfaces (e.g. utun routes) print the interface name in
// the gateway column instead of an IP, so a plain string compare after a
// best-effort IP parse handles both forms correctly.
func sameGateway(a, b string) bool {
	if a == b {
		return true
	}
	ipA, errA := netip.ParseAddr(a)
	ipB, errB := netip.ParseAddr(b)
	if errA == nil && errB == nil {
		return ipA == ipB
	}
	return false
}

// parseNetstatDest reads a network destination as `netstat -rn` prints it: a
// full "10.20.0.0/16", or the abbreviated "10.20/16" macOS uses when trailing
// octets are zero. A host, "default", or anything else reports false.
func parseNetstatDest(raw string) (netip.Prefix, bool) {
	addr, bitsText, ok := strings.Cut(raw, "/")
	if !ok {
		return netip.Prefix{}, false
	}
	octets := strings.Split(addr, ".")
	if len(octets) == 0 || len(octets) > 4 {
		return netip.Prefix{}, false
	}
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	p, err := netip.ParsePrefix(strings.Join(octets, ".") + "/" + bitsText)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// ParseNetstatDest is parseNetstatDest for other packages that read the same
// notation, so there is one reader of it.
func ParseNetstatDest(raw string) (netip.Prefix, bool) { return parseNetstatDest(raw) }
