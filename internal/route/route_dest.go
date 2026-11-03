package route

import (
	"fmt"
	"net/netip"
	"strings"
)

// parseRouteDest reads a destination in any notation the manager hands back
// from the table: "default", a CIDR (full, or the abbreviated "128.0/1"), or a
// bare address for a host route.
func parseRouteDest(raw string) (netip.Prefix, error) {
	if raw == "default" {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), nil
	}
	if p, ok := parseNetstatDest(raw); ok {
		return p, nil
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("unrecognised route destination %q", raw)
}

// StaticDestinations maps each destination the table holds a route of its own for to
// the interface that route leads through. An interface-scoped route overrides nothing,
// and a cloned one is a cache the kernel replaces, so neither counts.
func StaticDestinations(entries []RouteEntry) map[netip.Prefix]string {
	out := make(map[netip.Prefix]string, len(entries))
	for _, e := range entries {
		if strings.ContainsAny(e.Flags, "IW") {
			continue
		}
		if p, err := parseRouteDest(e.Destination); err == nil {
			out[p] = e.Interface
		}
	}
	return out
}
