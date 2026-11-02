package route

import (
	"fmt"
	"net/netip"
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
