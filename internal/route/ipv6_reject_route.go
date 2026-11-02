package route

import (
	"fmt"
	"net/netip"
)

// globalUnicastV6 is the only IPv6 range a reject route may name (2000::/3).
var globalUnicastV6 = netip.MustParsePrefix("2000::/3")

// ValidateBlockableIPv6 reports whether addr may get a reject route: a global
// unicast IPv6 address. Loopback, link-local, unique-local, multicast,
// unspecified, IPv4-mapped, and zoned addresses are refused, so a reject route
// can never cut off the machine's own network or a local service.
func ValidateBlockableIPv6(addr netip.Addr) error {
	switch {
	case !addr.IsValid():
		return fmt.Errorf("invalid IPv6 address")
	case addr.Zone() != "":
		return fmt.Errorf("%s: zoned addresses cannot be blocked", addr)
	case !addr.Is6() || addr.Is4In6():
		return fmt.Errorf("%s is not an IPv6 address", addr)
	case addr.IsLoopback(), addr.IsLinkLocalUnicast(), addr.IsMulticast(), addr.IsUnspecified(), addr.IsPrivate():
		return fmt.Errorf("%s is not a global unicast address", addr)
	case !globalUnicastV6.Contains(addr):
		return fmt.Errorf("%s is outside 2000::/3", addr)
	}
	return nil
}
