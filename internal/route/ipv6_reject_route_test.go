package route

import (
	"net/netip"
	"testing"
)

func TestValidateBlockableIPv6(t *testing.T) {
	for _, ok := range []string{"2001:db8::1", "2606:4700::6810:84e5", "3fff::1"} {
		if err := ValidateBlockableIPv6(netip.MustParseAddr(ok)); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"::1", "::", "fe80::1", "fe80::1%en0", "ff02::1", "fd00::1", "fc00::1", "::ffff:1.2.3.4", "1.2.3.4", "4000::1", "64:ff9b::1"} {
		if err := ValidateBlockableIPv6(netip.MustParseAddr(bad)); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	if ValidateBlockableIPv6(netip.Addr{}) == nil {
		t.Error("the zero address must be refused")
	}
}
