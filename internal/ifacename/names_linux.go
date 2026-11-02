//go:build linux

package ifacename

import (
	"fmt"
	"regexp"
)

// maxNameLen is the kernel's IFNAMSIZ (16) minus the terminating NUL.
const maxNameLen = 15

// validName is the conservative subset of what the kernel accepts: letters,
// digits, '-', '_' and '.', so names such as eth0, eth0.100, wg-work and
// rwtun0 pass while anything a command line or file name could misread does
// not. The kernel itself also forbids '/', whitespace and ':'.
var validName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

const nameHint = "may only contain letters, digits, '-', '_' and '.' (e.g., eth0, wg0, wg-work)"

// tunnelPrefixes are the interface families of point-to-point tunnels a VPN
// client owns: OpenVPN (tun, tap), the kernel and userspace WireGuard (wg),
// the helper's own tunnels (rwtun) and IPsec VTIs. ppp is left out on purpose:
// a PPPoE uplink is the LAN, not a VPN. A name is only a hint on Linux, since
// OpenVPN's `dev corp0` or NetworkManager's connection-named devices are
// tunnels too; the link type (link_kind_linux.go) settles those.
var tunnelPrefixes = []string{"tun", "tap", "wg", "rwtun", "ipsec"}

// vpnDevicePrefixes: every tunnel family above carries a VPN's address range.
var vpnDevicePrefixes = tunnelPrefixes

func validateOS(name string) error {
	if len(name) > maxNameLen {
		return fmt.Errorf("invalid interface name %q: longer than %d characters", name, maxNameLen)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid interface name %q", name)
	}
	return nil
}

func isTunnel(name string) bool {
	return hasAnyPrefix(name, tunnelPrefixes) || linkIsTunnel(name)
}

func isVPNDevice(name string) bool {
	return hasAnyPrefix(name, vpnDevicePrefixes) || linkIsTunnel(name)
}
