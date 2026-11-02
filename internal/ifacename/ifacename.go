// Package ifacename answers questions that depend only on a network
// interface's name: whether it is well formed, and whether it is a tunnel a VPN
// client would own. Keeping one definition stops packages from disagreeing
// about which interfaces count as tunnels. The naming rules differ per OS and
// live in names_*.go.
package ifacename

import (
	"fmt"
	"strings"
)

// Validate checks that name is a well-formed interface name. The name reaches
// command arguments and file names, so anything unexpected is rejected.
func Validate(name string) error {
	if name == "" {
		return fmt.Errorf("interface name is empty")
	}
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid interface name %q: %s", name, nameHint)
	}
	return validateOS(name)
}

// IsTunnel reports whether name is a point-to-point tunnel interface a VPN
// client would own, never the LAN.
func IsTunnel(name string) bool { return isTunnel(name) }

// IsVPNDevice reports whether name is a tunnel device whose address range is a
// VPN's, not a directly connected network: the interfaces left out when the
// helper collects the LAN subnets it refuses to route into.
func IsVPNDevice(name string) bool { return isVPNDevice(name) }

func hasAnyPrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
