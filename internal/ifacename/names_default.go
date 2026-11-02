//go:build !linux && !windows

package ifacename

import "regexp"

// validName matches macOS interface names such as en0, utun14, bridge100,
// awdl0, lo0, gif0, stf0 and llw0.
var validName = regexp.MustCompile(`^[a-z]+[0-9]+$`)

const nameHint = "must match pattern [a-z]+[0-9]+ (e.g., en0, utun14)"

// tunnelPrefixes are the interface families of point-to-point tunnels a VPN
// client owns. ppp is left out on purpose: a PPPoE uplink is the LAN, not a
// VPN.
var tunnelPrefixes = []string{"utun", "ipsec", "tun", "tap"}

// vpnDevicePrefixes: only utun networks are VPN address ranges here.
var vpnDevicePrefixes = []string{"utun"}

func validateOS(string) error { return nil }

func isTunnel(name string) bool { return hasAnyPrefix(name, tunnelPrefixes) }

func isVPNDevice(name string) bool { return hasAnyPrefix(name, vpnDevicePrefixes) }
