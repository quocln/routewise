//go:build linux

package daemon

// Tunnel interface names the tests use: the two managed tunnels, a tunnel
// RouteWise does not manage and the tunnel an older journal gives the default
// back to. Each is a name this OS treats as a VPN tunnel.
const (
	wgIface             = "wg9"
	awsIface            = "tun7"
	unmanagedTunIface   = "wg3"
	otherUnmanagedIface = "wg4"
	olderTunIface       = "wg5"
)
