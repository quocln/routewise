//go:build !linux && !windows

package daemon

// Tunnel interface names the tests use: the two managed tunnels, a tunnel
// RouteWise does not manage and the tunnel an older journal gives the default
// back to. Each is a name this OS treats as a VPN tunnel.
const (
	wgIface             = "utun9"
	awsIface            = "utun7"
	unmanagedTunIface   = "utun3"
	otherUnmanagedIface = "utun4"
	olderTunIface       = "utun5"
)
