//go:build windows

package daemon

// Tunnel interface names the tests use: the two managed tunnels, a tunnel
// RouteWise does not manage and the tunnel an older journal gives the default
// back to. Each is a "wg" alias, which Windows' name rules treat as a tunnel
// without an adapter to look up.
const (
	wgIface             = "wg9"
	awsIface            = "wg7"
	unmanagedTunIface   = "wg3"
	otherUnmanagedIface = "wg4"
	olderTunIface       = "wg5"
)
