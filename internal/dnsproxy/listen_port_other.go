//go:build !windows

package dnsproxy

// ListenPort is an unprivileged-range port: the resolver files (macOS) and the
// systemd-resolved link (Linux) both carry a port, so 53 is not needed.
const ListenPort = 53053

// FallbackHosts is empty: nothing else is needed where the port is free to move.
var FallbackHosts []string
