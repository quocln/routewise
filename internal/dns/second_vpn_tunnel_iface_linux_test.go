//go:build linux

package dns

// secondVPNTunnelIface is the tunnel the office-and-second-VPN resolver
// fixture binds a resolver to; this OS must recognise it as a tunnel.
const secondVPNTunnelIface = "wg9"
