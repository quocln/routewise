// Package winnet describes Windows network adapters and IPv4 routes in OS
// neutral types and classifies adapters as VPN tunnels. The rules live in plain
// Go so they are tested on every platform; reading the live tables through the
// IP Helper API is the Windows-only part (reader_windows.go).
package winnet

import (
	"net/netip"
	"strings"
)

// IF_TYPE values (ipifcons.h) that matter for classification.
const (
	ifTypeSoftwareLoopback = 24
	ifTypeTunnel           = 131
)

// TUNNEL_TYPE values (ifdef.h) of the Microsoft pseudo-interfaces that are
// never a third-party VPN: 6to4, ISATAP, Teredo and IP-HTTPS.
const (
	tunnelType6to4    = 11
	tunnelTypeISATAP  = 13
	tunnelTypeTeredo  = 14
	tunnelTypeIPHTTPS = 15
)

// MIB_IPPROTO values of a route's Protocol.
const (
	// ProtocolLocal marks routes the stack derived from an address: the
	// interface's own address, its connected subnet, broadcast and multicast.
	ProtocolLocal = 2
	// ProtocolNetMgmt marks routes added through the API or `route add`.
	ProtocolNetMgmt = 3
)

// Kind is the family of tunnel driver behind an adapter.
type Kind int

const (
	// KindNone is an adapter that is not a VPN tunnel: Ethernet, Wi-Fi,
	// loopback, Hyper-V, Bluetooth and the Microsoft tunnel pseudo-interfaces.
	KindNone Kind = iota
	// KindWireGuard is a wireguard-nt adapter ("WireGuard Tunnel").
	KindWireGuard
	// KindWintun is a Wintun adapter ("Wintun Userspace Tunnel"): wireguard-go,
	// OpenVPN 2.5+, OpenVPN Connect and RouteWise's own tunnels.
	KindWintun
	// KindTAP is a TAP-Windows adapter ("TAP-Windows Adapter V9"): OpenVPN, AWS
	// VPN Client.
	KindTAP
	// KindDCO is an OpenVPN Data Channel Offload adapter.
	KindDCO
	// KindOtherTunnel is an adapter of type IF_TYPE_TUNNEL that no keyword
	// above names.
	KindOtherTunnel
)

// Adapter is one network interface as the IP Helper API reports it.
type Adapter struct {
	// Index is the interface index, LUID the locally unique interface ID.
	Index uint32
	LUID  uint64
	// GUID is the interface GUID in braces, as TAP-Windows names its device.
	GUID string
	// Alias is the friendly name ("Ethernet", "Wi-Fi", "Local Area Connection*
	// 3"), the name RouteWise uses for an interface everywhere.
	Alias string
	// Description is the driver's description ("Wintun Userspace Tunnel").
	Description string
	// IfType and TunnelType are the IF_TYPE and TUNNEL_TYPE values.
	IfType     uint32
	TunnelType uint32
	// Up is true when the interface is operationally up.
	Up bool
	// Metric is the IPv4 interface metric added to every route's own metric.
	Metric uint32
}

// IsLoopback reports whether a is the software loopback interface.
func (a Adapter) IsLoopback() bool { return a.IfType == ifTypeSoftwareLoopback }

// Kind classifies a by its driver description, then by interface type. A
// description is matched case-insensitively. Names of the VPN products are
// matched on purpose: Windows has no flag that says "this adapter is a VPN",
// and a TAP or Wintun adapter reports itself as Ethernet or a proprietary
// virtual type.
func (a Adapter) Kind() Kind {
	if a.IsLoopback() {
		return KindNone
	}
	d := strings.ToLower(a.Description)
	switch {
	case strings.Contains(d, "wireguard"):
		return KindWireGuard
	case strings.Contains(d, "wintun"):
		return KindWintun
	case strings.Contains(d, "data channel offload"), strings.Contains(d, "ovpn-dco"):
		return KindDCO
	case strings.Contains(d, "tap-windows"), strings.Contains(d, "tap-win32"), strings.Contains(d, "tap0901"),
		strings.Contains(d, "openvpn"), strings.Contains(d, "aws vpn"):
		return KindTAP
	}
	if a.IfType == ifTypeTunnel && !strings.HasPrefix(d, "microsoft") {
		switch a.TunnelType {
		case tunnelType6to4, tunnelTypeISATAP, tunnelTypeTeredo, tunnelTypeIPHTTPS:
			return KindNone
		}
		return KindOtherTunnel
	}
	return KindNone
}

// IsVPNTunnel reports whether a is a tunnel adapter a VPN client would own.
func (a Adapter) IsVPNTunnel() bool { return a.Kind() != KindNone }

// Route is one IPv4 or IPv6 route with the adapter it leaves through.
type Route struct {
	Adapter Adapter
	Dest    netip.Prefix
	// NextHop is the gateway; invalid or unspecified (0.0.0.0, ::) for an
	// on-link route.
	NextHop netip.Addr
	// Metric is the route's own metric; the preference of a route is Metric
	// plus the interface metric (Effective).
	Metric   uint32
	Protocol uint32
}

// OnLink reports whether r points straight at its interface.
func (r Route) OnLink() bool { return !r.NextHop.IsValid() || r.NextHop.IsUnspecified() }

// Gateway returns the next hop, or an invalid address for an on-link route.
func (r Route) Gateway() netip.Addr {
	if r.OnLink() {
		return netip.Addr{}
	}
	return r.NextHop.Unmap()
}

// Effective is the metric Windows ranks routes by: the route's own metric plus
// its interface's metric.
func (r Route) Effective() uint32 { return r.Metric + r.Adapter.Metric }
