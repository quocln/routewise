package winnet

import (
	"net/netip"
	"testing"
)

func TestAdapterKindFromRecordedDescriptions(t *testing.T) {
	cases := []struct {
		name string
		a    Adapter
		want Kind
	}{
		{"wintun", Adapter{Alias: "wg0", Description: "Wintun Userspace Tunnel", IfType: 53}, KindWintun},
		{"wireguard-nt", Adapter{Alias: "office", Description: "WireGuard Tunnel", IfType: 53}, KindWireGuard},
		{"tap", Adapter{Alias: "Local Area Connection 3", Description: "TAP-Windows Adapter V9", IfType: 6}, KindTAP},
		{"tap numbered", Adapter{Alias: "Ethernet 2", Description: "TAP-Windows Adapter V9 #2", IfType: 6}, KindTAP},
		{"openvpn tap6", Adapter{Alias: "OpenVPN TAP", Description: "OpenVPN TAP-Windows6", IfType: 6}, KindTAP},
		{"aws", Adapter{Alias: "Local Area Connection 2", Description: "AWS VPN Client TAP-Windows Adapter V9", IfType: 6}, KindTAP},
		{"dco", Adapter{Alias: "OpenVPN Data Channel Offload", Description: "OpenVPN Data Channel Offload", IfType: 6}, KindDCO},
		{"dco driver name", Adapter{Alias: "Ethernet 3", Description: "ovpn-dco Virtual Adapter", IfType: 6}, KindDCO},
		{"ethernet", Adapter{Alias: "Ethernet", Description: "Intel(R) Ethernet Connection (7) I219-V", IfType: 6}, KindNone},
		{"wifi", Adapter{Alias: "Wi-Fi", Description: "Intel(R) Wi-Fi 6 AX201 160MHz", IfType: 71}, KindNone},
		{"hyper-v", Adapter{Alias: "vEthernet (Default Switch)", Description: "Hyper-V Virtual Ethernet Adapter", IfType: 6}, KindNone},
		{"wifi direct", Adapter{Alias: "Local Area Connection* 3", Description: "Microsoft Wi-Fi Direct Virtual Adapter #2", IfType: 71}, KindNone},
		{"loopback", Adapter{Alias: "Loopback Pseudo-Interface 1", Description: "Software Loopback Interface 1", IfType: 24}, KindNone},
		{"teredo", Adapter{Alias: "Teredo Tunneling Pseudo-Interface", Description: "Teredo Tunneling Pseudo-Interface", IfType: 131, TunnelType: 14}, KindNone},
		{"isatap", Adapter{Alias: "isatap.x", Description: "Microsoft ISATAP Adapter", IfType: 131, TunnelType: 13}, KindNone},
		{"other tunnel", Adapter{Alias: "Corp", Description: "Contoso Virtual Tunnel", IfType: 131, TunnelType: 1}, KindOtherTunnel},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.a.Kind(); got != c.want {
				t.Fatalf("Kind() = %d, want %d", got, c.want)
			}
			if got, want := c.a.IsVPNTunnel(), c.want != KindNone; got != want {
				t.Fatalf("IsVPNTunnel() = %v, want %v", got, want)
			}
		})
	}
}

func TestRouteOnLinkAndEffectiveMetric(t *testing.T) {
	r := Route{Adapter: Adapter{Metric: 25}, Metric: 5, NextHop: netip.IPv4Unspecified()}
	if !r.OnLink() || r.Gateway().IsValid() {
		t.Fatal("0.0.0.0 next hop is on-link")
	}
	if got := r.Effective(); got != 30 {
		t.Fatalf("Effective() = %d, want 30", got)
	}
	r.NextHop = netip.MustParseAddr("192.168.1.1")
	if r.OnLink() || r.Gateway() != netip.MustParseAddr("192.168.1.1") {
		t.Fatal("a real next hop is a gateway")
	}
	if !(Route{}).OnLink() {
		t.Fatal("an invalid next hop is on-link")
	}
}
