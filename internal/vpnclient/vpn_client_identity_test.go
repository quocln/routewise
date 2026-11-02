package vpnclient

import "testing"

func TestDisplayNameUsesTheAppBundle(t *testing.T) {
	cases := map[string]string{
		"/Applications/WireGuard.app/Contents/PlugIns/WireGuardNetworkExtension.appex/Contents/MacOS/WireGuardNetworkExtension": "WireGuard",
		"/Applications/AWS VPN Client/AWS VPN Client.app/Contents/Resources/openvpn/acvc-openvpn":                               "AWS VPN Client",
		"/opt/homebrew/sbin/openvpn":     "openvpn",
		"/opt/homebrew/bin/wireguard-go": "wireguard-go",
	}
	for path, want := range cases {
		if got := FromPath(path); got.Name != want || got.ID != path {
			t.Errorf("FromPath(%q) = %+v, want name %q and the path as ID", path, got, want)
		}
	}
}

func TestHomebrewClientsKeepTheirIdentityAcrossUpgrades(t *testing.T) {
	cases := map[string]string{
		"/usr/local/Cellar/wireguard-go/0.0.20230223/bin/wireguard-go": "/usr/local/opt/wireguard-go/bin/wireguard-go",
		"/opt/homebrew/Cellar/openvpn/2.6.12/sbin/openvpn":             "/opt/homebrew/opt/openvpn/sbin/openvpn",
		"/opt/homebrew/sbin/openvpn":                                   "/opt/homebrew/sbin/openvpn",
		"/Applications/Outline.app/Contents/MacOS/Outline":             "/Applications/Outline.app/Contents/MacOS/Outline",
	}
	for path, want := range cases {
		if got := FromPath(path).ID; got != want {
			t.Errorf("FromPath(%q).ID = %q, want %q", path, got, want)
		}
	}
	if FromPath("/usr/local/Cellar/wireguard-go/0.0.20230223/bin/wireguard-go").Name != "wireguard-go" {
		t.Error("the display name must stay the binary's name")
	}
}
