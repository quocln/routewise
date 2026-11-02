package ifacename

import (
	"strings"
	"testing"
)

func TestValidateWindowsAlias(t *testing.T) {
	for _, name := range []string{
		"Ethernet", "Ethernet 2", "Wi-Fi", "Local Area Connection* 3", "vEthernet (WSL)",
		"OpenVPN Data Channel Offload", "AWS VPN Client TAP-Windows Adapter V9", "Loopback Pseudo-Interface 1",
		"wg-work", "rwtun0", "Bluetooth Network Connection #2", "以太网", "Kablosuz Ağ Bağlantısı",
		strings.Repeat("a", 256),
	} {
		if err := validateWindowsAlias(name); err != nil {
			t.Errorf("validateWindowsAlias(%q) = %v, want nil", name, err)
		}
	}
	for name, why := range map[string]string{
		"":                       "empty",
		"   ":                    "blank",
		strings.Repeat("a", 257): "too long",
		strings.Repeat("😀", 129): "too long in UTF-16 units",
		"Eth\x00ernet":           "NUL",
		"Eth\nernet":             "newline",
		"Eth\x7fernet":           "DEL",
		`Eth"ernet`:              "double quote",
		"Bob's Wi-Fi":            "single quote",
		`Eth\ernet`:              "backslash",
		"a/b":                    "slash",
		"..\\x":                  "path climb",
		"bad\xffutf8":            "invalid UTF-8",
	} {
		if err := validateWindowsAlias(name); err == nil {
			t.Errorf("validateWindowsAlias(%q) accepted a name that is %s", name, why)
		}
	}
	// 128 astral characters are 256 UTF-16 units: the limit's edge.
	if err := validateWindowsAlias(strings.Repeat("😀", 128)); err != nil {
		t.Errorf("256 UTF-16 units rejected: %v", err)
	}
}

func TestWindowsTunnelHints(t *testing.T) {
	for _, name := range []string{
		"OpenVPN Data Channel Offload", "OpenVPN Wintun", "OpenVPN TAP-Windows6", "openvpn tap",
		"AWS VPN Client TAP-Windows Adapter V9", "Wintun Userspace Tunnel", "WireGuard Tunnel",
		"wg0", "wg-work", "WG_home", "wg", "rwtun0", "RouteWise Tunnel", "tun0", "tap1", "TAP-Windows Adapter V9",
	} {
		if !isWindowsTunnel(name) || !isWindowsVPNDevice(name) {
			t.Errorf("%q should be a tunnel and a VPN device", name)
		}
	}
	for _, name := range []string{
		"Ethernet", "Ethernet 2", "Wi-Fi", "Local Area Connection* 3", "Local Area Connection",
		"vEthernet (WSL)", "vEthernet (Default Switch)", "Loopback Pseudo-Interface 1",
		"Bluetooth Network Connection", "Laptop Wi-Fi", "Tapestry LAN", "wgx", "Tunnelbear LAN", "PPPoE", "",
	} {
		if isWindowsTunnel(name) || isWindowsVPNDevice(name) {
			t.Errorf("%q should not be a tunnel", name)
		}
	}
}
