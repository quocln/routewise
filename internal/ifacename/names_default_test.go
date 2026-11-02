//go:build !linux && !windows

package ifacename

import "testing"

func TestIsVPNDeviceIsUtunOnly(t *testing.T) {
	if !IsVPNDevice("utun4") || IsVPNDevice("tun0") || IsVPNDevice("en0") {
		t.Error("only utun is a VPN device")
	}
}

func TestIsTunnel(t *testing.T) {
	for name, want := range map[string]bool{
		"utun4": true, "ipsec0": true, "tun0": true, "tap1": true,
		"en0": false, "bridge100": false, "ppp0": false, "lo0": false, "awdl0": false, "": false,
	} {
		if got := IsTunnel(name); got != want {
			t.Errorf("IsTunnel(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, name := range []string{"en0", "utun14", "bridge100", "lo0"} {
		if err := Validate(name); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"", "en", "0", "EN0", "en0; rm", "en 0", "../en0", "en0\n", "utun-1"} {
		if err := Validate(name); err == nil {
			t.Errorf("Validate(%q) accepted an invalid name", name)
		}
	}
}
