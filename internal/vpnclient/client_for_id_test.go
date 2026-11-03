package vpnclient

import (
	"runtime"
	"testing"
)

func TestClientForIDKeepsTheIDAndNamesTheClientAsThisOSWould(t *testing.T) {
	if got := ClientForID(KernelWireGuard.ID); got != KernelWireGuard {
		t.Errorf("kernel WireGuard = %+v", got)
	}
	switch runtime.GOOS {
	case "linux":
		id := "/opt/awsvpnclient/Service/Resources/openvpn/acvc-openvpn"
		if got := ClientForID(id); got.ID != id || got.Name != "AWS VPN Client" {
			t.Errorf("client = %+v", got)
		}
	case "windows":
		id := `c:\program files\wireguard\wireguard.exe`
		if got := ClientForID(id); got.ID != id || got.Name != "WireGuard" {
			t.Errorf("client = %+v", got)
		}
	default:
		id := "/Applications/WireGuard.app/Contents/PlugIns/X.appex/Contents/MacOS/X"
		if got := ClientForID(id); got.ID != id || got.Name != "WireGuard" {
			t.Errorf("client = %+v", got)
		}
	}
}
