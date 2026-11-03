package vpnclient

import (
	"errors"
	"testing"
)

const (
	winAWSApp    = `C:\Program Files\Amazon\AWS VPN Client\AWSVPNClient.exe`
	winAWSTunnel = `C:\Program Files\Amazon\AWS VPN Client\Service\Resources\openvpn\acvc-openvpn.exe`
	winConnect   = `C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe`
	winConnector = `C:\Program Files\OpenVPN Connect\ovpnconnector.exe`
	winWireGuard = `C:\Program Files\WireGuard\wireguard.exe`
	winWg        = `C:\Program Files\WireGuard\wg.exe`
	winOpenVPN   = `C:\Program Files\OpenVPN\bin\openvpn.exe`
	winOpenGUI   = `C:\Program Files\OpenVPN\bin\openvpn-gui.exe`
)

var winRoots = []string{`C:\Program Files`, `C:\Windows`}

func TestInstalledWindowsClientsMatchWhatTheOwnerSearchReports(t *testing.T) {
	got := sortedUnique(installedWindowsClients([]string{
		winAWSApp, winAWSTunnel, winConnect, winConnector, winWireGuard, winWg, winOpenVPN, winOpenGUI,
	}))
	want := []Client{
		{ID: normalizeWindowsPath(winAWSTunnel), Name: "AWS VPN Client"},
		{ID: normalizeWindowsPath(winOpenVPN), Name: "OpenVPN"},
		{ID: normalizeWindowsPath(winConnector), Name: "OpenVPN Connect"},
		{ID: normalizeWindowsPath(winWireGuard), Name: "WireGuard"},
	}
	if len(got) != len(want) {
		t.Fatalf("clients = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("client %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestResolvingAWindowsFrontEndGivesTheProgramThatOwnsTheTunnel(t *testing.T) {
	installed := installedWindowsClients([]string{winAWSTunnel, winConnector, winOpenVPN, winWireGuard})
	cases := map[string]string{
		winAWSApp:    winAWSTunnel,
		winConnect:   winConnector,
		winOpenGUI:   winOpenVPN,
		winWireGuard: winWireGuard,
	}
	for chosen, want := range cases {
		got, err := resolveWindowsClient(chosen, winRoots, installed)
		if err != nil {
			t.Errorf("resolve %s: %v", chosen, err)
			continue
		}
		if got.ID != normalizeWindowsPath(want) {
			t.Errorf("resolve %s = %s, want %s", chosen, got.ID, normalizeWindowsPath(want))
		}
	}
}

func TestResolvingRefusesWhatTheOwnerSearchWouldIgnore(t *testing.T) {
	for _, chosen := range []string{
		`C:\Users\me\Downloads\openvpn.exe`,
		`C:\Program Files\Notepad\notepad.exe`,
		`C:\Program Files\OpenVPN\bin\openvpn-gui.exe`, // no openvpn.exe found to stand for it
	} {
		if got, err := resolveWindowsClient(chosen, winRoots, nil); !errors.Is(err, ErrNotAVPNClient) {
			t.Errorf("resolve %s = %+v, %v, want ErrNotAVPNClient", chosen, got, err)
		}
	}
}
