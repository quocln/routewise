package vpnclient

import (
	"slices"
	"strings"
	"testing"

	"github.com/quocln/routewise/internal/winnet"
)

func TestFromWindowsExeNamesTheProducts(t *testing.T) {
	cases := []struct {
		exe      string
		wantID   string
		wantName string
	}{
		{`C:\Program Files\WireGuard\wireguard.exe`, `c:\program files\wireguard\wireguard.exe`, "WireGuard"},
		{`C:\Program Files\OpenVPN\bin\openvpn.exe`, `c:\program files\openvpn\bin\openvpn.exe`, "OpenVPN"},
		{`C:\Program Files\OpenVPN\bin\openvpn-gui.exe`, `c:\program files\openvpn\bin\openvpn-gui.exe`, "OpenVPN GUI"},
		{`C:\Program Files\OpenVPN\bin\openvpnserv.exe`, `c:\program files\openvpn\bin\openvpnserv.exe`, "OpenVPN"},
		{`C:\Program Files\OpenVPN Connect\ovpnconnector.exe`, `c:\program files\openvpn connect\ovpnconnector.exe`, "OpenVPN Connect"},
		{`C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe`, `c:\program files\openvpn connect\openvpnconnect.exe`, "OpenVPN Connect"},
		{`C:\Program Files\Amazon\AWS VPN Client\Service\Resources\openvpn\acvc-openvpn.exe`, `c:\program files\amazon\aws vpn client\service\resources\openvpn\acvc-openvpn.exe`, "AWS VPN Client"},
		{`C:\Program Files\Amazon\AWS VPN Client\AWSVPNClient.exe`, `c:\program files\amazon\aws vpn client\awsvpnclient.exe`, "AWS VPN Client"},
		{`C:\Tools\wintunthing.exe`, `c:\tools\wintunthing.exe`, "wintunthing"},
	}
	for _, c := range cases {
		got := FromWindowsExe(c.exe)
		if got.ID != c.wantID || got.Name != c.wantName {
			t.Errorf("FromWindowsExe(%q) = %+v, want {%s %s}", c.exe, got, c.wantID, c.wantName)
		}
	}
}

func TestNormalizeWindowsPathIsStableAcrossSpellingsAndVersions(t *testing.T) {
	same := []string{
		`C:\Program Files\OpenVPN\bin\openvpn.exe`,
		`c:\PROGRAM FILES\openvpn\BIN\OpenVPN.EXE`,
		`\\?\C:\Program Files\OpenVPN\bin\openvpn.exe`,
		`C:/Program Files/OpenVPN/bin/openvpn.exe`,
	}
	want := normalizeWindowsPath(same[0])
	for _, p := range same {
		if got := normalizeWindowsPath(p); got != want {
			t.Errorf("normalize(%q) = %q, want %q", p, got, want)
		}
	}

	versions := []string{
		`C:\Users\kim\scoop\apps\openvpn\2.6.8\bin\openvpn.exe`,
		`C:\Users\kim\scoop\apps\openvpn\2.6.9\bin\openvpn.exe`,
		`C:\Users\kim\scoop\apps\openvpn\v2.7.0.1\bin\openvpn.exe`,
	}
	for _, p := range versions {
		if got := normalizeWindowsPath(p); got != `c:\users\kim\scoop\apps\openvpn\bin\openvpn.exe` {
			t.Errorf("normalize(%q) = %q, want the version directory dropped", p, got)
		}
	}
	// The drive and the file name are never taken for a version.
	if got := normalizeWindowsPath(`C:\tools\1.2`); got != `c:\tools\1.2` {
		t.Errorf("final component dropped: %q", got)
	}
}

func TestWireGuardTunnelFromServiceCommandLines(t *testing.T) {
	cases := []struct {
		cmd      string
		wantExe  string
		wantName string
		ok       bool
	}{
		{`"C:\Program Files\WireGuard\wireguard.exe" /tunnelservice "C:\Program Files\WireGuard\Data\Configurations\office.conf.dpapi"`,
			`C:\Program Files\WireGuard\wireguard.exe`, "office", true},
		{`"C:\Program Files\WireGuard\wireguard.exe" /TunnelService "C:\Program Files\WireGuard\Data\Configurations\Home VPN-2.conf"`,
			`C:\Program Files\WireGuard\wireguard.exe`, "Home VPN-2", true},
		{`C:\WG\wireguard.exe /tunnelservice C:\WG\Data\Configurations\wg0.conf.dpapi`, `C:\WG\wireguard.exe`, "wg0", true},
		{`"C:\Program Files\WireGuard\wireguard.exe"`, "", "", false},
		{`"C:\Program Files\WireGuard\wireguard.exe" /managerservice`, "", "", false},
		{`"C:\Program Files\Other\svc.exe" /tunnelservice "C:\x\a.conf.dpapi"`, "", "", false},
		{`"C:\Program Files\WireGuard\wireguard.exe" /tunnelservice "C:\x\notaconfig.txt"`, "", "", false},
	}
	for _, c := range cases {
		exe, name, ok := wireGuardTunnel(c.cmd)
		if exe != c.wantExe || name != c.wantName || ok != c.ok {
			t.Errorf("wireGuardTunnel(%q) = %q %q %v", c.cmd, exe, name, ok)
		}
	}
}

func TestSplitWindowsCommandLine(t *testing.T) {
	got := splitWindowsCommandLine(`"C:\Program Files\x.exe" --config "C:\a b\c.ovpn"  --flag  ""`)
	want := []string{`C:\Program Files\x.exe`, "--config", `C:\a b\c.ovpn`, "--flag", ""}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

var (
	tapAdapter = winnet.Adapter{Alias: "Local Area Connection 3", GUID: "{A1B2C3D4-0000-1111-2222-333344445555}", Description: "TAP-Windows Adapter V9", IfType: 6}
	dcoAdapter = winnet.Adapter{Alias: "OpenVPN Data Channel Offload", GUID: "{11111111-2222-3333-4444-555555555555}", Description: "OpenVPN Data Channel Offload", IfType: 6}
	wgAdapter  = winnet.Adapter{Alias: "office", Description: "WireGuard Tunnel", IfType: 53}
	wtAdapter  = winnet.Adapter{Alias: "office", Description: "Wintun Userspace Tunnel", IfType: 53}
)

const (
	openVPNExe   = `C:\Program Files\OpenVPN\bin\openvpn.exe`
	awsExe       = `C:\Program Files\Amazon\AWS VPN Client\Service\Resources\openvpn\acvc-openvpn.exe`
	awsGUIExe    = `C:\Program Files\Amazon\AWS VPN Client\AWSVPNClient.exe`
	connectorExe = `C:\Program Files\OpenVPN Connect\ovpnconnector.exe`
	connectExe   = `C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe`
	wireGuardExe = `C:\Program Files\WireGuard\wireguard.exe`
	wgService    = `"C:\Program Files\WireGuard\wireguard.exe" /tunnelservice "C:\Program Files\WireGuard\Data\Configurations\office.conf.dpapi"`
)

func TestPickWindowsClientSingleProduct(t *testing.T) {
	cases := []struct {
		name     string
		adapter  winnet.Adapter
		procs    []Process
		wantName string
		wantID   string
	}{
		{"openvpn on tap", tapAdapter, []Process{{Path: openVPNExe, CmdLine: `openvpn.exe --config c.ovpn`}, {Path: wireGuardExe}}, "OpenVPN", `c:\program files\openvpn\bin\openvpn.exe`},
		{"aws processes are one client", tapAdapter, []Process{{Path: awsGUIExe}, {Path: awsExe}}, "AWS VPN Client", `c:\program files\amazon\aws vpn client\service\resources\openvpn\acvc-openvpn.exe`},
		{"openvpn connect prefers the connector", dcoAdapter, []Process{{Path: connectExe}, {Path: connectorExe}}, "OpenVPN Connect", `c:\program files\openvpn connect\ovpnconnector.exe`},
		{"dco is openvpn", dcoAdapter, []Process{{Path: openVPNExe}}, "OpenVPN", `c:\program files\openvpn\bin\openvpn.exe`},
		{"wireguard tunnel service", wgAdapter, []Process{{Path: wireGuardExe, CmdLine: wgService}}, "WireGuard", `c:\program files\wireguard\wireguard.exe`},
		{"wintun used by openvpn", wtAdapter, []Process{{Path: openVPNExe}}, "OpenVPN", `c:\program files\openvpn\bin\openvpn.exe`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := PickWindowsClient(c.adapter, c.procs)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != c.wantName || got.ID != c.wantID {
				t.Fatalf("got %+v, want {%s %s}", got, c.wantID, c.wantName)
			}
		})
	}
}

func TestPickWindowsClientIgnoresOtherTunnelsAndTheUI(t *testing.T) {
	other := Process{Path: wireGuardExe, CmdLine: strings.Replace(wgService, "office", "home", 1)}
	ui := Process{Path: wireGuardExe, CmdLine: `"C:\Program Files\WireGuard\wireguard.exe"`}
	if _, err := PickWindowsClient(wgAdapter, []Process{other, ui}); err == nil {
		t.Fatal("another tunnel's service and the UI do not own office")
	}
	got, err := PickWindowsClient(wgAdapter, []Process{other, ui, {Path: wireGuardExe, CmdLine: wgService}})
	if err != nil || got.Name != "WireGuard" {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestPickWindowsClientNeedsTheDriversProducts(t *testing.T) {
	// A wireguard-nt adapter is never an OpenVPN client's, even with openvpn running.
	if _, err := PickWindowsClient(wgAdapter, []Process{{Path: openVPNExe}}); err == nil {
		t.Fatal("openvpn does not own a WireGuard adapter")
	}
	// A TAP adapter is never WireGuard's.
	if _, err := PickWindowsClient(tapAdapter, []Process{{Path: wireGuardExe, CmdLine: wgService}}); err == nil {
		t.Fatal("wireguard does not own a TAP adapter")
	}
	if _, err := PickWindowsClient(winnet.Adapter{Alias: "Ethernet", Description: "Intel(R) Ethernet", IfType: 6}, []Process{{Path: openVPNExe}}); err == nil {
		t.Fatal("a LAN adapter has no VPN client")
	}
	if _, err := PickWindowsClient(tapAdapter, nil); err == nil {
		t.Fatal("no process, no client")
	}
}

func TestPickWindowsClientDisambiguatesByDevNodeAndNeverGuesses(t *testing.T) {
	procs := []Process{
		{Path: openVPNExe, CmdLine: `openvpn.exe --config home.ovpn`},
		{Path: awsExe, CmdLine: `acvc-openvpn.exe --dev-node "Local Area Connection 3"`},
	}
	got, err := PickWindowsClient(tapAdapter, procs)
	if err != nil || got.Name != "AWS VPN Client" {
		t.Fatalf("got %+v %v, want the process that names the adapter", got, err)
	}

	byGUID := []Process{
		{Path: openVPNExe, CmdLine: `openvpn.exe --dev-node {A1B2C3D4-0000-1111-2222-333344445555}`},
		{Path: awsExe},
	}
	if got, err = PickWindowsClient(tapAdapter, byGUID); err != nil || got.Name != "OpenVPN" {
		t.Fatalf("got %+v %v, want OpenVPN by GUID (matched ignoring case)", got, err)
	}

	_, err = PickWindowsClient(tapAdapter, []Process{{Path: openVPNExe}, {Path: awsExe}})
	if err == nil || !strings.Contains(err.Error(), "cannot tell") {
		t.Fatalf("got %v, want an ambiguity error", err)
	}
}

func TestIsClientExe(t *testing.T) {
	for exe, want := range map[string]bool{
		openVPNExe: true, awsExe: true, connectorExe: true, wireGuardExe: true,
		`C:\Windows\System32\svchost.exe`: false, `C:\Program Files\Mozilla Firefox\firefox.exe`: false,
	} {
		if got := IsClientExe(exe); got != want {
			t.Errorf("IsClientExe(%q) = %v, want %v", exe, got, want)
		}
	}
}

func TestUnderTrustedRootRejectsFoldersAUserControls(t *testing.T) {
	roots := []string{`C:\Program Files`, `C:\Program Files (x86)\`, `C:\Windows`}
	for path, want := range map[string]bool{
		`C:\Program Files\OpenVPN\bin\openvpn.exe`:       true,
		`c:\program files (x86)\wireguard\wireguard.exe`: true,
		`\\?\C:\Windows\System32\openvpn.exe`:            true,
		`C:\a\openvpn.exe`:                               false,
		`C:\Program Files Evil\openvpn.exe`:              false,
		`C:\Users\bob\Program Files\openvpn.exe`:         false,
		`openvpn.exe`:                                    false,
	} {
		if got := underTrustedRoot(path, roots); got != want {
			t.Errorf("underTrustedRoot(%q) = %v, want %v", path, got, want)
		}
	}
	if underTrustedRoot(`C:\x\openvpn.exe`, nil) {
		t.Error("no roots trust nothing")
	}
}

func TestMayBeClientExeKeepsEveryClientExecutable(t *testing.T) {
	for _, name := range []string{"openvpn.exe", "OpenVPNConnect.exe", "ovpnconnector.exe", "wireguard.exe", "wireguard-go.exe", "AWSVPNClient.exe", "acvc-openvpn.exe", "ACVC.GUIService.exe"} {
		if !mayBeClientExe(name) {
			t.Errorf("%s was filtered out before the path check", name)
		}
	}
	for _, name := range []string{"chrome.exe", "svchost.exe", "explorer.exe"} {
		if mayBeClientExe(name) {
			t.Errorf("%s should not be inspected", name)
		}
	}
}
