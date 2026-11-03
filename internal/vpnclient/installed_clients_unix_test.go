//go:build !windows

package vpnclient

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// fakeRoot is a scratch filesystem root with links resolved, since the scan
// resolves them too and macOS's temp directory is itself behind one.
func fakeRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func writeFile(t *testing.T, path, contents string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeExtension builds an app with one NetworkExtension and returns the app and
// the extension's executable.
func fakeExtension(t *testing.T, apps, app, extension, point string) (string, string) {
	t.Helper()
	bundle := filepath.Join(apps, app)
	ext := filepath.Join(bundle, "Contents", "PlugIns", extension+".appex")
	writeFile(t, filepath.Join(ext, "Contents", "Info.plist"), "bplist00\x01"+point+"\x02", 0o644)
	exe := writeFile(t, filepath.Join(ext, "Contents", "MacOS", extension), "\x7fbin", 0o755)
	writeFile(t, filepath.Join(bundle, "Contents", "MacOS", "Window"), "\x7fbin", 0o755)
	return bundle, exe
}

func ids(clients []Client) []string {
	out := make([]string, len(clients))
	for i, c := range clients {
		out[i] = c.ID
	}
	slices.Sort(out)
	return out
}

func TestScanMacFindsTunnelExtensionsAndCommandLineClients(t *testing.T) {
	root := fakeRoot(t)
	apps := filepath.Join(root, "Applications")
	_, wg := fakeExtension(t, apps, "WireGuard.app", "WireGuardNetworkExtension", packetTunnelExtensionPoint)
	// A content filter is a NetworkExtension too, but holds no tunnel.
	fakeExtension(t, apps, "Filter.app", "FilterExtension", "com.apple.networkextension.filter-data")
	aws := writeFile(t, filepath.Join(apps, "AWS VPN Client", "AWS VPN Client.app", "Contents", "Resources", "openvpn", "acvc-openvpn"), "\x7fbin", 0o755)
	_, home := fakeExtension(t, filepath.Join(root, "Users", "me", "Applications"), "Other.app", "Tunnel", packetTunnelExtensionPoint)

	// Homebrew's link, which resolves to the formula's stable path.
	keg := writeFile(t, filepath.Join(root, "opt", "homebrew", "Cellar", "openvpn", "2.6.8", "sbin", "openvpn"), "\x7fbin", 0o755)
	link := filepath.Join(root, "opt", "homebrew", "sbin", "openvpn")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keg, link); err != nil {
		t.Fatal(err)
	}

	got := ids(sortedUnique(scanMac(root)))
	want := []string{aws, FromPath(keg).ID, wg, home}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("scan = %v\nwant %v", got, want)
	}
}

func TestScanMacOnAnEmptyMachineFindsNothing(t *testing.T) {
	if got := scanMac(fakeRoot(t)); len(got) != 0 {
		t.Errorf("scan = %+v, want nothing", got)
	}
}

func TestAnExtensionWithoutOneClearExecutableIsNotGuessed(t *testing.T) {
	root := fakeRoot(t)
	ext := filepath.Join(root, "Odd.appex")
	writeFile(t, filepath.Join(ext, "Contents", "Info.plist"), packetTunnelExtensionPoint, 0o644)
	writeFile(t, filepath.Join(ext, "Contents", "MacOS", "one"), "x", 0o755)
	writeFile(t, filepath.Join(ext, "Contents", "MacOS", "two"), "x", 0o755)
	if exe, ok := macTunnelExtensionExe(ext); ok {
		t.Errorf("executable = %s, want none", exe)
	}
}

func TestResolveMacAcceptsAnAppItsWindowBinaryOrAProgram(t *testing.T) {
	root := fakeRoot(t)
	app, exe := fakeExtension(t, root, "WireGuard.app", "WireGuardNetworkExtension", packetTunnelExtensionPoint)
	program := writeFile(t, filepath.Join(root, "bin", "my-vpn"), "\x7fbin", 0o755)
	for chosen, want := range map[string]string{
		app: exe,
		filepath.Join(app, "Contents", "MacOS", "Window"):                            exe,
		filepath.Join(app, "Contents", "PlugIns", "WireGuardNetworkExtension.appex"): exe,
		program: program,
	} {
		got, err := resolveMacClient(chosen)
		if err != nil || got.ID != want {
			t.Errorf("resolve %s = %+v, %v, want %s", chosen, got, err, want)
		}
	}
}

func TestResolveMacRefusesWhatCouldNeverOwnATunnel(t *testing.T) {
	root := fakeRoot(t)
	plain, _ := fakeExtension(t, root, "Filter.app", "FilterExtension", "com.apple.networkextension.filter-data")
	for _, chosen := range []string{
		plain,
		filepath.Join(root, "missing.app"),
		writeFile(t, filepath.Join(root, "notes.txt"), "text", 0o644),
		writeFile(t, filepath.Join(root, "wg-quick"), "#!/bin/bash\n", 0o755),
	} {
		if got, err := resolveMacClient(chosen); !errors.Is(err, ErrNotAVPNClient) {
			t.Errorf("resolve %s = %+v, %v, want ErrNotAVPNClient", chosen, got, err)
		}
	}
}

func TestScanLinuxFindsEachClientOnceUnderItsRealIdentity(t *testing.T) {
	root := fakeRoot(t)
	writeFile(t, filepath.Join(root, "usr", "sbin", "openvpn"), "\x7fbin", 0o755)
	writeFile(t, filepath.Join(root, "usr", "bin", "wg"), "\x7fbin", 0o755)
	writeFile(t, filepath.Join(root, "usr", "local", "bin", "wireguard-go"), "\x7fbin", 0o755)
	writeFile(t, filepath.Join(root, awsClientTunnel), "\x7fbin", 0o755)
	writeFile(t, filepath.Join(root, openVPN3Service), "\x7fbin", 0o755)
	writeFile(t, filepath.Join(root, "usr", "bin", "not-executable-openvpn"), "x", 0o644)

	got := sortedUnique(scanLinux(root))
	want := []Client{
		{ID: awsClientTunnel, Name: "AWS VPN Client"},
		{ID: "/usr/sbin/openvpn", Name: "OpenVPN"},
		{ID: openVPN3Service, Name: "OpenVPN 3"},
		KernelWireGuard,
		{ID: "/usr/local/bin/wireguard-go", Name: "WireGuard"},
	}
	wantIDs, gotIDs := ids(want), ids(got)
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("scan = %+v\nwant %+v", got, want)
	}
	for _, c := range got {
		i := slices.IndexFunc(want, func(w Client) bool { return w.ID == c.ID })
		if want[i].Name != c.Name {
			t.Errorf("%s named %q, want %q", c.ID, c.Name, want[i].Name)
		}
	}
}

func TestResolveLinuxMapsFrontEndsToWhatOwnsTheTunnel(t *testing.T) {
	root := fakeRoot(t)
	tunnel := writeFile(t, filepath.Join(root, awsClientTunnel), "\x7fbin", 0o755)
	service := writeFile(t, filepath.Join(root, openVPN3Service), "\x7fbin", 0o755)
	for chosen, want := range map[string]string{
		writeFile(t, filepath.Join(root, "opt", "awsvpnclient", "AWS VPN Client"), "\x7fbin", 0o755): awsClientTunnel,
		writeFile(t, filepath.Join(root, "usr", "bin", "openvpn3"), "\x7fbin", 0o755):                openVPN3Service,
		writeFile(t, filepath.Join(root, "usr", "bin", "wg-quick"), "#!/bin/bash\n", 0o755):          KernelWireGuard.ID,
		writeFile(t, filepath.Join(root, "usr", "sbin", "openvpn"), "\x7fbin", 0o755):                "/usr/sbin/openvpn",
		tunnel:  awsClientTunnel,
		service: openVPN3Service,
	} {
		got, err := resolveLinuxClient(root, chosen)
		if err != nil || got.ID != want {
			t.Errorf("resolve %s = %+v, %v, want %s", chosen, got, err, want)
		}
	}
}

func TestResolveLinuxRefusesWhatCouldNeverOwnATunnel(t *testing.T) {
	root := fakeRoot(t)
	for _, chosen := range []string{
		filepath.Join(root, "missing"),
		writeFile(t, filepath.Join(root, "notes"), "text", 0o644),
		writeFile(t, filepath.Join(root, "start-vpn.sh"), "#!/bin/sh\n", 0o755),
	} {
		if got, err := resolveLinuxClient(root, chosen); !errors.Is(err, ErrNotAVPNClient) {
			t.Errorf("resolve %s = %+v, %v, want ErrNotAVPNClient", chosen, got, err)
		}
	}
}

func TestResolveInstalledNeedsAnAbsolutePath(t *testing.T) {
	if _, err := ResolveInstalled("relative/vpn"); !errors.Is(err, ErrNotAVPNClient) {
		t.Errorf("err = %v, want ErrNotAVPNClient", err)
	}
}
