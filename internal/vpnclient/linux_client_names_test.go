package vpnclient

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestFromLinuxExeNamesKnownClients(t *testing.T) {
	cases := []struct {
		exe      string
		wantID   string
		wantName string
	}{
		{"/opt/awsvpnclient/Service/Resources/openvpn/acvc-openvpn", "/opt/awsvpnclient/Service/Resources/openvpn/acvc-openvpn", "AWS VPN Client"},
		{"/usr/sbin/openvpn", "/usr/sbin/openvpn", "OpenVPN"},
		{"/usr/sbin/openvpn (deleted)", "/usr/sbin/openvpn", "OpenVPN"},
		{"/usr/libexec/openvpn3-linux/openvpn3-service-client", "/usr/libexec/openvpn3-linux/openvpn3-service-client", "OpenVPN 3"},
		{"/usr/libexec/openvpn3-linux/openvpn3-service-netcfg", "/usr/libexec/openvpn3-linux/openvpn3-service-client", "OpenVPN 3"},
		{"/usr/bin/wireguard-go", "/usr/bin/wireguard-go", "WireGuard"},
		{"/usr/sbin/tailscaled", "/usr/sbin/tailscaled", "tailscaled"},
	}
	for _, c := range cases {
		if got := FromLinuxExe(c.exe); got.ID != c.wantID || got.Name != c.wantName {
			t.Errorf("FromLinuxExe(%q) = %+v, want ID %q name %q", c.exe, got, c.wantID, c.wantName)
		}
	}
}

func TestSnapClientsKeepTheirIdentityAcrossRefreshes(t *testing.T) {
	a := FromLinuxExe("/snap/some-vpn/1234/usr/bin/vpnd")
	b := FromLinuxExe("/snap/some-vpn/1300/usr/bin/vpnd")
	if a != b || a.ID != "/snap/some-vpn/current/usr/bin/vpnd" {
		t.Errorf("snap revisions must share one identity, got %+v and %+v", a, b)
	}
}

func TestKernelWireGuardHasAStableIdentity(t *testing.T) {
	if KernelWireGuard.ID == "" || KernelWireGuard.Name != "WireGuard" {
		t.Errorf("KernelWireGuard = %+v", KernelWireGuard)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// fakeProc lays out a /proc tree: each descriptor of each pid links to target
// and has an fdinfo file.
func fakeProc(t *testing.T, fds map[string]map[string][2]string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("procfs layout is Linux only")
	}
	root := t.TempDir()
	for pid, perFd := range fds {
		for fd, v := range perFd {
			target, info := v[0], v[1]
			must(t, os.MkdirAll(filepath.Join(root, pid, "fd"), 0o755))
			must(t, os.MkdirAll(filepath.Join(root, pid, "fdinfo"), 0o755))
			must(t, os.Symlink(target, filepath.Join(root, pid, "fd", fd)))
			must(t, os.WriteFile(filepath.Join(root, pid, "fdinfo", fd), []byte(info), 0o644))
		}
	}
	return root
}

func TestTunOwnerPIDsMatchesTheInterfaceInFdinfo(t *testing.T) {
	root := fakeProc(t, map[string]map[string][2]string{
		"900": {"7": {"/dev/net/tun", "pos:\t0\nflags:\t02000002\nmnt_id:\t8\nino:\t1\niff:\ttun0\n"}},
		"410": {
			"3": {"/dev/net/tun", "pos:\t0\niff:\ttun1\n"},
			"4": {"/dev/net/tun", "pos:\t0\niff:\ttun0\n"}, // inherited by a second process
		},
		"22": {"5": {"socket:[123]", "pos:\t0\niff:\ttun0\n"}}, // not a tun descriptor
	})
	if got, want := tunOwnerPIDs(root, "tun0"), []int{410, 900}; !slices.Equal(got, want) {
		t.Errorf("tunOwnerPIDs(tun0) = %v, want %v", got, want)
	}
	if got := tunOwnerPIDs(root, "tun9"); len(got) != 0 {
		t.Errorf("tunOwnerPIDs(tun9) = %v, want none", got)
	}
	if got := tunOwnerPIDs(filepath.Join(root, "missing"), "tun0"); got != nil {
		t.Errorf("a missing /proc must yield nothing, got %v", got)
	}
}

func TestTunIfaceFromFdinfo(t *testing.T) {
	if got := tunIfaceFromFdinfo("pos:\t0\nflags:\t02\niff:\twg-work\n"); got != "wg-work" {
		t.Errorf("got %q", got)
	}
	if got := tunIfaceFromFdinfo("pos:\t0\nflags:\t02\n"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestTunOwnerPIDsSkipsProcessesInAnotherNetworkNamespace(t *testing.T) {
	tun := [2]string{"/dev/net/tun", "pos:\t0\niff:\ttun0\n"}
	root := fakeProc(t, map[string]map[string][2]string{
		"100": {"3": tun}, // the helper's namespace
		"200": {"3": tun}, // a container's tun0
	})
	link := func(pid, netns string) {
		must(t, os.MkdirAll(filepath.Join(root, pid, "ns"), 0o755))
		must(t, os.Symlink(netns, filepath.Join(root, pid, "ns", "net")))
	}
	link("self", "net:[4026531840]")
	link("100", "net:[4026531840]")
	link("200", "net:[4026532999]")
	if got, want := tunOwnerPIDs(root, "tun0"), []int{100}; !slices.Equal(got, want) {
		t.Errorf("tunOwnerPIDs(tun0) = %v, want %v", got, want)
	}
}
