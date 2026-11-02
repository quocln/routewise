package vpnclient

import (
	pathpkg "path"
	"strings"

	"github.com/quocln/routewise/internal/config"
)

// KernelWireGuard is the client of a kernel WireGuard link. The kernel module
// has no owning process: wg-quick, NetworkManager or systemd-networkd create
// the link and exit. The fixed ID lets the allowlist admit it like any other
// client.
var KernelWireGuard = Client{ID: config.KernelWireGuardClient, Name: "WireGuard"}

// openVPN3ServicePrefix starts the binary names of OpenVPN 3 Linux's service
// processes, which share one identity. Its netcfg service creates the tun device and hands the
// descriptor to the per-tunnel client service, so both hold it and either may
// be the one found.
const openVPN3ServicePrefix = "openvpn3-service-"

// FromLinuxExe builds the Client for the executable of a process that owns a
// tunnel on Linux: AWS VPN Client, OpenVPN (also as spawned by
// NetworkManager-openvpn), OpenVPN 3 and wireguard-go get their product name;
// anything else is named after its binary.
func FromLinuxExe(exe string) Client {
	exe = strings.TrimSuffix(exe, " (deleted)") // the binary was replaced by an upgrade while running
	exe = stableSnapPath(exe)
	base := pathpkg.Base(exe)

	switch {
	case strings.HasPrefix(exe, "/opt/awsvpnclient/"):
		return Client{ID: exe, Name: "AWS VPN Client"}
	case base == "openvpn":
		return Client{ID: exe, Name: "OpenVPN"}
	case strings.HasPrefix(base, openVPN3ServicePrefix):
		return Client{ID: pathpkg.Join(pathpkg.Dir(exe), openVPN3ServicePrefix+"client"), Name: "OpenVPN 3"}
	case base == "wireguard-go":
		return Client{ID: exe, Name: "WireGuard"}
	}
	return FromPath(exe)
}

// stableSnapPath rewrites a snap revision directory ("/snap/foo/1234/bin/x")
// to "current" ("/snap/foo/current/bin/x") so a snap refresh does not look
// like a new client.
func stableSnapPath(path string) string {
	rest, found := strings.CutPrefix(path, "/snap/")
	if !found {
		return path
	}
	parts := strings.SplitN(rest, "/", 3) // snap name, revision, rest of the path
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[1] == "current" {
		return path
	}
	return "/snap/" + parts[0] + "/current/" + parts[2]
}
