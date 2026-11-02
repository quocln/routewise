// Package vpnclient identifies which program owns a VPN tunnel interface, so
// RouteWise manages only the VPN clients the user allowed. On macOS a utun
// interface is created through a com.apple.net.utun_control socket; the
// process holding that socket is the client, whether it is a plain binary
// (openvpn, wireguard-go) or a NetworkExtension provider inside an app bundle.
// On Linux the process holding the tun device's descriptor is the client, and
// a kernel WireGuard link, which has no process, is the WireGuard client.
// Finding that owner is the platform part (Identify); naming the client from
// its path is not.
package vpnclient

import (
	"path/filepath"
	"strings"
)

// Client is the program that owns a tunnel.
type Client struct {
	// ID is the client's executable path, the stable key the allowlist uses.
	ID string `json:"id"`
	// Name is a human-readable name: the app bundle's name, or the binary's.
	Name string `json:"name"`
}

// FromPath builds the Client for an executable path.
func FromPath(path string) Client {
	path = stableHomebrewPath(path)
	return Client{ID: path, Name: displayName(path)}
}

// stableHomebrewPath rewrites a Homebrew keg path, which names the formula's
// version ("/usr/local/Cellar/wireguard-go/0.0.20230223/bin/wireguard-go"),
// to the formula's stable opt path ("/usr/local/opt/wireguard-go/bin/
// wireguard-go"). Otherwise every `brew upgrade` would look like a new VPN
// client and ask for approval again.
func stableHomebrewPath(path string) string {
	before, rest, found := strings.Cut(path, "/Cellar/")
	if !found {
		return path
	}
	parts := strings.SplitN(rest, "/", 3) // formula, version, rest of the path
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
		return path
	}
	return before + "/opt/" + parts[0] + "/" + parts[2]
}

// displayName names a client after the outermost app bundle in its path
// ("/Applications/WireGuard.app/.../WireGuardNetworkExtension" is
// "WireGuard"), or after the binary itself ("/opt/homebrew/sbin/openvpn" is
// "openvpn").
func displayName(path string) string {
	for part := range strings.SplitSeq(path, "/") {
		if strings.HasSuffix(part, ".app") && len(part) > len(".app") {
			return strings.TrimSuffix(part, ".app")
		}
	}
	return filepath.Base(path)
}
