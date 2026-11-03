package vpnclient

import (
	"fmt"
	"slices"
	"strings"
)

// The Windows rules take paths as plain strings, like the naming rules, so they
// run and are tested on every OS; installed_clients_windows.go supplies the disk.

// windowsProductDirs are the install folders of the clients Windows can
// recognize, relative to a Program Files folder.
var windowsProductDirs = []string{`WireGuard`, `OpenVPN`, `OpenVPN Connect`, `Amazon\AWS VPN Client`}

// installedWindowsClients reduces the executables found in those folders to one
// client per product, represented as PickWindowsClient represents its running
// processes, so an allowed entry matches once the client connects.
func installedWindowsClients(exes []string) []Client {
	byFamily := make(map[clientFamily][]string)
	for _, exe := range exes {
		path := normalizeWindowsPath(exe)
		if f := familyOf(path); f != familyNone {
			byFamily[f] = append(byFamily[f], path)
		}
	}
	found := make([]Client, 0, len(byFamily))
	for f, paths := range byFamily {
		found = append(found, Client{ID: representative(f, paths), Name: f.displayName()})
	}
	return found
}

// resolveWindowsClient maps a chosen executable to the client that owns its
// tunnels. Identify ignores anything outside the trusted roots or the known
// products, so those are refused here instead of being allowed and never
// matching.
func resolveWindowsClient(path string, roots []string, installed []Client) (Client, error) {
	id := normalizeWindowsPath(path)
	if !underTrustedRoot(id, roots) {
		return Client{}, fmt.Errorf("%w: %q is not installed under Program Files", ErrNotAVPNClient, path)
	}
	product := func(f clientFamily) (Client, bool) {
		i := slices.IndexFunc(installed, func(c Client) bool { return c.Name == f.displayName() })
		if i < 0 {
			return Client{}, false
		}
		return installed[i], true
	}
	f := familyOf(id)
	switch f {
	case familyWireGuard, familyOpenVPN:
		return Client{ID: id, Name: f.displayName()}, nil
	case familyAWS, familyOpenVPNConnect:
		// The app people pick is not the process that holds the adapter.
		if c, ok := product(f); ok {
			return c, nil
		}
		return Client{ID: id, Name: f.displayName()}, nil
	}
	if strings.Contains(windowsBase(id), "openvpn") { // openvpn-gui.exe, openvpnserv.exe
		if c, ok := product(familyOpenVPN); ok {
			return c, nil
		}
	}
	return Client{}, fmt.Errorf("%w: on Windows that means AWS VPN Client, OpenVPN, OpenVPN Connect or WireGuard, not %q", ErrNotAVPNClient, path)
}
