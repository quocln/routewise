package vpnclient

import (
	"fmt"
	"slices"
	"strings"

	"github.com/quocln/routewise/internal/winnet"
)

// Process is a running process as the owner search sees it.
type Process struct {
	// Path is the executable's full path; CmdLine its command line, which may
	// be empty when it could not be read.
	Path    string
	CmdLine string
}

// IsClientExe reports whether the executable at path can belong to a VPN
// client, so the owner search reads command lines only for those.
func IsClientExe(path string) bool { return familyOf(normalizeWindowsPath(path)) != familyNone }

// familiesFor lists the client families that can own an adapter of kind: a
// wireguard-nt adapter is the WireGuard client's; a TAP or Data Channel Offload
// adapter belongs to an OpenVPN based client; a Wintun adapter is used by
// WireGuard's userspace tunnel, OpenVPN 2.5+ and OpenVPN Connect.
func familiesFor(kind winnet.Kind) []clientFamily {
	switch kind {
	case winnet.KindWireGuard:
		return []clientFamily{familyWireGuard}
	case winnet.KindWintun:
		return []clientFamily{familyWireGuard, familyOpenVPN, familyOpenVPNConnect, familyAWS}
	case winnet.KindTAP, winnet.KindDCO:
		return []clientFamily{familyOpenVPN, familyOpenVPNConnect, familyAWS}
	}
	return nil
}

// mentions reports whether the command line names the adapter by alias or GUID,
// as OpenVPN's --dev-node does.
func mentions(cmdline string, a winnet.Adapter) bool {
	c := strings.ToLower(cmdline)
	return (a.Alias != "" && strings.Contains(c, strings.ToLower(a.Alias))) ||
		(a.GUID != "" && strings.Contains(c, strings.ToLower(a.GUID)))
}

// ownsAdapter reports whether process p of family f can be the owner of a.
// The official WireGuard client runs one tunnel service per tunnel, named by
// its command line, so only the service of the adapter's own tunnel counts; a
// wireguard.exe without /tunnelservice is the UI.
func ownsAdapter(f clientFamily, p Process, a winnet.Adapter) bool {
	if f != familyWireGuard {
		return true
	}
	if _, name, ok := wireGuardTunnel(p.CmdLine); ok {
		return strings.EqualFold(name, a.Alias)
	}
	return windowsBase(normalizeWindowsPath(p.Path)) == "wireguard-go.exe" && mentions(p.CmdLine, a)
}

// representative chooses the executable that stands for a product's processes,
// the same one whichever of them the search met first: for OpenVPN Connect its
// connector service, for the AWS client its OpenVPN binary, otherwise the
// first by path.
func representative(f clientFamily, paths []string) string {
	slices.Sort(paths)
	prefer := ""
	switch f {
	case familyOpenVPNConnect:
		prefer = "ovpnconnector.exe"
	case familyAWS:
		for _, p := range paths {
			if strings.Contains(windowsBase(p), "openvpn") {
				return p
			}
		}
	}
	for _, p := range paths {
		if prefer != "" && windowsBase(p) == prefer {
			return p
		}
	}
	return paths[0]
}

// PickWindowsClient names the client that owns adapter a from the running
// processes. Windows does not say which process holds a TAP, Wintun or DCO
// adapter, so the owner is inferred:
//
//   - only the product families that use a's driver are considered;
//   - several processes of one product are one client, represented by a single
//     executable so its ID does not depend on which process was met first;
//   - when processes of several products run, those whose command line names the
//     adapter (OpenVPN's --dev-node, a WireGuard tunnel service's own tunnel)
//     decide, and when that does not settle it the answer is an error, never a
//     guess: an unidentified tunnel is not admitted.
func PickWindowsClient(a winnet.Adapter, procs []Process) (Client, error) {
	families := familiesFor(a.Kind())
	if len(families) == 0 {
		return Client{}, fmt.Errorf("%q is not a VPN adapter RouteWise recognises (%q)", a.Alias, a.Description)
	}

	byFamily := make(map[clientFamily][]string)
	named := make(map[clientFamily]bool)
	for _, p := range procs {
		path := normalizeWindowsPath(p.Path)
		f := familyOf(path)
		if f == familyNone || !slices.Contains(families, f) || !ownsAdapter(f, p, a) {
			continue
		}
		byFamily[f] = append(byFamily[f], path)
		if mentions(p.CmdLine, a) {
			named[f] = true
		}
	}

	found := make([]clientFamily, 0, len(byFamily))
	for f := range byFamily {
		found = append(found, f)
	}
	slices.Sort(found)
	if len(found) > 1 {
		var narrowed []clientFamily
		for _, f := range found {
			if named[f] {
				narrowed = append(narrowed, f)
			}
		}
		if len(narrowed) != 1 {
			names := make([]string, len(found))
			for i, f := range found {
				names[i] = f.displayName()
			}
			return Client{}, fmt.Errorf("cannot tell which of %s owns %q", strings.Join(names, ", "), a.Alias)
		}
		found = narrowed
	}
	if len(found) == 0 {
		return Client{}, fmt.Errorf("no VPN client process found for %q (%s)", a.Alias, a.Description)
	}
	f := found[0]
	return Client{ID: representative(f, byFamily[f]), Name: f.displayName()}, nil
}
