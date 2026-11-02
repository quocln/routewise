package vpnclient

import (
	"regexp"
	"strings"
)

// Windows paths are handled here as plain strings with backslashes, never
// through path/filepath, so the naming rules run and are tested on every OS.

// versionDir matches a directory named after a version ("2.6.8", "v3.4.0.1"),
// which an installer or package manager may put in the path of a binary.
var versionDir = regexp.MustCompile(`^v?\d+(\.\d+)+$`)

// normalizeWindowsPath returns the stable form of an executable path used as a
// client ID: backslashes, no \\?\ prefix, no version directories, lower case.
// Windows compares paths without regard to case and the same process can be
// reported as "C:\Program Files\..." or "c:\program files\...", so the ID is
// lower case to match the allowlist whichever spelling the system gives; a
// version directory is dropped so an upgrade does not look like a new client.
func normalizeWindowsPath(path string) string {
	path = strings.ReplaceAll(path, "/", `\`)
	path = strings.TrimPrefix(path, `\\?\`)
	path = strings.TrimSpace(path)
	parts := strings.Split(path, `\`)
	kept := parts[:0]
	for i, p := range parts {
		if i > 0 && i < len(parts)-1 && versionDir.MatchString(p) {
			continue
		}
		kept = append(kept, p)
	}
	return strings.ToLower(strings.Join(kept, `\`))
}

// windowsBase returns the file name of a normalized path.
func windowsBase(path string) string {
	if i := strings.LastIndex(path, `\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// Client families, by the product that owns the tunnel.
type clientFamily int

const (
	familyNone clientFamily = iota
	familyAWS
	familyOpenVPNConnect
	familyWireGuard
	familyOpenVPN
)

// familyOf classifies a normalized executable path. A path under the AWS VPN
// Client or OpenVPN Connect install directory belongs to that product even for
// its bundled openvpn.exe, which is why those come first.
func familyOf(path string) clientFamily {
	base := windowsBase(path)
	switch {
	case strings.Contains(path, `\aws vpn client\`):
		return familyAWS
	case strings.Contains(path, `\openvpn connect\`), base == "openvpnconnect.exe", base == "ovpnconnector.exe":
		return familyOpenVPNConnect
	case base == "wireguard.exe", base == "wireguard-go.exe":
		return familyWireGuard
	case base == "openvpn.exe":
		return familyOpenVPN
	}
	return familyNone
}

func (f clientFamily) displayName() string {
	switch f {
	case familyAWS:
		return "AWS VPN Client"
	case familyOpenVPNConnect:
		return "OpenVPN Connect"
	case familyWireGuard:
		return "WireGuard"
	case familyOpenVPN:
		return "OpenVPN"
	}
	return ""
}

// FromWindowsExe builds the Client for the executable of a process or service
// that owns a tunnel on Windows: AWS VPN Client, OpenVPN, OpenVPN Connect and
// WireGuard get their product name; anything else is named after its binary
// without ".exe". The ID is the normalized path (see normalizeWindowsPath).
func FromWindowsExe(exe string) Client {
	id := normalizeWindowsPath(exe)
	if f := familyOf(id); f != familyNone {
		return Client{ID: id, Name: f.displayName()}
	}
	switch windowsBase(id) {
	case "openvpn-gui.exe":
		return Client{ID: id, Name: "OpenVPN GUI"}
	case "openvpnserv.exe", "openvpnserv2.exe":
		return Client{ID: id, Name: "OpenVPN"}
	}
	return Client{ID: id, Name: strings.TrimSuffix(windowsBase(id), ".exe")}
}

// splitWindowsCommandLine splits a command line into arguments the way a
// service's BinaryPathName or a process command line is written: spaces
// separate, double quotes group.
func splitWindowsCommandLine(cmd string) []string {
	var args []string
	var cur strings.Builder
	inQuote, have := false, false
	for _, r := range cmd {
		switch {
		case r == '"':
			inQuote, have = !inQuote, true
		case (r == ' ' || r == '\t') && !inQuote:
			if have {
				args = append(args, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		args = append(args, cur.String())
	}
	return args
}

// wireGuardTunnel reads the command line of the official WireGuard client's
// tunnel service, `wireguard.exe /tunnelservice <path>\<name>.conf.dpapi`, and
// returns the executable and the tunnel's name. The adapter carries the same
// name.
func wireGuardTunnel(cmdline string) (exe, name string, ok bool) {
	args := splitWindowsCommandLine(cmdline)
	if len(args) < 3 || windowsBase(normalizeWindowsPath(args[0])) != "wireguard.exe" {
		return "", "", false
	}
	for i := 1; i+1 < len(args); i++ {
		if strings.EqualFold(args[i], "/tunnelservice") {
			conf := windowsBase(strings.ReplaceAll(args[i+1], "/", `\`))
			for _, ext := range []string{".conf.dpapi", ".conf"} {
				if n, found := strings.CutSuffix(strings.ToLower(conf), ext); found && n != "" {
					return args[0], conf[:len(n)], true
				}
			}
			return "", "", false
		}
	}
	return "", "", false
}
