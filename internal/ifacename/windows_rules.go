package ifacename

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Windows names a network adapter by its friendly alias, a free-form string the
// user can rename: "Ethernet", "Wi-Fi", "Local Area Connection* 3",
// "vEthernet (WSL)", a localized "以太网", or whatever the VPN software chose
// ("OpenVPN Data Channel Offload", the WireGuard tunnel's config name). The
// route code does not key anything by alias; it keys routes by the adapter's
// LUID or interface index. The alias is validated because it still reaches
// logs, the API and messages, and classified by name only as a hint: a name
// match here is a necessary hint, never proof, and the VPN finder confirms with
// the adapter's driver description before it acts.
//
// The rules live in this untagged file so they are tested on every OS; the
// windows build selects them in names_windows.go.

// maxWindowsAliasLen is IF_MAX_STRING_SIZE, the length limit of an adapter
// alias in UTF-16 code units.
const maxWindowsAliasLen = 256

// windowsAliasChars accepts any printable text (spaces, parentheses, '*', '-',
// '#', digits, letters of any script) and refuses control characters, quotes,
// backslash and slash, which could end an argument or climb a path.
var windowsAliasChars = regexp.MustCompile(`^[^\p{Cc}"'\\/]+$`)

const windowsNameHint = "must be 1-256 characters without control characters, quotes, '/' or '\\' (e.g., Ethernet, Wi-Fi, Local Area Connection* 3)"

func validateWindowsAlias(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("invalid interface name %q: not valid UTF-8", name)
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("invalid interface name %q: blank", name)
	}
	if !windowsAliasChars.MatchString(name) {
		return fmt.Errorf("invalid interface name %q: %s", name, windowsNameHint)
	}
	if units := len(utf16.Encode([]rune(name))); units > maxWindowsAliasLen {
		return fmt.Errorf("invalid interface name %q: longer than %d characters", name, maxWindowsAliasLen)
	}
	return nil
}

// windowsTunnelNames matches the adapters of the VPN stacks RouteWise
// recognises, case-insensitively: OpenVPN (TAP-Windows, Wintun and Data Channel
// Offload adapters, including AWS VPN Client's TAP adapter and OpenVPN
// Connect's), WireGuard (the official client names the adapter after the
// tunnel, so "wg0" style names are matched and anything else needs the driver
// check), and the helper's own tunnels ("rwtun0", "RouteWise ...").
//
// Not matched, on purpose: "Local Area Connection* N" (Wi-Fi Direct virtual
// adapters), "vEthernet (...)" (Hyper-V and WSL switches), "Loopback
// Pseudo-Interface N", "Bluetooth Network Connection" and PPP/PPPoE adapters:
// they are the LAN or the machine, not a VPN.
var windowsTunnelNames = regexp.MustCompile(`(?i)` +
	`openvpn|wintun|tap-windows|wireguard|aws vpn|ovpn` + // anywhere in the alias
	`|^rwtun|^routewise` + // the helper's tunnels
	`|^wg([0-9_-]|$)|^(tun|tap)([0-9_-]|$)`) // Unix-style names

func isWindowsTunnel(name string) bool { return windowsTunnelNames.MatchString(name) }

// isWindowsVPNDevice: every tunnel family above carries a VPN's address range,
// not a directly connected network.
func isWindowsVPNDevice(name string) bool { return isWindowsTunnel(name) }
