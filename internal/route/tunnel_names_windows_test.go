//go:build windows

package route

// Tunnel interface names the route tests report. Each is a "wg" alias, which
// Windows' name rules treat as a tunnel without an adapter to look up.
const (
	tun0  = "wg0"
	tun3  = "wg3"
	tun4  = "wg4"
	tun5  = "wg5"
	tun6  = "wg6"
	tun7  = "wg7"
	tun9  = "wg9"
	tun12 = "wg12"
)

// invalidInterfaceNames are names this OS's interface-name rules refuse,
// beyond the ones every OS refuses. An alias is free text, so only what could
// end an argument or climb a path is out.
var invalidInterfaceNames = []string{"wg0/x", `wg0\x`, `wg"0`, "   "}
