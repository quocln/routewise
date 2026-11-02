//go:build linux

package route

// Tunnel interface names the route tests report. Each is a
// wireguard device: the tunnel family a Linux host recognises.
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
// beyond the ones every OS refuses: the kernel's 15-character limit and the
// dot entries that would name a directory.
var invalidInterfaceNames = []string{"wg0/x", "wg 0", "abcdefghijklmnop", ".", ".."}
