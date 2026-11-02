//go:build !linux && !windows

package route

// Tunnel interface names the fake BSD kernel in these tests reports. Each is a
// utun, the family a macOS VPN client owns.
const (
	tun0  = "utun0"
	tun3  = "utun3"
	tun4  = "utun4"
	tun5  = "utun5"
	tun6  = "utun6"
	tun7  = "utun7"
	tun9  = "utun9"
	tun12 = "utun12"
)

// invalidInterfaceNames are names this OS's interface-name rules refuse,
// beyond the ones every OS refuses.
var invalidInterfaceNames = []string{"utun", "5", "utun-5", "UTUN5", "utun 7"}
