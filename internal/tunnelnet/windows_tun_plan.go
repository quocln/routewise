package tunnelnet

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The helpers in this file decide the names, GUIDs and addresses of the Wintun
// adapters the helper creates. They hold no Windows calls, so they are tested
// on every platform; tun_windows.go applies them.

// WindowsTunNamePrefix starts the friendly name of every adapter the helper
// creates (rwtun0, rwtun1, ...), so its adapters are recognised by name and no
// VPN client's adapter can be taken for one of them. Wintun, unlike the Linux
// kernel, has no "%d" template: the helper picks the number.
const WindowsTunNamePrefix = "rwtun"

// freeTunName returns the first rwtunN that no existing interface uses. Windows
// compares adapter names without regard to case. Wintun reuses an adapter that
// already has the requested name instead of failing, so a name must be free
// before it is asked for or two tunnels would share one adapter.
func freeTunName(existing []string) string {
	taken := make(map[string]bool, len(existing))
	for _, n := range existing {
		taken[strings.ToLower(n)] = true
	}
	for i := 0; ; i++ {
		name := WindowsTunNamePrefix + strconv.Itoa(i)
		if !taken[name] {
			return name
		}
	}
}

// tunGUID derives the adapter GUID from its name: the same name always gets the
// same GUID, so Windows keeps one network profile per name instead of adding an
// "unidentified network" for every tunnel the helper starts. The bytes follow
// RFC 4122 (version 5 layout) in the order of the GUID structure's fields.
func tunGUID(name string) (data1 uint32, data2, data3 uint16, data4 [8]byte) {
	sum := sha256.Sum256([]byte("routewise-tun:" + strings.ToLower(name)))
	sum[6] = sum[6]&0x0f | 0x50
	sum[8] = sum[8]&0x3f | 0x80
	data1 = uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])
	data2 = uint16(sum[4])<<8 | uint16(sum[5])
	data3 = uint16(sum[6])<<8 | uint16(sum[7])
	copy(data4[:], sum[8:16])
	return data1, data2, data3, data4
}

// windowsAddress is the address plan of one tunnel: the interface's own
// address and, when the peer is a different address, an on-link host route to
// it, which is what the other platforms' point-to-point configuration implies.
type windowsAddress struct {
	Local netip.Prefix
	// Peer is invalid when the peer is the local address itself, as wg-quick
	// configures: a /32 then installs no route, because routing belongs to the
	// caller and a route nobody listed must never appear.
	Peer netip.Addr
}

// planWindowsAddress parses local (an address, or an address with a prefix
// length; a bare address is a /32) and peer. Both must be IPv4.
func planWindowsAddress(local, peer string) (windowsAddress, error) {
	prefix := local
	if !strings.Contains(prefix, "/") {
		prefix += "/32"
	}
	lp, err := netip.ParsePrefix(prefix)
	if err != nil {
		return windowsAddress{}, err
	}
	if !lp.Addr().Is4() {
		return windowsAddress{}, fmt.Errorf("%s is not an IPv4 address", local)
	}
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil {
		return windowsAddress{}, fmt.Errorf("peer: %w", err)
	}
	if !peerAddr.Is4() {
		return windowsAddress{}, fmt.Errorf("peer %s is not an IPv4 address", peer)
	}
	plan := windowsAddress{Local: lp}
	if peerAddr != lp.Addr() {
		plan.Peer = peerAddr
	}
	return plan, nil
}
