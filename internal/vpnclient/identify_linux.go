//go:build linux

package vpnclient

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/vishvananda/netlink"
)

// Identify returns the client that owns iface (for example "tun0").
//
// A kernel WireGuard link has no owning process and is the WireGuard client. A
// tun device is owned by the process holding its descriptor, found through
// /proc; its executable names the client. When several processes hold the
// descriptor, the first one with a readable executable decides.
func Identify(ctx context.Context, iface string) (Client, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return Client{}, fmt.Errorf("look up %s: %w", iface, err)
	}
	if link.Type() == "wireguard" {
		return KernelWireGuard, nil
	}

	var lastErr error
	for _, pid := range tunOwnerPIDs("/proc", iface) {
		if err := ctx.Err(); err != nil {
			return Client{}, err
		}
		exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
		if err != nil {
			lastErr = fmt.Errorf("executable of pid %d: %w", pid, err)
			continue
		}
		rememberOwner(iface, pid)
		return FromLinuxExe(exe), nil
	}
	if lastErr != nil {
		return Client{}, lastErr
	}
	return Client{}, fmt.Errorf("no process owns %s", iface)
}
