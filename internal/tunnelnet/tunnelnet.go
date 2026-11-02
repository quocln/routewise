// Package tunnelnet holds the interface plumbing the built-in WireGuard and
// Outline tunnels share: running a system tool safely as root, creating the
// TUN device, giving it its point-to-point address (CreateTUN, AddAlias and Up
// are the platform part: ifconfig on macOS, netlink on Linux), and picking a server address from a lookup.
package tunnelnet

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
)

// CommandRunner executes an external command and returns its combined output.
// name must be an absolute path.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs real commands via os/exec, refusing non-absolute names.
type ExecRunner struct{}

// Run implements CommandRunner.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(name) {
		return nil, fmt.Errorf("refusing to run %q: command path must be absolute", name)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Links addresses and raises a tunnel interface. Start functions take one so a
// test can run on an in-memory device that the kernel knows nothing about.
type Links interface {
	AddAlias(ctx context.Context, iface, local, peer string) error
	Up(ctx context.Context, iface string) error
}

// SystemLinks configures real interfaces with the OS's own mechanism: ifconfig
// through Run on macOS, netlink on Linux (Run is unused there).
type SystemLinks struct{ Run CommandRunner }

// AddAlias implements Links.
func (s SystemLinks) AddAlias(ctx context.Context, iface, local, peer string) error {
	return AddAlias(ctx, s.Run, iface, local, peer)
}

// Up implements Links.
func (s SystemLinks) Up(ctx context.Context, iface string) error {
	return Up(ctx, s.Run, iface)
}

// PreferIPv4 picks the first IPv4 address, else the first address, with
// IPv4-mapped IPv6 forms unmapped. It reports false for an empty list.
func PreferIPv4(addrs []netip.Addr) (netip.Addr, bool) {
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			return a, true
		}
	}
	if len(addrs) > 0 {
		return addrs[0].Unmap(), true
	}
	return netip.Addr{}, false
}
