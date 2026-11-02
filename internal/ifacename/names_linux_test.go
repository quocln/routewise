//go:build linux

package ifacename

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestValidateLinux(t *testing.T) {
	for _, name := range []string{"eth0", "wg0", "wg-work", "eth0.100", "rwtun0", "br_lan", "enp0s3", "a23456789012345"} {
		if err := Validate(name); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", "a234567890123456", "en0; rm", "en 0", "../en0", "en0\n", "a/b", "a:b", "é0"} {
		if err := Validate(name); err == nil {
			t.Errorf("Validate(%q) accepted an invalid name", name)
		}
	}
}

func TestLinuxTunnelFamilies(t *testing.T) {
	for _, name := range []string{"tun0", "tap1", "wg0", "wg-work", "rwtun0", "ipsec0"} {
		if !IsTunnel(name) || !IsVPNDevice(name) {
			t.Errorf("%q should be a tunnel", name)
		}
	}
	for _, name := range []string{"eth0", "lo", "docker0", "ppp0", "rw-dns"} {
		if IsTunnel(name) {
			t.Errorf("%q should not be a tunnel", name)
		}
	}
}

// TestLinuxTunnelByLinkType covers tunnels whose name carries no hint: the link
// type decides. It runs on a thread of its own in a private network namespace,
// so no link is ever added to the host.
func TestLinuxTunnelByLinkType(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating links needs root")
	}
	type result struct {
		corpTunnel, dummyTunnel bool
		skip                    string
		err                     error
	}
	done := make(chan result, 1)
	go func() {
		// The thread is never unlocked, so the runtime discards it with the
		// namespace once this goroutine returns.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			done <- result{skip: fmt.Sprintf("cannot create a network namespace: %v", err)}
			return
		}
		tap := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "corp0"}, Mode: netlink.TUNTAP_MODE_TUN}
		if err := netlink.LinkAdd(tap); err != nil {
			done <- result{skip: fmt.Sprintf("cannot create a tun link: %v", err)}
			return
		}
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "lan9"}}); err != nil {
			done <- result{err: err}
			return
		}
		done <- result{corpTunnel: IsTunnel("corp0") && IsVPNDevice("corp0"), dummyTunnel: IsTunnel("lan9")}
	}()
	res := <-done
	if res.skip != "" {
		t.Skip(res.skip)
	}
	if res.err != nil {
		t.Fatal(res.err)
	}
	if !res.corpTunnel {
		t.Error("a tun link named corp0 should be a tunnel")
	}
	if res.dummyTunnel {
		t.Error("a dummy link should not be a tunnel")
	}
}
