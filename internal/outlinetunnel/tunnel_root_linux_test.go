//go:build linux

package outlinetunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

// startRootTunnel starts a tunnel on a real TUN device with the fake dialer.
// It needs root and ROUTEWISE_OUTLINE_ROOT_TEST=1; run it inside a throwaway
// network namespace, because it adds a host route.
func startRootTunnel(t *testing.T, addr netip.Addr) (*Tunnel, *fakeDialer) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("ROUTEWISE_OUTLINE_ROOT_TEST") != "1" {
		t.Skip("needs root and ROUTEWISE_OUTLINE_ROOT_TEST=1")
	}
	dialer := &fakeDialer{tcpTarget: startDestServer(t)}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tn, err := Start(ctx, testKey, Options{
		Address:   addr,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Resolver:  fakeResolver{},
		NewDialer: func(Key, netip.AddrPort) (Dialer, error) { return dialer, nil },
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = tn.Stop() })
	return tn, dialer
}

// TestTunnelLifecycleAsRoot creates a real TUN device and checks its name, its
// plain /32 address, that no route is added, and that Stop removes it.
func TestTunnelLifecycleAsRoot(t *testing.T) {
	addr := netip.MustParseAddr("10.233.250.1")
	tn, _ := startRootTunnel(t, addr)

	name := tn.Name()
	if !strings.HasPrefix(name, "rwtun") {
		t.Fatalf("Name = %q, want rwtunN", name)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		t.Fatalf("%s is not up", name)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil || len(addrs) != 1 || addrs[0].IPNet.String() != addr.String()+"/32" {
		t.Fatalf("addrs = %v, err = %v", addrs, err)
	}
	if routes, err := netlink.RouteList(link, netlink.FAMILY_V4); err != nil || len(routes) != 0 {
		t.Fatalf("routes on %s = %v, err = %v; want none", name, routes, err)
	}

	if err := tn.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := tn.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatalf("%s still exists after Stop", name)
	}
}

// TestKernelTCPThroughRealTUN sends real kernel TCP traffic into the tunnel
// and back. A 1 MiB upload makes the kernel emit large offloaded segments that
// wireguard-go splits on read, and the replies it must coalesce on write, so
// it proves the packet offset and the batch handling against the Linux driver.
func TestKernelTCPThroughRealTUN(t *testing.T) {
	tn, dialer := startRootTunnel(t, netip.MustParseAddr("10.233.250.2"))

	link, err := netlink.LinkByName(tn.Name())
	if err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddrPort("203.0.113.77:8443")
	_, dstNet, _ := net.ParseCIDR(dst.Addr().String() + "/32")
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dstNet, Scope: netlink.SCOPE_LINK}); err != nil {
		t.Fatalf("route to the test destination: %v", err)
	}

	c, err := net.DialTimeout("tcp", dst.String(), 10*time.Second)
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer c.Close()
	payload := []byte(strings.Repeat("0123456789abcdef", 64<<10))
	go func() {
		_, _ = c.Write(payload)
		_ = c.(*net.TCPConn).CloseWrite()
	}()
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != len(payload)+4 || string(got[4:]) != string(payload) {
		t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(payload)+4)
	}
	if d := dialer.dialed(); len(d) != 1 || d[0] != dst.String() {
		t.Fatalf("dialed %v, want [%s]", d, dst)
	}
}

var _ tun.Device // the device under test is wireguard-go's Linux TUN
