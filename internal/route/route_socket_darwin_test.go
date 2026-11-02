//go:build darwin

package route

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"syscall"
	"testing"

	xroute "golang.org/x/net/route"
)

// countingExec is the route(8) a runner falls back to, recording what reached it.
func socketRunnerForTest(t *testing.T, write func([]byte) error) (*routeSocketRunner, *[]string) {
	t.Helper()
	var calls []string
	r := newRouteSocketRunner(&execRunner{tools: map[string]string{toolRoute: "/usr/bin/true"}, timeout: commandTimeout, maxOutput: maxCommandOutput})
	r.write = func(message []byte) error { return write(message) }
	r.fallbackHook = func(args []string) { calls = append(calls, strings.Join(args, " ")) }
	return r, &calls
}

func parseWire(t *testing.T, message []byte) *xroute.RouteMessage {
	t.Helper()
	messages, err := xroute.ParseRIB(xroute.RIBTypeRoute, message)
	if err != nil || len(messages) != 1 {
		t.Fatalf("parse: %v, %d messages", err, len(messages))
	}
	return messages[0].(*xroute.RouteMessage)
}

func TestRouteCommandsBecomeTheMessagesRouteWouldSend(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		kind    int
		flags   int
		dst     netip.Addr
		mask    string
		gateway string
	}{
		{"host via gateway", []string{"-n", "add", "-host", "10.1.2.3", "192.168.7.1"}, syscall.RTM_ADD,
			syscall.RTF_UP | syscall.RTF_STATIC | syscall.RTF_HOST | syscall.RTF_GATEWAY, netip.MustParseAddr("10.1.2.3"), "", "192.168.7.1"},
		{"network via gateway", []string{"-n", "add", "-net", "10.20.0.0/16", "10.8.0.1"}, syscall.RTM_ADD,
			syscall.RTF_UP | syscall.RTF_STATIC | syscall.RTF_GATEWAY, netip.MustParseAddr("10.20.0.0"), "255.255.0.0", "10.8.0.1"},
		{"abbreviated network", []string{"-n", "add", "-net", "128.0/1", "10.8.0.1"}, syscall.RTM_ADD,
			syscall.RTF_UP | syscall.RTF_STATIC | syscall.RTF_GATEWAY, netip.MustParseAddr("128.0.0.0"), "128.0.0.0", "10.8.0.1"},
		{"delete host", []string{"-n", "delete", "-host", "10.1.2.3"}, syscall.RTM_DELETE,
			syscall.RTF_HOST, netip.MustParseAddr("10.1.2.3"), "", ""},
		{"delete network", []string{"-n", "delete", "-net", "64.0.0.0/2"}, syscall.RTM_DELETE,
			0, netip.MustParseAddr("64.0.0.0"), "192.0.0.0", ""},
		{"reject all of IPv6", []string{"-n", "add", "-inet6", "-net", "2000::/3", "::1", "-reject"}, syscall.RTM_ADD,
			syscall.RTF_UP | syscall.RTF_STATIC | syscall.RTF_GATEWAY | syscall.RTF_REJECT, netip.MustParseAddr("2000::"), "e000::", "::1"},
		{"reject one IPv6 address", []string{"-n", "add", "-inet6", "-host", "2001:db8::1", "::1", "-reject"}, syscall.RTM_ADD,
			syscall.RTF_UP | syscall.RTF_STATIC | syscall.RTF_HOST | syscall.RTF_GATEWAY | syscall.RTF_REJECT, netip.MustParseAddr("2001:db8::1"), "", "::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, ok := parseRouteCommand(tt.args)
			if !ok {
				t.Fatal("not handled")
			}
			message := xroute.RouteMessage{Version: syscall.RTM_VERSION, Type: request.kind, Flags: request.flags, Addrs: request.addrs}
			wire, err := message.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			got := parseWire(t, wire)
			if got.Type != tt.kind || got.Flags != tt.flags {
				t.Errorf("type %d flags %#x, want %d %#x", got.Type, got.Flags, tt.kind, tt.flags)
			}
			if addrString(got.Addrs[addrDst]) != tt.dst.String() {
				t.Errorf("destination = %s, want %s", addrString(got.Addrs[addrDst]), tt.dst)
			}
			if gotMask := addrString(addrAt(got, addrNetmask)); gotMask != tt.mask {
				t.Errorf("mask = %q, want %q", gotMask, tt.mask)
			}
			if gotGateway := addrString(addrAt(got, addrGateway)); gotGateway != tt.gateway {
				t.Errorf("gateway = %q, want %q", gotGateway, tt.gateway)
			}
		})
	}
}

func addrAt(m *xroute.RouteMessage, i int) xroute.Addr {
	if i < len(m.Addrs) {
		return m.Addrs[i]
	}
	return nil
}

func addrString(a xroute.Addr) string {
	switch a := a.(type) {
	case *xroute.Inet4Addr:
		return netip.AddrFrom4(a.IP).String()
	case *xroute.Inet6Addr:
		return netip.AddrFrom16(a.IP).String()
	}
	return ""
}

func TestARouteThroughAnInterfaceNamesIt(t *testing.T) {
	request, ok := parseRouteCommand([]string{"-n", "add", "-net", "0.0.0.0/2", "-interface", "lo0"})
	if !ok {
		t.Fatal("not handled")
	}
	link, isLink := request.addrs[addrGateway].(*xroute.LinkAddr)
	if !isLink || link.Name != "lo0" || link.Index == 0 {
		t.Fatalf("gateway = %#v", request.addrs[addrGateway])
	}
	if request.flags&syscall.RTF_GATEWAY != 0 {
		t.Error("a route through an interface has no gateway")
	}
}

func TestWhatRouteAloneHandlesStaysWithRoute(t *testing.T) {
	for _, args := range [][]string{
		{"-n", "change", "default", "192.168.7.1"},
		{"-n", "change", "default", "-interface", "utun6"},
		{"-n", "add", "default", "192.168.7.1"},
		{"-n", "add", "default", "-interface", "utun6"},
		{"-n", "delete", "default"},
		{"-n", "add", "-net", "default", "192.168.7.1"},
		{"-n", "add", "-host", "10.1.2.3", "-interface", "no-such-interface"},
		{"-n", "add", "-host", "10.1.2.3", "2001:db8::1"},
		{"-n", "add", "-host", "not-an-address", "192.168.7.1"},
		{"-n", "delete", "-host", "10.1.2.3", "extra"},
		{"add", "-host", "10.1.2.3", "192.168.7.1"},
	} {
		if _, ok := parseRouteCommand(args); ok {
			t.Errorf("%v must go to route(8)", args)
		}
	}
}

func TestKernelErrorsReadAsRouteSpellsThem(t *testing.T) {
	for errno, want := range map[syscall.Errno]string{
		syscall.EEXIST:      "File exists",
		syscall.ESRCH:       "not in table",
		syscall.ENETUNREACH: "Network is unreachable",
	} {
		r, calls := socketRunnerForTest(t, func([]byte) error { return errno })
		_, err := r.Run(context.Background(), toolRoute, "-n", "add", "-host", "10.1.2.3", "192.168.7.1")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: err = %v, want it to contain %q", errno, err, want)
		}
		if len(*calls) != 0 {
			t.Errorf("%v: a known error went to route(8): %v", errno, *calls)
		}
	}
}

func TestAnUnknownKernelErrorGoesToRoute(t *testing.T) {
	r, calls := socketRunnerForTest(t, func([]byte) error { return syscall.EINVAL })
	if _, err := r.Run(context.Background(), toolRoute, "-n", "add", "-host", "10.1.2.3", "192.168.7.1"); err != nil {
		t.Fatalf("route(8) succeeded, so the call must: %v", err)
	}
	if len(*calls) != 1 {
		t.Errorf("route(8) calls = %v, want the one that failed", *calls)
	}
}

func TestAChangeThatWorksStartsNoProcess(t *testing.T) {
	sent := 0
	r, calls := socketRunnerForTest(t, func([]byte) error { sent++; return nil })
	if _, err := r.Run(context.Background(), toolRoute, "-n", "delete", "-net", "64.0.0.0/2"); err != nil {
		t.Fatal(err)
	}
	if sent != 1 || len(*calls) != 0 {
		t.Errorf("sent %d, route(8) calls %v", sent, *calls)
	}
}

func TestDefaultRouteChangesNeverTouchTheSocket(t *testing.T) {
	r, calls := socketRunnerForTest(t, func([]byte) error { return errors.New("must not be called") })
	if _, err := r.Run(context.Background(), toolRoute, "-n", "change", "default", "192.168.7.1"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Errorf("route(8) calls = %v", *calls)
	}
}

// Lookups need no privilege, so the real kernel can check this one: what the socket
// answers must read the same as what /sbin/route prints.
func TestLookupsMatchRouteOnThisMachine(t *testing.T) {
	r := newRouteSocketRunner(newExecRunner())
	ctx := context.Background()
	for _, addr := range []string{"127.0.0.1", "8.8.8.8", "93.184.216.34"} {
		dest := netip.MustParseAddr(addr)
		wantIface, wantGateway, err := lookupRoute(ctx, newExecRunner(), dest)
		if err != nil {
			t.Skipf("route(8) cannot answer here: %v", err)
		}
		gotIface, gotGateway, err := lookupRoute(ctx, r, dest)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		if gotIface != wantIface || gotGateway != wantGateway {
			t.Errorf("%s: socket %q via %v, route(8) %q via %v", addr, gotIface, gotGateway, wantIface, wantGateway)
		}
	}
	wantGateway, wantIface, err := getDefaultRoute(ctx, newExecRunner())
	if err != nil {
		t.Skipf("no default route: %v", err)
	}
	gotGateway, gotIface, err := getDefaultRoute(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if gotGateway != wantGateway || gotIface != wantIface {
		t.Errorf("default: socket %v on %q, route(8) %v on %q", gotGateway, gotIface, wantGateway, wantIface)
	}
}

func BenchmarkRouteLookup(b *testing.B) {
	dest := netip.MustParseAddr("8.8.8.8")
	ctx := context.Background()
	b.Run("route(8)", func(b *testing.B) {
		r := newExecRunner()
		for b.Loop() {
			if _, _, err := lookupRoute(ctx, r, dest); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("socket", func(b *testing.B) {
		r := newRouteSocketRunner(newExecRunner())
		for b.Loop() {
			if _, _, err := lookupRoute(ctx, r, dest); err != nil {
				b.Fatal(err)
			}
		}
	})
}
