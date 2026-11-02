//go:build darwin

package route

import (
	"context"
	"encoding/binary"
	"slices"
	"strings"
	"syscall"
	"testing"

	xroute "golang.org/x/net/route"
)

func inet4(a, b, c, d byte) *xroute.Inet4Addr { return &xroute.Inet4Addr{IP: [4]byte{a, b, c, d}} }

// ribRow builds the routing message of one row.
func ribRow(flags, index int, dst, gw, mask xroute.Addr) *xroute.RouteMessage {
	return &xroute.RouteMessage{Flags: flags, Index: index, Addrs: []xroute.Addr{syscall.RTAX_DST: dst, syscall.RTAX_GATEWAY: gw, syscall.RTAX_NETMASK: mask}}
}

// TestRIBRowsSpellLikeNetstat checks each row shape against the line netstat
// prints for it, recorded from macOS.
func TestRIBRowsSpellLikeNetstat(t *testing.T) {
	const (
		up, gateway, static, prcloning, global = syscall.RTF_UP, syscall.RTF_GATEWAY, syscall.RTF_STATIC, syscall.RTF_PRCLONING, rtfGlobal
		host, cloning, llinfo, wascloned       = syscall.RTF_HOST, syscall.RTF_CLONING, syscall.RTF_LLINFO, syscall.RTF_WASCLONED
		ifscope, ifref, router, multicast      = syscall.RTF_IFSCOPE, syscall.RTF_IFREF, rtfRouter, syscall.RTF_MULTICAST
	)
	names := func() map[int]string {
		return map[int]string{1: "lo0", 6: "en0", 15: "utun7", 19: "bridge100", 20: "utun9"}
	}
	zero := inet4(0, 0, 0, 0)
	tests := []struct {
		line string // as printed: destination, gateway, flags, netif
		msg  *xroute.RouteMessage
	}{
		{"default 192.168.7.1 UGScg en0", ribRow(up|gateway|static|prcloning|global, 6, zero, inet4(192, 168, 7, 1), zero)},
		{"default link#19 UCSIg bridge100", ribRow(up|cloning|static|ifscope|global, 19, zero, &xroute.LinkAddr{Index: 19}, zero)},
		{"0/1 10.8.0.1 UGSc utun9", ribRow(up|gateway|static|prcloning, 20, zero, inet4(10, 8, 0, 1), inet4(128, 0, 0, 0))},
		{"128.0/1 10.8.0.1 UGSc utun9", ribRow(up|gateway|static|prcloning, 20, inet4(128, 0, 0, 0), inet4(10, 8, 0, 1), inet4(128, 0, 0, 0))},
		{"1.0.0.1 utun7 UHS utun7", ribRow(up|host|static, 15, inet4(1, 0, 0, 1), &xroute.LinkAddr{Index: 15, Name: "utun7"}, nil)},
		{"10.8.0.3 10.8.0.3 UH utun7", ribRow(up|host, 15, inet4(10, 8, 0, 3), inet4(10, 8, 0, 3), nil)},
		{"127 127.0.0.1 UCS lo0", ribRow(up|cloning|static, 1, inet4(127, 0, 0, 0), inet4(127, 0, 0, 1), inet4(255, 0, 0, 0))},
		{"10 link#6 UCS en0", ribRow(up|cloning|static, 6, inet4(10, 0, 0, 0), &xroute.LinkAddr{Index: 6}, inet4(255, 0, 0, 0))},
		{"169.254 link#6 UCS en0", ribRow(up|cloning|static, 6, inet4(169, 254, 0, 0), &xroute.LinkAddr{Index: 6}, inet4(255, 255, 0, 0))},
		{"192.168.7 link#6 UCS en0", ribRow(up|cloning|static, 6, inet4(192, 168, 7, 0), &xroute.LinkAddr{Index: 6}, inet4(255, 255, 255, 0))},
		{"192.168.7.1/32 link#6 UCS en0", ribRow(up|cloning|static, 6, inet4(192, 168, 7, 1), &xroute.LinkAddr{Index: 6}, inet4(255, 255, 255, 255))},
		{"192.168.138/23 link#19 UC bridge100", ribRow(up|cloning, 19, inet4(192, 168, 138, 0), &xroute.LinkAddr{Index: 19}, inet4(255, 255, 254, 0))},
		{"10/16 link#6 UCS en0", ribRow(up|cloning|static, 6, inet4(10, 0, 0, 0), &xroute.LinkAddr{Index: 6}, inet4(255, 255, 0, 0))},
		{"224.0.0/4 link#6 UmCS en0", ribRow(up|multicast|cloning|static, 6, inet4(224, 0, 0, 0), &xroute.LinkAddr{Index: 6}, inet4(240, 0, 0, 0))},
		{"255.255.255.255/32 link#6 UCS en0", ribRow(up|cloning|static, 6, inet4(255, 255, 255, 255), &xroute.LinkAddr{Index: 6}, inet4(255, 255, 255, 255))},
		{"169.254.185.60 ec:63:d7:d9:4f:9 UHLSW en0", ribRow(up|host|llinfo|static|wascloned, 6, inet4(169, 254, 185, 60), &xroute.LinkAddr{Index: 6, Addr: []byte{0xec, 0x63, 0xd7, 0xd9, 0x4f, 0x09}}, nil)},
		{"192.168.7.1 d4:35:38:e7:20:84 UHLWIir en0", ribRow(up|host|llinfo|wascloned|ifscope|ifref|router, 6, inet4(192, 168, 7, 1), &xroute.LinkAddr{Index: 6, Addr: []byte{0xd4, 0x35, 0x38, 0xe7, 0x20, 0x84}}, nil)},
		{"224.0.0.251 1:0:5e:0:0:fb UHmLWI en0", ribRow(up|host|multicast|llinfo|wascloned|ifscope, 6, inet4(224, 0, 0, 251), &xroute.LinkAddr{Index: 6, Addr: []byte{1, 0, 0x5e, 0, 0, 0xfb}}, nil)},
		{"192.168.7.255 ff:ff:ff:ff:ff:ff UHLWbI en0", ribRow(up|host|llinfo|wascloned|syscall.RTF_BROADCAST|ifscope, 6, inet4(192, 168, 7, 255), &xroute.LinkAddr{Index: 6, Addr: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, nil)},
		{"10.9/24 utun7:aa:b UC utun7", ribRow(up|cloning, 15, inet4(10, 9, 0, 0), &xroute.LinkAddr{Index: 15, Name: "utun7", Addr: []byte{0xaa, 0x0b}}, inet4(255, 255, 255, 0))},
	}
	for _, tt := range tests {
		// The last field of the recorded line is the interface; the rest is
		// destination, gateway and flags. Spell the expectation the way
		// parseRouteTable reads a printed row.
		want := parseRouteTable(tt.line)
		if len(want) != 1 {
			t.Fatalf("recorded line %q did not parse", tt.line)
		}
		got := ribEntries([]xroute.Message{tt.msg}, names)
		if len(got) != 1 || got[0] != want[0] {
			t.Errorf("row %q: got %+v, want %+v", tt.line, got, want)
		}
	}
}

// rt_msghdr2 stand-ins: only the length, flags and parent flags are read.
func ribHeader(flags, parentFlags uint32) []byte {
	msg := make([]byte, 92)
	binary.NativeEndian.PutUint16(msg[0:], 92)
	binary.NativeEndian.PutUint32(msg[ribFlagsOffset:], flags)
	binary.NativeEndian.PutUint32(msg[ribParentFlagsStart:], parentFlags)
	return msg
}

func TestProtocolClonesAreDroppedLikeNetstat(t *testing.T) {
	var rib []byte
	rib = append(rib, ribHeader(syscall.RTF_UP|syscall.RTF_STATIC, 0)...)                                         // kept: ordinary route
	rib = append(rib, ribHeader(syscall.RTF_UP|syscall.RTF_HOST|syscall.RTF_WASCLONED, syscall.RTF_PRCLONING)...) // dropped
	rib = append(rib, ribHeader(syscall.RTF_UP|syscall.RTF_HOST|syscall.RTF_WASCLONED, syscall.RTF_CLONING)...)   // kept: an ARP entry
	rib = append(rib, ribHeader(syscall.RTF_UP|syscall.RTF_HOST, syscall.RTF_PRCLONING)...)                       // kept: not itself cloned
	got, err := dropProtocolClones(rib)
	if err != nil || len(got) != 3*92 {
		t.Fatalf("kept %d bytes, err %v; want 3 of 4 messages", len(got), err)
	}
	for _, bad := range [][]byte{rib[:10], rib[:len(rib)-1], make([]byte, 40)} {
		if _, err := dropProtocolClones(slices.Clone(bad)); err == nil {
			t.Errorf("a malformed dump of %d bytes must be refused", len(bad))
		}
	}
}

func TestRIBRowsWithoutAnInterfaceOrGatewayAreSkipped(t *testing.T) {
	names := func() map[int]string { return map[int]string{6: "en0"} }
	zero := inet4(0, 0, 0, 0)
	got := ribEntries([]xroute.Message{
		ribRow(syscall.RTF_UP, 99, zero, inet4(10, 0, 0, 1), zero), // unknown interface
		ribRow(syscall.RTF_UP, 6, zero, nil, zero),                 // no gateway
		&xroute.InterfaceMessage{},                                 // not a route
	}, names)
	if len(got) != 0 {
		t.Fatalf("got %+v, want nothing", got)
	}
}

// TestRIBSnapshotMatchesNetstatOnThisMachine reads the live table both ways. A
// table that changes between the two reads is read again.
func TestRIBSnapshotMatchesNetstatOnThisMachine(t *testing.T) {
	var fromRIB, fromNetstat []RouteEntry
	for range 5 {
		var err error
		if fromRIB, err = readRoutes(); err != nil {
			t.Fatalf("read the routing table in process: %v", err)
		}
		out, err := newExecRunner().Run(context.Background(), toolNetstat, "-rn", "-f", "inet")
		if err != nil {
			t.Skipf("netstat is not usable here: %v", err)
		}
		fromNetstat = withColonHardwareAddrs(parseRouteTable(out))
		if slices.Equal(fromRIB, fromNetstat) {
			t.Logf("%d rows agree", len(fromRIB))
			return
		}
	}
	t.Fatalf("in-process rows differ from netstat rows\nRIB:\n%s\nnetstat:\n%s", formatRows(fromRIB), formatRows(fromNetstat))
}

// withColonHardwareAddrs spells every hardware address gateway with colons.
// netstat joins them with dots on an interface that is not Ethernet, such as a
// bridge, and the routing dump does not carry the interface type. Nothing reads
// these gateways except to find out they are not IP addresses.
func withColonHardwareAddrs(rows []RouteEntry) []RouteEntry {
	for i := range rows {
		if strings.Count(rows[i].Gateway, ".") == 5 {
			rows[i].Gateway = strings.ReplaceAll(rows[i].Gateway, ".", ":")
		}
	}
	return rows
}

func formatRows(rows []RouteEntry) string {
	var sb strings.Builder
	for _, r := range rows {
		sb.WriteString(r.Destination + " " + r.Gateway + " " + r.Flags + " " + r.Interface + "\n")
	}
	return sb.String()
}

// The execRunner answers snapshots in process, so the netstat output cap never
// applies to a table of any size.
func TestExecRunnerSnapshotsInProcess(t *testing.T) {
	var reader routeTableReader = newExecRunner()
	entries, err := snapshotRoutes(context.Background(), reader.(commandRunner))
	if err != nil || len(entries) == 0 {
		t.Fatalf("snapshotRoutes = %d rows, %v", len(entries), err)
	}
}

func BenchmarkSnapshotRoutes(b *testing.B) {
	b.Run("netstat-exec-and-parse", func(b *testing.B) {
		r := newExecRunner()
		b.ReportAllocs()
		for b.Loop() {
			out, err := r.Run(context.Background(), toolNetstat, "-rn", "-f", "inet")
			if err != nil {
				b.Fatal(err)
			}
			parseRouteTable(out)
		}
	})
	b.Run("in-process", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := readRoutes(); err != nil {
				b.Fatal(err)
			}
		}
	})
}
