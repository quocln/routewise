//go:build darwin

package monitor

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// ribFixtureRow describes one routing table row in neutral terms so the same
// row can be written as a kernel routing message and as a netstat line.
type ribFixtureRow struct {
	dest    string // "default", a prefix, or a host address
	gateway string // IPv4 address, "link#N", a hardware address, or the interface name
	flags   string // netstat's flag letters; only I (scope) is read
	netif   string
}

var ribFixtureIndexes = map[string]int{
	"en0": 6, "lo0": 1, "bridge100": 19, "utun4": 12, "utun6": 14, "utun7": 15, "utun9": 17, "ipsec0": 20,
}

func ribFixtureNames() map[int]string {
	names := make(map[int]string)
	for name, index := range ribFixtureIndexes {
		names[index] = name
	}
	return names
}

// ribFixture covers each shape the detector reads and the rows around them:
// scoped and global defaults, both halves on a gateway and on the interface,
// a tunnel that is not a utun, host routes, ARP rows and subnets.
var ribFixture = []ribFixtureRow{
	{"default", "192.168.7.1", "UGScg", "en0"},
	{"default", "link#19", "UCSIg", "bridge100"},
	{"default", "link#12", "UCSg", "utun4"},
	{"0/1", "10.8.0.1", "UGSc", "utun6"},
	{"128.0/1", "10.8.0.1", "UGSc", "utun6"},
	{"0/1", "utun7", "UCS", "utun7"},
	{"128.0/1", "utun7", "UCSI", "utun7"},
	{"0/1", "10.0.0.1", "UGSc", "ipsec0"},
	{"128.0/1", "link#17", "UCS", "utun9"},
	{"1.0.0.1", "utun7", "UHS", "utun7"},
	{"10.8.0.3", "10.8.0.3", "UH", "utun6"},
	{"104.21.83.220", "utun6", "UHS", "utun6"},
	{"127.0.0.0/8", "127.0.0.1", "UCS", "lo0"},
	{"127.0.0.1", "127.0.0.1", "UH", "lo0"},
	{"169.254.0.0/16", "link#6", "UCS", "en0"},
	{"169.254.185.60", "ec:63:d7:d9:4f:9", "UHLSW", "en0"},
	{"192.168.7.0/24", "link#6", "UCS", "en0"},
	{"192.168.7.1/32", "link#6", "UCS", "en0"},
	{"192.168.7.1", "d4:35:38:e7:20:84", "UHLWIir", "en0"},
	{"192.168.138/23", "link#19", "UC", "bridge100"},
	{"224.0.0/4", "link#6", "UmCS", "en0"},
	{"255.255.255.255/32", "link#6", "UCS", "en0"},
}

// ribMessages encodes rows as the kernel's NET_RT_DUMP messages: the 92-byte
// rt_msghdr, then the destination, gateway and netmask socket addresses in the
// layout the kernel uses (full sockaddr_in for addresses, a compact netmask).
func ribMessages(t testing.TB, rows []ribFixtureRow) []byte {
	t.Helper()
	var rib []byte
	for _, r := range rows {
		rib = append(rib, ribMessage(t, r)...)
	}
	return rib
}

func ribMessage(t testing.TB, r ribFixtureRow) []byte {
	t.Helper()
	dest, ok := parseNetstatDest(r.dest)
	if !ok {
		t.Fatalf("fixture destination %q", r.dest)
	}
	host := !strings.Contains(r.dest, "/") && r.dest != "default" && strings.Count(r.dest, ".") == 3
	flags := uint32(syscall.RTF_UP)
	if host {
		flags |= syscall.RTF_HOST
	}
	if strings.Contains(r.flags, "I") {
		flags |= syscall.RTF_IFSCOPE
	}

	var body []byte
	body = append(body, sockaddrIn(dest.Addr())...)
	body = append(body, ribGatewayBytes(t, r.gateway, ribFixtureIndexes[r.netif])...)
	if !host {
		body = append(body, ribMaskBytes(dest.Bits())...)
	}
	addrs := uint32(1<<syscall.RTAX_DST | 1<<syscall.RTAX_GATEWAY)
	if !host {
		addrs |= 1 << syscall.RTAX_NETMASK
	}

	msg := make([]byte, 92, 92+len(body))
	binary.NativeEndian.PutUint16(msg[0:], uint16(92+len(body)))
	msg[2] = 5 // RTM_VERSION
	msg[3] = syscall.RTM_GET
	binary.NativeEndian.PutUint16(msg[4:], uint16(ribFixtureIndexes[r.netif]))
	binary.NativeEndian.PutUint32(msg[8:], flags)
	binary.NativeEndian.PutUint32(msg[12:], addrs)
	return append(msg, body...)
}

func sockaddrIn(a netip.Addr) []byte {
	b := make([]byte, 16)
	b[0], b[1] = 16, syscall.AF_INET
	ip := a.As4()
	copy(b[4:], ip[:])
	return b
}

// ribGatewayBytes encodes a gateway column: an IPv4 address, "link#N", a
// hardware address, or an interface name (a link-level address with a name).
func ribGatewayBytes(t testing.TB, gw string, ifindex int) []byte {
	t.Helper()
	if a, err := netip.ParseAddr(gw); err == nil {
		return sockaddrIn(a)
	}
	b := make([]byte, 20) // sockaddr_dl
	b[0], b[1] = 20, syscall.AF_LINK
	switch {
	case strings.HasPrefix(gw, "link#"):
		var n int
		fmt.Sscanf(gw, "link#%d", &n)
		binary.NativeEndian.PutUint16(b[2:], uint16(n))
	case strings.Contains(gw, ":"):
		binary.NativeEndian.PutUint16(b[2:], uint16(ifindex))
		b[4], b[6] = 6, 6 // IFT_ETHER, address length
		for i, octet := range strings.Split(gw, ":") {
			var v byte
			fmt.Sscanf(octet, "%x", &v)
			b[8+i] = v
		}
	default: // the interface's name
		binary.NativeEndian.PutUint16(b[2:], uint16(ifindex))
		b[5] = byte(len(gw))
		copy(b[8:], gw)
	}
	return b
}

// ribMaskBytes encodes a netmask the way the kernel dumps it: a sockaddr_in
// cut after the last non-zero byte of the mask (length 4 plus that many bytes,
// the first four bytes being filler), padded to four bytes; a zero mask is four
// filler bytes.
func ribMaskBytes(ones int) []byte {
	if ones == 0 {
		return make([]byte, 4)
	}
	n := (ones + 7) / 8
	b := []byte{byte(4 + n), 0xff, 0xff, 0xff}
	for i := range n {
		bitsLeft := min(8, ones-8*i)
		b = append(b, byte(0xff<<(8-bitsLeft)))
	}
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func netstatText(rows []ribFixtureRow) []byte {
	var sb strings.Builder
	sb.WriteString("Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n")
	for _, r := range rows {
		fmt.Fprintf(&sb, "%-18s %-18s %-14s %12s\n", r.dest, r.gateway, r.flags, r.netif)
	}
	return []byte(sb.String())
}

func sortEntries(entries []routeEntry) []routeEntry {
	out := slices.Clone(entries)
	slices.SortFunc(out, func(a, b routeEntry) int {
		return strings.Compare(fmt.Sprintf("%v %s %v %v", a.Dest, a.Iface, a.Gateway, a.Scoped), fmt.Sprintf("%v %s %v %v", b.Dest, b.Iface, b.Gateway, b.Scoped))
	})
	return out
}

func TestRIBEntriesMatchTheNetstatParserOnTheFixture(t *testing.T) {
	fromRIB, err := entriesFromRIB(ribMessages(t, ribFixture), ribFixtureNames)
	if err != nil {
		t.Fatal(err)
	}
	fromNetstat := parseNetstatRoutes(netstatText(ribFixture))
	if len(fromNetstat) == 0 {
		t.Fatal("the netstat parser found nothing in the fixture")
	}
	if got, want := sortEntries(fromRIB), sortEntries(fromNetstat); !slices.Equal(got, want) {
		t.Fatalf("RIB entries differ from netstat entries\nRIB:     %+v\nnetstat: %+v", got, want)
	}

	p := netip.MustParsePrefix
	gw := netip.MustParseAddr("10.8.0.1")
	want := []routeEntry{
		{Dest: p("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.7.1"), Iface: "en0"},
		{Dest: p("0.0.0.0/0"), Iface: "bridge100", Scoped: true},
		{Dest: p("0.0.0.0/0"), Iface: "utun4", Tunnel: true},
		{Dest: p("0.0.0.0/1"), Gateway: gw, Iface: "utun6", Tunnel: true},
		{Dest: p("128.0.0.0/1"), Gateway: gw, Iface: "utun6", Tunnel: true},
		{Dest: p("0.0.0.0/1"), Iface: "utun7", Tunnel: true},
		{Dest: p("128.0.0.0/1"), Iface: "utun7", Tunnel: true, Scoped: true},
		{Dest: p("0.0.0.0/1"), Gateway: netip.MustParseAddr("10.0.0.1"), Iface: "ipsec0"},
		{Dest: p("128.0.0.0/1"), Iface: "utun9", Tunnel: true},
	}
	if got := sortEntries(fromRIB); !slices.Equal(got, sortEntries(want)) {
		t.Fatalf("RIB entries = %+v\nwant %+v", got, sortEntries(want))
	}
}

// The detector must draw the same conclusion from both sources.
func TestRIBAndNetstatFindTheSameVPNs(t *testing.T) {
	fromRIB, err := entriesFromRIB(ribMessages(t, ribFixture), ribFixtureNames)
	if err != nil {
		t.Fatal(err)
	}
	a, b := findVPNFromRoutes(fromRIB), findVPNFromRoutes(parseNetstatRoutes(netstatText(ribFixture)))
	if !slices.Equal(a, b) || len(a) == 0 {
		t.Fatalf("RIB found %+v, netstat found %+v", a, b)
	}
}

// TestRIBEntriesMatchNetstatOnThisMachine compares the two readers on the live
// routing table. A table that changes between the two reads is read again.
func TestRIBEntriesMatchNetstatOnThisMachine(t *testing.T) {
	var fromRIB, fromNetstat []routeEntry
	for range 5 {
		var err error
		if fromRIB, err = ribRouteEntries(); err != nil {
			t.Fatalf("read the routing table in process: %v", err)
		}
		out, err := exec.Command(netstatPath, "-rn", "-f", "inet").Output()
		if err != nil {
			t.Skipf("netstat is not usable here: %v", err)
		}
		fromNetstat = parseNetstatRoutes(out)
		if slices.Equal(sortEntries(fromRIB), sortEntries(fromNetstat)) {
			t.Logf("%d entries agree", len(fromRIB))
			return
		}
	}
	t.Fatalf("RIB and netstat disagree\nRIB:     %+v\nnetstat: %+v", sortEntries(fromRIB), sortEntries(fromNetstat))
}

func TestDropHostRoutesRefusesAMalformedDump(t *testing.T) {
	good := ribMessages(t, ribFixture)
	for name, rib := range map[string][]byte{
		"truncated header": good[:8],
		"length past end":  good[:len(good)-1],
		"zero length":      make([]byte, 16),
		"length below hdr": append([]byte{4, 0}, make([]byte, 20)...),
	} {
		if _, err := entriesFromRIB(slices.Clone(rib), ribFixtureNames); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// bigFixture is a table of the size the netstat route runner's output cap
// failed at: thousands of RouteWise host routes around a few real rows.
func bigFixture(hosts int) []ribFixtureRow {
	rows := slices.Clone(ribFixture)
	for i := range hosts {
		rows = append(rows, ribFixtureRow{
			dest: fmt.Sprintf("10.%d.%d.%d", 100+i/65536, i/256%256, i%256), gateway: "utun6", flags: "UHS", netif: "utun6",
		})
	}
	return rows
}

func TestRIBReadsATableLargerThanTheNetstatRunnerCap(t *testing.T) {
	rows := bigFixture(5000)
	if n := len(netstatText(rows)); n < 262144 {
		t.Fatalf("netstat text is %d bytes; the fixture must exceed the runner's 256 KiB cap", n)
	}
	entries, err := entriesFromRIB(ribMessages(t, rows), ribFixtureNames)
	if err != nil || len(entries) != 9 {
		t.Fatalf("entries = %d, err = %v; want the 9 detector rows of a 5000-host table", len(entries), err)
	}
}

func BenchmarkReadRouteTable(b *testing.B) {
	rows := bigFixture(3000)
	rib := ribMessages(b, rows)
	text := netstatText(rows)

	b.Run("netstat-parse-3000-rows", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			parseNetstatRoutes(text)
		}
	})
	b.Run("rib-parse-3000-rows", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			// The parser compacts its input in place, so it gets a copy.
			if _, err := entriesFromRIB(append([]byte(nil), rib...), ribFixtureNames); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("netstat-exec-and-parse-live", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			out, err := exec.Command(netstatPath, "-rn", "-f", "inet").Output()
			if err != nil {
				b.Fatal(err)
			}
			parseNetstatRoutes(out)
		}
	})
	b.Run("rib-live", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := ribRouteEntries(); err != nil {
				b.Fatal(err)
			}
		}
	})
}
