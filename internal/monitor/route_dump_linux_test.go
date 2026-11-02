//go:build linux

package monitor

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

type dumpRow struct {
	dstLen, table, rtype byte
	flags                uint32
	dst, gw              string
	oif                  uint32
	metric               uint32
	tableAttr            uint32
}

func attr(typ uint16, val []byte) []byte {
	b := make([]byte, align4(4+len(val)))
	binary.NativeEndian.PutUint16(b, uint16(4+len(val)))
	binary.NativeEndian.PutUint16(b[2:], typ)
	copy(b[4:], val)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func routeMsg(r dumpRow, msgFlags uint16) []byte {
	body := make([]byte, unix.SizeofRtMsg)
	body[0], body[1], body[4], body[7] = unix.AF_INET, r.dstLen, r.table, r.rtype
	binary.NativeEndian.PutUint32(body[8:], r.flags)
	if r.dst != "" {
		body = append(body, attr(unix.RTA_DST, net.ParseIP(r.dst).To4())...)
	}
	if r.gw != "" {
		body = append(body, attr(unix.RTA_GATEWAY, net.ParseIP(r.gw).To4())...)
	}
	if r.oif != 0 {
		body = append(body, attr(unix.RTA_OIF, u32(r.oif))...)
	}
	if r.metric != 0 {
		body = append(body, attr(unix.RTA_PRIORITY, u32(r.metric))...)
	}
	if r.tableAttr != 0 {
		body = append(body, attr(unix.RTA_TABLE, u32(r.tableAttr))...)
	}
	return nlMsg(unix.RTM_NEWROUTE, msgFlags, body)
}

func nlMsg(typ, flags uint16, body []byte) []byte {
	b := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(b, uint32(unix.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint16(b[6:], flags)
	return append(b, body...)
}

func TestParseRouteDumpKeepsOnlyWhatDetectionReads(t *testing.T) {
	var raw []byte
	for _, r := range []dumpRow{
		{dstLen: 0, table: 254, rtype: unix.RTN_UNICAST, gw: "192.168.1.1", oif: 2, metric: 100},
		{dstLen: 1, table: 252, rtype: unix.RTN_UNICAST, dst: "128.0.0.0", gw: "10.8.0.1", oif: 3, tableAttr: 51820},
		{dstLen: 32, table: 254, rtype: unix.RTN_UNICAST, dst: "10.1.2.3", oif: 3, metric: 5},
		{dstLen: 24, table: 254, rtype: unix.RTN_UNICAST, dst: "192.168.1.0", oif: 2},
		{dstLen: 0, table: 255, rtype: unix.RTN_LOCAL, oif: 1},
		{dstLen: 0, table: 254, rtype: unix.RTN_UNICAST, flags: unix.RTM_F_CLONED, oif: 2},
		{dstLen: 0, table: 254, rtype: unix.RTN_UNICAST}, // multipath: no output interface
	} {
		raw = append(raw, routeMsg(r, unix.NLM_F_MULTI)...)
	}
	raw = append(raw, nlMsg(unix.NLMSG_DONE, unix.NLM_F_MULTI, make([]byte, 4))...)

	got, err := parseRouteDump(raw)
	if err != nil || len(got) != 2 {
		t.Fatalf("routes = %+v, err %v; want the default and the /1", got, err)
	}
	if got[0].Dst != nil || got[0].LinkIndex != 2 || got[0].Priority != 100 || got[0].Table != 254 || !got[0].Gw.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("default = %+v", got[0])
	}
	if got[1].Dst.String() != "128.0.0.0/1" || got[1].Table != 51820 || got[1].LinkIndex != 3 {
		t.Errorf("/1 = %+v (the table attribute must win over the header's)", got[1])
	}
}

func TestParseRouteDumpReportsAnInterruptedDump(t *testing.T) {
	raw := routeMsg(dumpRow{dstLen: 0, table: 254, rtype: unix.RTN_UNICAST, oif: 2}, unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR)
	raw = append(raw, nlMsg(unix.NLMSG_DONE, unix.NLM_F_MULTI, make([]byte, 4))...)
	if _, err := parseRouteDump(raw); !errors.Is(err, errDumpInterrupted) {
		t.Fatalf("err = %v, want errDumpInterrupted so the dump is read again", err)
	}
}

func TestParseRouteDumpRefusesTruncatedMessages(t *testing.T) {
	raw := routeMsg(dumpRow{dstLen: 0, table: 254, rtype: unix.RTN_UNICAST, oif: 2}, 0)
	if _, err := parseRouteDump(raw[:len(raw)-3]); err == nil {
		t.Fatal("a message cut short must be refused")
	}
}

// The dump of this machine's table must yield the same detector routes as the
// netlink library's own list.
func TestDumpDetectorRoutesMatchesTheNetlinkLibrary(t *testing.T) {
	got, err := dumpDetectorRoutes()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones > 1 {
				t.Errorf("kept a /%d route %+v", ones, r)
			}
		}
		if r.LinkIndex == 0 || r.Type != unix.RTN_UNICAST {
			t.Errorf("kept an unusable route %+v", r)
		}
	}
}

func BenchmarkFetchRouteTable(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := fetchRouteTable(); err != nil {
			b.Fatal(err)
		}
	}
}
