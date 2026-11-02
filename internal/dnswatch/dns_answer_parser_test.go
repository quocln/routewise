package dnswatch

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// dnsReply builds a DNS response for name with one A record per address.
func dnsReply(t *testing.T, name string, rcode int, addrs ...string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	// A fixed ID keeps the first payload byte below 0x80, so these bytes can
	// never look like a QUIC long header to the capture filter.
	m.Id = 0x1234
	m.Response = true
	m.Rcode = rcode
	for _, a := range addrs {
		rr, err := dns.NewRR(dns.Fqdn(name) + " 60 IN A " + a)
		if err != nil {
			t.Fatal(err)
		}
		m.Answer = append(m.Answer, rr)
	}
	payload, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func udpDatagram(srcPort uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], 50000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	return udp
}

func ipv4Packet(src string, proto byte, flagsFrag uint16, payload []byte) []byte {
	ip := make([]byte, 20+len(payload))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	binary.BigEndian.PutUint16(ip[6:8], flagsFrag)
	ip[8] = 64
	ip[9] = proto
	s := netip.MustParseAddr(src).As4()
	copy(ip[12:16], s[:])
	copy(ip[16:20], []byte{192, 168, 7, 20})
	copy(ip[20:], payload)
	return ip
}

func ipv6Packet(src string, payload []byte) []byte {
	ip := make([]byte, 40+len(payload))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(payload)))
	ip[6] = 17
	ip[7] = 64
	s := netip.MustParseAddr(src).As16()
	copy(ip[8:24], s[:])
	copy(ip[40:], payload)
	return ip
}

func ethernet(packet []byte) []byte {
	frame := make([]byte, 14+len(packet))
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], packet)
	return frame
}

// utunFrame prefixes the 4-byte address family header utun and loopback use.
func utunFrame(packet []byte) []byte {
	frame := make([]byte, 4+len(packet))
	binary.BigEndian.PutUint32(frame[0:4], 2)
	copy(frame[4:], packet)
	return frame
}

func TestParseFrameReadsAnAnswerOffEthernet(t *testing.T) {
	frame := ethernet(ipv4Packet("1.1.1.1", 17, 0, udpDatagram(53, dnsReply(t, "API.example.com", dns.RcodeSuccess, "93.184.216.34"))))

	got, ok := parseFrame(frame, dltEN10M)
	if !ok {
		t.Fatal("expected a DNS answer")
	}
	if got.Name != "api.example.com" || got.Server != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("answer = %+v, want lowercase name from 1.1.1.1", got)
	}
	if len(got.Addresses) != 1 || got.Addresses[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("addresses = %v", got.Addresses)
	}
}

func TestParseFrameReadsAnAnswerOffATunnel(t *testing.T) {
	frame := utunFrame(ipv4Packet("10.0.0.2", 17, 0, udpDatagram(53, dnsReply(t, "jira.corp.example.com", dns.RcodeSuccess, "10.20.30.40", "10.20.30.41"))))

	got, ok := parseFrame(frame, dltNull)
	if !ok || got.Name != "jira.corp.example.com" || len(got.Addresses) != 2 {
		t.Fatalf("answer = %+v ok=%v, want two addresses for jira.corp.example.com", got, ok)
	}
}

func TestParseFrameReadsAnIPv6Transport(t *testing.T) {
	frame := ipv6Packet("2606:4700:4700::1111", udpDatagram(53, dnsReply(t, "example.org", dns.RcodeSuccess, "93.184.216.34")))

	got, ok := parseFrame(frame, dltRaw)
	if !ok || got.Server != netip.MustParseAddr("2606:4700:4700::1111") {
		t.Fatalf("answer = %+v ok=%v, want one from the IPv6 server", got, ok)
	}
}

func TestParseFrameIgnoresWhatIsNotAnAnswer(t *testing.T) {
	answer := dnsReply(t, "example.com", dns.RcodeSuccess, "93.184.216.34")
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	cases := map[string][]byte{
		"a query, not a response": ethernet(ipv4Packet("1.1.1.1", 17, 0, udpDatagram(53, queryBytes))),
		"NXDOMAIN":                ethernet(ipv4Packet("1.1.1.1", 17, 0, udpDatagram(53, dnsReply(t, "nope.example.com", dns.RcodeNameError)))),
		"another source port":     ethernet(ipv4Packet("1.1.1.1", 17, 0, udpDatagram(443, answer))),
		"TCP":                     ethernet(ipv4Packet("1.1.1.1", 6, 0, udpDatagram(53, answer))),
		"a fragment":              ethernet(ipv4Packet("1.1.1.1", 17, 0x2000, udpDatagram(53, answer))),
		"truncated":               ethernet(ipv4Packet("1.1.1.1", 17, 0, udpDatagram(53, answer)))[:40],
		"empty":                   {},
		"not IP":                  ethernet([]byte{0x00, 0x01, 0x08, 0x00}),
	}
	for name, frame := range cases {
		if got, ok := parseFrame(frame, dltEN10M); ok {
			t.Errorf("%s: parsed %+v, want it ignored", name, got)
		}
	}
	if _, ok := parseFrame(ethernet(ipv4Packet("1.1.1.1", 17, 0, udpDatagram(53, answer))), 999); ok {
		t.Error("an unknown link type must be ignored")
	}
}

func TestSplitBPFBufferWalksPaddedRecords(t *testing.T) {
	record := func(frame []byte) []byte {
		const hdrLen = 18
		total := (hdrLen + len(frame) + 3) &^ 3
		rec := make([]byte, total)
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(frame)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(frame)))
		binary.LittleEndian.PutUint16(rec[16:18], hdrLen)
		copy(rec[hdrLen:], frame)
		return rec
	}
	var buf []byte
	buf = append(buf, record([]byte{1, 2, 3})...)
	buf = append(buf, record([]byte{4, 5, 6, 7, 8})...)

	frames := splitBPFBuffer(buf)
	if len(frames) != 2 || len(frames[0]) != 3 || frames[1][0] != 4 || len(frames[1]) != 5 {
		t.Fatalf("frames = %v, want [1 2 3] and [4 5 6 7 8]", frames)
	}
	if got := splitBPFBuffer(buf[:10]); len(got) != 0 {
		t.Fatalf("a cut-off record must yield nothing, got %v", got)
	}
}

// TestWatcherWithoutRootCapturesNothing proves an unprivileged watcher fails
// soft: it logs and keeps going rather than erroring out.
func TestWatcherWithoutRootCapturesNothing(t *testing.T) {
	w := NewWatcher(func(Answer) {}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.Sync(WatchableInterfaces())
	w.Stop()
}
