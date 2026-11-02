package dnswatch

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/net/bpf"
)

// Test packet builders for connection-start traffic.

// tcpSegment builds a TCP header with the given flags and destination port.
func tcpSegment(dstPort uint16, flags byte, payload []byte) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], 50000)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	seg[12] = 5 << 4
	seg[13] = flags
	copy(seg[20:], payload)
	return seg
}

// udpTo builds a UDP datagram from an ephemeral port to dstPort.
func udpTo(dstPort uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], 50000)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	return udp
}

// ipv4Between builds an IPv4 packet carrying payload, with optionWords 32-bit
// words of IP options (each a no-op byte run) between header and payload.
func ipv4Between(src, dst string, proto byte, optionWords int, flagsFrag uint16, payload []byte) []byte {
	hdr := 20 + optionWords*4
	ip := make([]byte, hdr+len(payload))
	ip[0] = byte(0x40 | hdr/4)
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	binary.BigEndian.PutUint16(ip[6:8], flagsFrag)
	ip[8] = 64
	ip[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(ip[12:16], s[:])
	copy(ip[16:20], d[:])
	for i := 20; i < hdr; i++ {
		ip[i] = 0x01 // no-operation option
	}
	copy(ip[hdr:], payload)
	return ip
}

func ipv6Between(src, dst string, next byte, payload []byte) []byte {
	ip := make([]byte, 40+len(payload))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(payload)))
	ip[6] = next
	ip[7] = 64
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(ip[8:24], s[:])
	copy(ip[24:40], d[:])
	copy(ip[40:], payload)
	return ip
}

const (
	flagSYN    = 0x02
	flagACK    = 0x10
	flagSYNACK = flagSYN | flagACK
	flagFIN    = 0x01
	flagPSHACK = 0x18
)

var (
	quicInitial = []byte{0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}
	quicShort   = []byte{0x43, 1, 2, 3, 4, 5, 6, 7, 8, 9}
)

// framing wraps an IP packet the way each capture link type delivers it.
type framing struct {
	name    string
	linkLen uint32
	dlt     int
	wrap    func(packet []byte) []byte
}

func framings(v6 bool) []framing {
	ethertype := uint16(0x0800)
	family := uint32(2)
	if v6 {
		ethertype, family = 0x86dd, 30
	}
	return []framing{
		{"ethernet", 14, dltEN10M, func(p []byte) []byte {
			f := make([]byte, 14+len(p))
			binary.BigEndian.PutUint16(f[12:14], ethertype)
			copy(f[14:], p)
			return f
		}},
		{"utun", 4, dltNull, func(p []byte) []byte {
			f := make([]byte, 4+len(p))
			binary.BigEndian.PutUint32(f[0:4], family)
			copy(f[4:], p)
			return f
		}},
		{"raw", 0, dltRaw, func(p []byte) []byte { return p }},
	}
}

// filterVerdict runs the kernel program in the BPF VM and returns how many
// bytes it would hand over, or 0 when it drops the frame.
func filterVerdict(t *testing.T, linkLen uint32, frame []byte) int {
	t.Helper()
	vm, err := bpf.NewVM(captureFilter(linkLen))
	if err != nil {
		t.Fatalf("filter does not assemble: %v", err)
	}
	n, err := vm.Run(frame)
	if err != nil {
		return 0 // a read past the end drops the frame, as in the kernel
	}
	return n
}

func TestCaptureFilterAcceptsConnectionStartsOnEveryLinkType(t *testing.T) {
	dnsAnswer := dnsReply(t, "example.com", dns.RcodeSuccess, "93.184.216.34")

	type packet struct {
		v6   bool
		ip   []byte
		want int // bytes handed over
	}
	packets := map[string]packet{
		"IPv4 SYN":                      {false, ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagSYN, nil)), flowSnapLen},
		"IPv4 SYN with options":         {false, ipv4Between("10.0.0.2", "93.184.216.34", 6, 10, 0, tcpSegment(443, flagSYN, nil)), flowSnapLen},
		"IPv4 SYN, first fragment":      {false, ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0x2000, tcpSegment(443, flagSYN, nil)), flowSnapLen},
		"IPv4 QUIC initial":             {false, ipv4Between("10.0.0.2", "93.184.216.34", 17, 0, 0, udpTo(443, quicInitial)), flowSnapLen},
		"IPv4 QUIC initial with option": {false, ipv4Between("10.0.0.2", "93.184.216.34", 17, 3, 0, udpTo(443, quicInitial)), flowSnapLen},
		"IPv4 DNS answer":               {false, ipv4Between("1.1.1.1", "10.0.0.2", 17, 0, 0, udpDatagram(53, dnsAnswer)), snapLen},
		"IPv4 DNS answer with options":  {false, ipv4Between("1.1.1.1", "10.0.0.2", 17, 4, 0, udpDatagram(53, dnsAnswer)), snapLen},
		"IPv6 SYN":                      {true, ipv6Between("2001:db8::2", "2606:4700::1111", 6, tcpSegment(443, flagSYN, nil)), flowSnapLen},
		"IPv6 QUIC initial":             {true, ipv6Between("2001:db8::2", "2606:4700::1111", 17, udpTo(443, quicInitial)), flowSnapLen},
		"IPv6 DNS answer":               {true, ipv6Between("2606:4700:4700::1111", "2001:db8::2", 17, udpDatagram(53, dnsAnswer)), snapLen},
	}
	for name, p := range packets {
		for _, fr := range framings(p.v6) {
			if got := filterVerdict(t, fr.linkLen, fr.wrap(p.ip)); got != p.want {
				t.Errorf("%s over %s: filter handed over %d bytes, want %d", name, fr.name, got, p.want)
			}
		}
	}
}

func TestCaptureFilterDropsEstablishedTrafficInTheKernel(t *testing.T) {
	bulk := make([]byte, 1200)
	packets := map[string]struct {
		v6 bool
		ip []byte
	}{
		"SYN-ACK":                        {false, ipv4Between("93.184.216.34", "10.0.0.2", 6, 0, 0, tcpSegment(50000, flagSYNACK, nil))},
		"ACK":                            {false, ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagACK, nil))},
		"PSH-ACK with data":              {false, ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagPSHACK, bulk))},
		"FIN-ACK":                        {false, ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagFIN|flagACK, nil))},
		"no flags":                       {false, ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, 0, nil))},
		"SYN with options, then ACK":     {false, ipv4Between("10.0.0.2", "93.184.216.34", 6, 10, 0, tcpSegment(443, flagACK, nil))},
		"TCP later fragment":             {false, ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0x00b9, tcpSegment(443, flagSYN, nil))},
		"QUIC short header":              {false, ipv4Between("10.0.0.2", "93.184.216.34", 17, 0, 0, udpTo(443, quicShort))},
		"QUIC short header with options": {false, ipv4Between("10.0.0.2", "93.184.216.34", 17, 5, 0, udpTo(443, quicShort))},
		"UDP later fragment":             {false, ipv4Between("10.0.0.2", "93.184.216.34", 17, 0, 0x00b9, udpTo(443, quicInitial))},
		"ICMP":                           {false, ipv4Between("10.0.0.2", "93.184.216.34", 1, 0, 0, []byte{8, 0, 0, 0, 0, 0, 0, 0})},
		"IPv6 ACK":                       {true, ipv6Between("2001:db8::2", "2606:4700::1111", 6, tcpSegment(443, flagACK, bulk))},
		"IPv6 SYN-ACK":                   {true, ipv6Between("2606:4700::1111", "2001:db8::2", 6, tcpSegment(50000, flagSYNACK, nil))},
		"IPv6 QUIC short header":         {true, ipv6Between("2001:db8::2", "2606:4700::1111", 17, udpTo(443, quicShort))},
		"IPv6 extension header":          {true, ipv6Between("2001:db8::2", "2606:4700::1111", 0, tcpSegment(443, flagSYN, nil))},
		"IPv6 ICMPv6":                    {true, ipv6Between("2001:db8::2", "2606:4700::1111", 58, []byte{128, 0, 0, 0})},
	}
	for name, p := range packets {
		for _, fr := range framings(p.v6) {
			if got := filterVerdict(t, fr.linkLen, fr.wrap(p.ip)); got != 0 {
				t.Errorf("%s over %s: kernel filter let it through (%d bytes)", name, fr.name, got)
			}
		}
	}

	// Truncated and foreign frames never panic and never pass.
	syn := ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagSYN, nil))
	for cut := 0; cut < 14+20+13; cut++ {
		frame := framings(false)[0].wrap(syn)[:cut]
		if filterVerdict(t, 14, frame) != 0 {
			t.Errorf("a SYN cut at %d bytes must be dropped", cut)
		}
	}
	arp := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00}
	if filterVerdict(t, 14, arp) != 0 {
		t.Error("ARP must be dropped")
	}
}

func TestCaptureFilterOnlyHandsOverHeadersOfConnectionStarts(t *testing.T) {
	syn := framings(false)[0].wrap(ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagSYN, make([]byte, 1000))))
	if got := filterVerdict(t, 14, syn); got != flowSnapLen {
		t.Fatalf("snap length = %d, want %d: a SYN must not copy its payload to userspace", got, flowSnapLen)
	}
	// 14 link + 60 IPv4 with options + 14 to the TCP flags byte must fit.
	if flowSnapLen < 14+60+20 {
		t.Fatalf("flowSnapLen %d is too small for the largest headers", flowSnapLen)
	}
}

func TestAssembleStepsRejectsBadLabels(t *testing.T) {
	if _, err := assembleSteps([]filterStep{{ins: bpf.Jump{}, onTrue: "nowhere"}}); err == nil {
		t.Error("an unknown label must be an error")
	}
	if _, err := assembleSteps([]filterStep{{label: "a", ins: bpf.RetConstant{}}, {label: "a", ins: bpf.RetConstant{}}}); err == nil {
		t.Error("a duplicate label must be an error")
	}
	if _, err := assembleSteps([]filterStep{{label: "back", ins: bpf.RetConstant{}}, {ins: bpf.Jump{}, onTrue: "back"}}); err == nil {
		t.Error("a backward jump must be an error")
	}
}

func TestParseFlowReadsConnectionStarts(t *testing.T) {
	tcp := ipv4Between("10.0.0.2", "93.184.216.34", 6, 3, 0, tcpSegment(8443, flagSYN, nil))
	for _, fr := range framings(false) {
		got, ok := parseFlow(fr.wrap(tcp), fr.dlt)
		if !ok || got.Proto != ProtoTCP || got.DstPort != 8443 ||
			got.Src != netip.MustParseAddr("10.0.0.2") || got.Dst != netip.MustParseAddr("93.184.216.34") {
			t.Errorf("%s: flow = %+v ok=%v", fr.name, got, ok)
		}
	}

	quic := ipv6Between("2001:db8::2", "2606:4700::1111", 17, udpTo(443, quicInitial))
	got, ok := parseFlow(framings(true)[2].wrap(quic), dltRaw)
	if !ok || got.Proto != ProtoUDP || got.DstPort != 443 || got.Dst != netip.MustParseAddr("2606:4700::1111") {
		t.Errorf("QUIC flow = %+v ok=%v", got, ok)
	}
}

func TestParseFlowIgnoresWhatIsNotAConnectionStart(t *testing.T) {
	cases := map[string][]byte{
		"SYN-ACK":              ipv4Between("1.1.1.1", "10.0.0.2", 6, 0, 0, tcpSegment(50000, flagSYNACK, nil)),
		"ACK":                  ipv4Between("10.0.0.2", "1.1.1.1", 6, 0, 0, tcpSegment(443, flagACK, nil)),
		"QUIC short header":    ipv4Between("10.0.0.2", "1.1.1.1", 17, 0, 0, udpTo(443, quicShort)),
		"DNS query":            ipv4Between("10.0.0.2", "1.1.1.1", 17, 0, 0, udpTo(53, []byte{0x91, 0x23, 1, 0, 0, 1})),
		"later fragment":       ipv4Between("10.0.0.2", "1.1.1.1", 6, 0, 0x00b9, tcpSegment(443, flagSYN, nil)),
		"truncated TCP":        ipv4Between("10.0.0.2", "1.1.1.1", 6, 0, 0, tcpSegment(443, flagSYN, nil)[:12]),
		"UDP without a byte":   ipv4Between("10.0.0.2", "1.1.1.1", 17, 0, 0, udpTo(443, nil)),
		"ICMP":                 ipv4Between("10.0.0.2", "1.1.1.1", 1, 0, 0, []byte{8, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
		"options past the end": ipv4Between("10.0.0.2", "1.1.1.1", 6, 10, 0, nil)[:30],
	}
	for name, ip := range cases {
		if got, ok := parseFlow(ip, dltRaw); ok {
			t.Errorf("%s: parsed %+v, want it ignored", name, got)
		}
	}
	if _, ok := parseFlow(nil, dltRaw); ok {
		t.Error("an empty frame must be ignored")
	}
}

func TestParseFrameKeepsTheShortestAnswerTTL(t *testing.T) {
	frame := ipv4Between("1.1.1.1", "10.0.0.2", 17, 0, 0, udpDatagram(53, dnsReply(t, "ttl.example.com", dns.RcodeSuccess, "93.184.216.34")))
	got, ok := parseFrame(frame, dltRaw)
	if !ok || got.TTL.Seconds() != 60 {
		t.Fatalf("answer = %+v ok=%v, want a 60s TTL", got, ok)
	}
}
