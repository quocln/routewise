package dnswatch

import (
	"bytes"
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestSoftFilterMatchesTheKernelProgramOnRawIP(t *testing.T) {
	f, err := newSoftFilter()
	if err != nil {
		t.Fatal(err)
	}
	answer := dnsReply(t, "example.com", dns.RcodeSuccess, "93.184.216.34")
	quicHello := append([]byte{0xc3}, make([]byte, 40)...)

	packets := map[string][]byte{
		"DNS answer":                 ipv4Packet("1.1.1.1", 17, 0, udpDatagram(53, answer)),
		"DNS answer with ip options": ipv4Between("1.1.1.1", "192.168.7.20", 17, 2, 0, udpDatagram(53, answer)),
		"IPv6 DNS answer":            ipv6Packet("2606:4700:4700::1111", udpDatagram(53, answer)),
		"TCP SYN":                    ipv4Between("1.1.1.1", "192.168.7.20", 6, 0, 0, tcpSegment(443, tcpSYN, nil)),
		"QUIC long header":           ipv4Between("1.1.1.1", "192.168.7.20", 17, 0, 0, udpTo(443, quicHello)),
		"TCP SYN-ACK":                ipv4Between("1.1.1.1", "192.168.7.20", 6, 0, 0, tcpSegment(443, tcpSYN|tcpACK, nil)),
		"established TCP":            ipv4Between("1.1.1.1", "192.168.7.20", 6, 0, 0, tcpSegment(443, tcpACK, []byte("data"))),
		"HTTPS UDP":                  ipv4Packet("1.1.1.1", 17, 0, udpDatagram(443, answer)),
		"later DNS fragment":         ipv4Packet("1.1.1.1", 17, 0x0010, udpDatagram(53, answer)),
		"ICMP":                       ipv4Between("1.1.1.1", "192.168.7.20", 1, 0, 0, make([]byte, 8)),
		"truncated header":           {0x45, 0, 0, 20},
		"empty":                      {},
	}
	for name, pkt := range packets {
		want := filterVerdict(t, 0, pkt)
		got := f.apply(pkt)
		if len(got) != min(want, len(pkt)) {
			t.Errorf("%s: kept %d bytes, kernel program keeps %d of %d", name, len(got), want, len(pkt))
		}
		if len(got) > 0 && !bytes.Equal(got, pkt[:len(got)]) {
			t.Errorf("%s: kept bytes differ from the packet", name)
		}
	}
}

func TestSoftFilterKeepsWholeAnswersAndOnlyHeadersOfFlows(t *testing.T) {
	f, err := newSoftFilter()
	if err != nil {
		t.Fatal(err)
	}
	answer := ipv4Packet("1.1.1.1", 17, 0, udpDatagram(53, dnsReply(t, "example.com", dns.RcodeSuccess, "93.184.216.34")))
	if got := f.apply(answer); !bytes.Equal(got, answer) {
		t.Errorf("answer kept %d of %d bytes", len(got), len(answer))
	}
	syn := ipv4Between("1.1.1.1", "192.168.7.20", 6, 0, 0, tcpSegment(443, tcpSYN, make([]byte, 400)))
	if got := f.apply(syn); len(got) != flowSnapLen {
		t.Errorf("connection start kept %d bytes, want %d", len(got), flowSnapLen)
	}
}

func TestSoftFilterOutputParsesAsAnAnswer(t *testing.T) {
	f, err := newSoftFilter()
	if err != nil {
		t.Fatal(err)
	}
	pkt := ipv4Packet("1.1.1.1", 17, 0, udpDatagram(53, dnsReply(t, "example.com", dns.RcodeSuccess, "93.184.216.34")))
	p, ok := decodeIP(f.apply(pkt), dltRaw)
	if !ok {
		t.Fatal("filtered packet does not decode")
	}
	answer, ok := answerFromPacket(p)
	if !ok || answer.Name != "example.com" {
		t.Errorf("answer = %+v, ok = %v", answer, ok)
	}
}

func ipnet(s string) net.Addr {
	ip, n, _ := net.ParseCIDR(s)
	n.IP = ip
	return n
}

func TestCaptureAddressPrefersGlobalIPv4(t *testing.T) {
	cases := map[string]struct {
		addrs []net.Addr
		want  string
	}{
		"global after link-local": {[]net.Addr{ipnet("169.254.3.4/16"), ipnet("10.0.0.5/24")}, "10.0.0.5"},
		"skips IPv6":              {[]net.Addr{ipnet("fd00::5/64"), ipnet("192.168.1.9/24")}, "192.168.1.9"},
		"link-local only":         {[]net.Addr{ipnet("169.254.3.4/16")}, "169.254.3.4"},
		"v4-mapped":               {[]net.Addr{&net.IPNet{IP: net.ParseIP("10.1.1.1"), Mask: net.CIDRMask(24, 32)}}, "10.1.1.1"},
		"none":                    {[]net.Addr{ipnet("fe80::1/64"), ipnet("127.0.0.1/8")}, ""},
		"no addresses":            {nil, ""},
	}
	for name, c := range cases {
		got, ok := captureAddress(c.addrs)
		if c.want == "" {
			if ok {
				t.Errorf("%s: got %v, want no address", name, got)
			}
			continue
		}
		if !ok || got != netip.MustParseAddr(c.want) {
			t.Errorf("%s: got %v ok=%v, want %s", name, got, ok, c.want)
		}
	}
}

// Random and mutated packets, truncated at every length, must get the same
// verdict from the written-out filter as from the BPF program it replaces.
func TestSoftFilterAgreesWithTheKernelProgramOnMutatedPackets(t *testing.T) {
	f, err := newSoftFilter()
	if err != nil {
		t.Fatal(err)
	}
	answer := dnsReply(t, "example.com", dns.RcodeSuccess, "93.184.216.34")
	seeds := [][]byte{
		ipv4Packet("1.1.1.1", 17, 0, udpDatagram(53, answer)),
		ipv4Between("1.1.1.1", "192.168.7.20", 17, 2, 0, udpDatagram(53, answer)),
		ipv6Packet("2606:4700:4700::1111", udpDatagram(53, answer)),
		ipv4Between("1.1.1.1", "192.168.7.20", 6, 0, 0, tcpSegment(443, tcpSYN, nil)),
		ipv4Between("1.1.1.1", "192.168.7.20", 17, 0, 0, udpTo(443, append([]byte{0xc3}, make([]byte, 40)...))),
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		pkt := bytes.Clone(seeds[rng.IntN(len(seeds))])
		for m := rng.IntN(4); m > 0; m-- {
			pkt[rng.IntN(len(pkt))] = byte(rng.IntN(256))
		}
		pkt = pkt[:rng.IntN(len(pkt)+1)]
		want := filterVerdict(t, 0, pkt)
		if got := f.apply(pkt); len(got) != min(want, len(pkt)) {
			t.Fatalf("packet % x: kept %d bytes, kernel program keeps %d", pkt, len(got), want)
		}
	}
}
