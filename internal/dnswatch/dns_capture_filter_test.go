package dnswatch

import (
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/net/bpf"
)

func runFilter(t *testing.T, linkLen uint32, frame []byte) bool {
	t.Helper()
	vm, err := bpf.NewVM(captureFilter(linkLen))
	if err != nil {
		t.Fatalf("filter does not assemble: %v", err)
	}
	n, err := vm.Run(frame)
	if err != nil {
		return false // the VM rejects reads past the end, as the kernel does
	}
	return n > 0
}

func TestCaptureFilterKeepsDNSAnswersOnly(t *testing.T) {
	answer := dnsReply(t, "example.com", dns.RcodeSuccess, "93.184.216.34")

	accept := map[string]struct {
		linkLen uint32
		frame   []byte
	}{
		"IPv4 over Ethernet":  {14, ethernet(ipv4Packet("1.1.1.1", 17, 0, udpDatagram(53, answer)))},
		"IPv4 over a tunnel":  {4, utunFrame(ipv4Packet("10.0.0.2", 17, 0, udpDatagram(53, answer)))},
		"IPv6 transport, raw": {0, ipv6Packet("2606:4700:4700::1111", udpDatagram(53, answer))},
	}
	for name, c := range accept {
		if !runFilter(t, c.linkLen, c.frame) {
			t.Errorf("%s: filter dropped a DNS answer", name)
		}
	}

	drop := map[string][]byte{
		"HTTPS traffic":    ethernet(ipv4Packet("1.1.1.1", 17, 0, udpDatagram(443, answer))),
		"TCP":              ethernet(ipv4Packet("1.1.1.1", 6, 0, udpDatagram(53, answer))),
		"a later fragment": ethernet(ipv4Packet("1.1.1.1", 17, 0x0010, udpDatagram(53, answer))),
		"ARP":              {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0x08, 0x06, 0x00, 0x01},
	}
	for name, frame := range drop {
		if runFilter(t, 14, frame) {
			t.Errorf("%s: filter let it through", name)
		}
	}
}
