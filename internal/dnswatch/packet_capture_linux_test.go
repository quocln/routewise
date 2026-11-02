package dnswatch

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A packet socket needs CAP_NET_RAW and port 53 needs CAP_NET_BIND_SERVICE, so
// the live capture test runs only as root.
func TestPacketCaptureSeesDNSAnswerOnLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("packet capture needs root")
	}
	c, err := openCapture("lo")
	if err != nil {
		t.Fatalf("openCapture: %v", err)
	}
	defer c.close()
	if c.linkType() != dltRaw {
		t.Fatalf("link type = %d, want raw IP (%d)", c.linkType(), dltRaw)
	}

	// An answer comes from source port 53; a datagram from any other port must
	// be filtered out in the kernel.
	sink, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	answer := dnsReply(t, "example.com", dns.RcodeSuccess, "93.184.216.34")
	for _, src := range []string{"127.0.0.1:5353", "127.0.0.1:53"} {
		conn, err := net.ListenPacket("udp4", src)
		if err != nil {
			t.Fatalf("listen %s: %v", src, err)
		}
		_, err = conn.WriteTo(answer, sink.LocalAddr())
		conn.Close()
		if err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		frames, err := c.read()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		for _, f := range frames {
			pkt, ok := decodeIP(f, c.linkType())
			if !ok {
				t.Fatalf("captured frame does not decode as IP: % x", f)
			}
			if port := binary.BigEndian.Uint16(pkt.transport); port != 53 {
				t.Fatalf("filter let through a datagram from port %d", port)
			}
			return
		}
	}
	t.Fatal("no DNS answer captured on lo")
}

func TestPacketCaptureKernelDropsStartAtZero(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("packet capture needs root")
	}
	c, err := openCapture("lo")
	if err != nil {
		t.Fatalf("openCapture: %v", err)
	}
	defer c.close()
	for range 2 {
		if drops, err := c.kernelDrops(); err != nil || drops != 0 {
			t.Fatalf("kernelDrops = %d, %v; want 0, nil", drops, err)
		}
	}
}

func TestPacketCaptureRejectsUnknownInterface(t *testing.T) {
	if _, err := openCapture("rw-no-such0"); err == nil {
		t.Fatal("openCapture accepted an interface that does not exist")
	}
}
