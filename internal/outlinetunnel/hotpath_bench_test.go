package outlinetunnel

import (
	"io"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// sinkTun discards writes, so a benchmark measures the packet path alone.
type sinkTun struct{ tun.Device }

func (sinkTun) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

// udpPacket builds a valid IPv4/UDP packet with a payload of n bytes.
func udpPacket(n int) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+n)
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4([4]byte{10, 233, 0, 2}),
		DstAddr:     tcpip.AddrFrom4([4]byte{192, 0, 2, 1}),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return pkt
}

// BenchmarkInjectPacket measures handing one 1400-byte packet from the utun to
// the stack.
func BenchmarkInjectPacket(b *testing.B) {
	ns, err := newNetStack(DefaultMTU, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer ns.close()
	pkt := udpPacket(1400)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		injectPacket(ns.ep, pkt)
	}
}

// BenchmarkWritePacket measures writing one 1400-byte stack packet to the utun.
func BenchmarkWritePacket(b *testing.B) {
	payload := udpPacket(1400)
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)})
	defer pb.DecRef()
	w := packetWriter{dev: sinkTun{}}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.write(pb); err != nil {
			b.Fatal(err)
		}
	}
}

// relayEnd is an in-memory halfCloser: it reads size bytes, then EOF, and
// discards what is written.
type relayEnd struct{ left int }

func (r *relayEnd) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.left)
	r.left -= n
	return n, nil
}
func (r *relayEnd) Write(p []byte) (int, error) { return len(p), nil }
func (r *relayEnd) Close() error                { return nil }
func (r *relayEnd) CloseWrite() error           { return nil }

// BenchmarkRelayShortFlow measures one remote-to-local copy of a 4 KiB
// response, the shape of a typical short connection.
func BenchmarkRelayShortFlow(b *testing.B) {
	t := &Tunnel{}
	var n atomic.Uint64
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		src, dst := &relayEnd{left: 4096}, &relayEnd{}
		t.copyHalf(dst, src, &n, src, dst)
	}
}
