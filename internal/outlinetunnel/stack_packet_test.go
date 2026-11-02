package outlinetunnel

import (
	"bytes"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// captureTun records each written packet and the offset it was written at.
type captureTun struct {
	tun.Device
	got    [][]byte
	offset int
}

func (c *captureTun) Write(bufs [][]byte, offset int) (int, error) {
	c.offset = offset
	for _, b := range bufs {
		c.got = append(c.got, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func TestPacketWriterCopiesHeaderAndPayloadAndReusesItsBuffer(t *testing.T) {
	dev := &captureTun{}
	w := packetWriter{dev: dev}
	for _, payloadLen := range []int{1200, 40, 1500} {
		payload := bytes.Repeat([]byte{byte(payloadLen)}, payloadLen)
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: 20,
			Payload:            buffer.MakeWithData(payload),
		})
		hdr := pb.NetworkHeader().Push(20)
		for i := range hdr {
			hdr[i] = 0xAB
		}
		if err := w.write(pb); err != nil {
			t.Fatal(err)
		}
		pb.DecRef()

		want := append(bytes.Repeat([]byte{0xAB}, 20), payload...)
		if got := dev.got[len(dev.got)-1]; !bytes.Equal(got, want) {
			t.Fatalf("payload %d: wrote %d bytes, want %d with the header first", payloadLen, len(got), len(want))
		}
		if dev.offset != tunOffset {
			t.Fatalf("offset = %d, want %d", dev.offset, tunOffset)
		}
	}
}
