package outlinetunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	// nicID is the only NIC of the stack.
	nicID tcpip.NICID = 1
	// tunOffset is the headroom the TUN driver needs in front of each packet:
	// the 4-byte address-family header on macOS, wireguard-go's 10-byte
	// virtio-net header on Linux, none on Windows (Wintun copies packets to and
	// from the given offset); extra room is harmless.
	tunOffset = 16
	// maxPacket bounds one packet read from the utun.
	maxPacket = 65535
	// channelQueue is the depth of the outbound packet queue.
	channelQueue = 1024
	// tcpRcvWnd is the receive window of forwarded connections (0 = default).
	tcpRcvWnd = 0
	// tcpMaxInFlight bounds half-open forwarded connections.
	tcpMaxInFlight = 1024
)

// netStack is a gVisor IPv4 stack that accepts every destination and hands new
// TCP and UDP flows to forwarders.
type netStack struct {
	stack *stack.Stack
	ep    *channel.Endpoint
}

// newNetStack builds the stack with a promiscuous, spoofing NIC and a default
// route to it, so a packet for any destination is accepted and the answers can
// carry that destination as their source address.
func newNetStack(mtu int, onTCP func(*tcp.ForwarderRequest), onUDP func(*udp.ForwarderRequest)) (*netStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(channelQueue, uint32(mtu), "")
	if terr := s.CreateNIC(nicID, ep); terr != nil {
		return nil, fmt.Errorf("create NIC: %v", terr)
	}
	if terr := s.SetPromiscuousMode(nicID, true); terr != nil {
		s.Destroy()
		return nil, fmt.Errorf("promiscuous mode: %v", terr)
	}
	if terr := s.SetSpoofing(nicID, true); terr != nil {
		s.Destroy()
		return nil, fmt.Errorf("spoofing mode: %v", terr)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	sack := tcpip.TCPSACKEnabled(true)
	if terr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); terr != nil {
		s.Destroy()
		return nil, fmt.Errorf("enable SACK: %v", terr)
	}

	if onTCP != nil {
		s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, tcpRcvWnd, tcpMaxInFlight, onTCP).HandlePacket)
	}
	if onUDP != nil {
		s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(s, onUDP).HandlePacket)
	}
	return &netStack{stack: s, ep: ep}, nil
}

// close shuts the stack down and waits for its goroutines.
func (n *netStack) close() {
	n.stack.Close()
	n.stack.Wait()
	n.stack.Destroy()
}

// pumpTunToStack reads packets from the device and injects them into the
// stack until the device is closed or ctx ends. The device reads at an offset
// that leaves room for its header: one packet per call on macOS, a batch on
// Linux (where one read of a coalesced TCP or UDP segment yields several).
func pumpTunToStack(ctx context.Context, dev tun.Device, ep *channel.Endpoint, onErr func(error)) {
	batch := dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, tunOffset+maxPacket)
	}
	for {
		n, err := dev.Read(bufs, sizes, tunOffset)
		for i := 0; i < n; i++ {
			injectPacket(ep, bufs[i][tunOffset:tunOffset+sizes[i]])
		}
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.EOF) {
				onErr(fmt.Errorf("read tunnel device: %w", err))
			}
			return
		}
	}
}

// injectPacket hands one raw IP packet to the stack. Only IPv4 is routed into
// the tunnel; anything else is dropped.
func injectPacket(ep *channel.Endpoint, pkt []byte) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		// MakeWithData copies pkt into the buffer's own chunk, and the stack
		// keeps that chunk after the read buffer is reused.
		Payload: buffer.MakeWithData(pkt),
	})
	ep.InjectInbound(ipv4.ProtocolNumber, pb)
	pb.DecRef()
}

// pumpStackToTun writes packets the stack emits to the device until ctx ends.
func pumpStackToTun(ctx context.Context, dev tun.Device, ep *channel.Endpoint, onErr func(error)) {
	w := packetWriter{dev: dev}
	for {
		pkt := ep.ReadContext(ctx)
		if pkt == nil {
			return // ctx done
		}
		err := w.write(pkt)
		pkt.DecRef()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, os.ErrClosed) {
				onErr(fmt.Errorf("write tunnel device: %w", err))
			}
			if errors.Is(err, os.ErrClosed) {
				return
			}
		}
	}
}

// packetWriter writes stack packets to the device through one reused buffer.
// The device does not keep the slice past Write, and only the single pump
// goroutine uses a writer, so one buffer serves every packet.
type packetWriter struct {
	dev  tun.Device
	out  []byte
	bufs [1][]byte
}

// write copies pkt behind the device's headroom (growing the buffer when it is
// too small) and writes it.
func (w *packetWriter) write(pkt *stack.PacketBuffer) error {
	if need := tunOffset + pkt.Size(); cap(w.out) < need {
		w.out = make([]byte, need)
	} else {
		w.out = w.out[:need]
	}
	views, skip := pkt.AsViewList()
	n := tunOffset
	for v := views.Front(); v != nil; v = v.Next() {
		s := v.AsSlice()
		if skip >= len(s) {
			skip -= len(s)
			continue
		}
		n += copy(w.out[n:], s[skip:])
		skip = 0
	}
	w.bufs[0] = w.out
	_, err := w.dev.Write(w.bufs[:], tunOffset)
	return err
}

// closers tracks live flows so Stop can close every one of them.
type closers struct {
	mu     sync.Mutex
	closed bool
	set    map[io.Closer]struct{}
}

// add registers c; it returns false (and closes c) when the registry is shut.
func (r *closers) add(c io.Closer) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		_ = c.Close()
		return false
	}
	if r.set == nil {
		r.set = make(map[io.Closer]struct{})
	}
	r.set[c] = struct{}{}
	return true
}

func (r *closers) remove(c io.Closer) {
	r.mu.Lock()
	delete(r.set, c)
	r.mu.Unlock()
}

// closeAll closes every registered flow and refuses new ones.
func (r *closers) closeAll() {
	r.mu.Lock()
	r.closed = true
	all := make([]io.Closer, 0, len(r.set))
	for c := range r.set {
		all = append(all, c)
	}
	r.set = nil
	r.mu.Unlock()
	for _, c := range all {
		_ = c.Close()
	}
}
