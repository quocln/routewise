package outlinetunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// pipeTun is an in-memory tun.Device. Packets written to one end are read from
// its peer, so a second gVisor stack can play the role of the local host.
type pipeTun struct {
	name   string
	in     chan []byte
	peer   *pipeTun
	closed chan struct{}
	once   sync.Once
	events chan tun.Event
}

func newPipeTunPair(a, b string) (*pipeTun, *pipeTun) {
	x := &pipeTun{name: a, in: make(chan []byte, 256), closed: make(chan struct{}), events: make(chan tun.Event)}
	y := &pipeTun{name: b, in: make(chan []byte, 256), closed: make(chan struct{}), events: make(chan tun.Event)}
	x.peer, y.peer = y, x
	return x, y
}

func (p *pipeTun) File() *os.File { return nil }
func (p *pipeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-p.in:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-p.closed:
		return 0, os.ErrClosed
	}
}
func (p *pipeTun) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		pkt := append([]byte(nil), b[offset:]...)
		select {
		case p.peer.in <- pkt:
		case <-p.peer.closed:
			return i, os.ErrClosed
		case <-p.closed:
			return i, os.ErrClosed
		}
	}
	return len(bufs), nil
}
func (p *pipeTun) MTU() (int, error)        { return DefaultMTU, nil }
func (p *pipeTun) Name() (string, error)    { return p.name, nil }
func (p *pipeTun) Events() <-chan tun.Event { return p.events }
func (p *pipeTun) BatchSize() int           { return 1 }
func (p *pipeTun) Close() error             { p.once.Do(func() { close(p.closed) }); return nil }
func (p *pipeTun) isClosed() bool {
	select {
	case <-p.closed:
		return true
	default:
		return false
	}
}

// recordLinks records the address and link-up requests Start makes, in the
// OS-neutral form of tunnelnet.Links.
type recordLinks struct {
	mu    sync.Mutex
	calls [][]string
	err   error
}

func (r *recordLinks) record(call ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
	if r.err != nil {
		return fmt.Errorf("boom: %w", r.err)
	}
	return nil
}

func (r *recordLinks) AddAlias(_ context.Context, iface, local, peer string) error {
	return r.record("addalias", iface, local, peer)
}

func (r *recordLinks) Up(_ context.Context, iface string) error { return r.record("up", iface) }

type fakeResolver struct{ addrs []netip.Addr }

func (f fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if len(f.addrs) == 0 {
		return nil, errors.New("no such host")
	}
	return f.addrs, nil
}

// fakeDialer stands in for the Shadowsocks server. TCP streams connect to a
// local loopback server; UDP is answered by echoUDP.
type fakeDialer struct {
	tcpTarget string // loopback address of the fake destination server

	mu      sync.Mutex
	streams []string
	packets []fakePacket
	pcs     []*fakePacketConn
	dialErr error
}

type fakePacket struct {
	payload string
	to      string
}

func (d *fakeDialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	d.mu.Lock()
	d.streams = append(d.streams, addr)
	err := d.dialErr
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "tcp", d.tcpTarget)
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

func (d *fakeDialer) ListenPacket(context.Context) (net.PacketConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	pc := &fakePacketConn{d: d, replies: make(chan fakeReply, 16), closed: make(chan struct{})}
	d.pcs = append(d.pcs, pc)
	return pc, nil
}

func (d *fakeDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.streams...)
}

type fakeReply struct {
	payload []byte
	from    net.Addr
}

// fakePacketConn echoes every datagram back prefixed with "echo:", from the
// address it was sent to.
type fakePacketConn struct {
	d       *fakeDialer
	replies chan fakeReply
	closed  chan struct{}
	once    sync.Once
}

func (c *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.d.mu.Lock()
	c.d.packets = append(c.d.packets, fakePacket{payload: string(b), to: addr.String()})
	c.d.mu.Unlock()
	c.replies <- fakeReply{payload: append([]byte("echo:"), b...), from: addr}
	return len(b), nil
}

func (c *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case r := <-c.replies:
		return copy(b, r.payload), r.from, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}
func (c *fakePacketConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }
func (c *fakePacketConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}
func (c *fakePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

// startDestServer runs a TCP server that reads until EOF and replies
// "got:<data>", which exercises half-close in both directions.
func startDestServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				data, _ := io.ReadAll(c)
				_, _ = c.Write(append([]byte("got:"), data...))
			}()
		}
	}()
	return ln.Addr().String()
}

// localHost is a second gVisor stack acting as the machine whose packets are
// routed into the tunnel; it talks to the tunnel through the pipe device.
type localHost struct {
	ns *netStack
}

func newLocalHost(t *testing.T, dev tun.Device, addr netip.Addr) *localHost {
	t.Helper()
	ns, err := newNetStack(DefaultMTU, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := addr.As4()
	if terr := ns.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(a).WithPrefix(),
	}, stack.AddressProperties{}); terr != nil {
		t.Fatalf("add address: %v", terr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	onErr := func(err error) { t.Logf("local host pump: %v", err) }
	wg.Add(2)
	go func() { defer wg.Done(); pumpTunToStack(ctx, dev, ns.ep, onErr) }()
	go func() { defer wg.Done(); pumpStackToTun(ctx, dev, ns.ep, onErr) }()
	t.Cleanup(func() {
		cancel()
		_ = dev.Close()
		ns.close()
		wg.Wait()
	})
	return &localHost{ns: ns}
}

func (h *localHost) dialTCP(ctx context.Context, dst netip.AddrPort) (*gonet.TCPConn, error) {
	a := dst.Addr().As4()
	return gonet.DialContextTCP(ctx, h.ns.stack, tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(a), Port: dst.Port()}, ipv4.ProtocolNumber)
}

func (h *localHost) dialUDP(dst netip.AddrPort) (*gonet.UDPConn, error) {
	a := dst.Addr().As4()
	return gonet.DialUDP(h.ns.stack, nil, &tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(a), Port: dst.Port()}, ipv4.ProtocolNumber)
}
