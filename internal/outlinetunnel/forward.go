package outlinetunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// halfCloser is the half-close surface shared by gonet.TCPConn and the
// Shadowsocks stream.
type halfCloser interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// countReader counts bytes read through it into n.
type countReader struct {
	r io.Reader
	n *atomic.Uint64
}

func (c countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(uint64(n))
	return n, err
}

// tcpCopyBufSize is io.Copy's default buffer size, so pooling changes nothing
// about how data moves.
const tcpCopyBufSize = 32 * 1024

// tcpCopyBufPool recycles relay buffers so each forwarded connection does not
// allocate its own pair.
var tcpCopyBufPool = sync.Pool{New: func() any {
	b := make([]byte, tcpCopyBufSize)
	return &b
}}

// handleTCP is called by the stack for each new TCP connection. The handler
// runs on the packet path, so the work moves to a goroutine immediately.
func (t *Tunnel) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	if !t.spawn(func() { t.serveTCP(r, dst) }) {
		r.Complete(true)
	}
}

// serveTCP dials the destination through Shadowsocks first and only then
// accepts the client's connection, so a dead server shows up as a reset
// instead of a connection that hangs.
func (t *Tunnel) serveTCP(r *tcp.ForwarderRequest, dst string) {
	ctx, cancel := context.WithTimeout(t.ctx, dialTimeout)
	remote, err := t.dialer.DialStream(ctx, dst)
	cancel()
	if err != nil {
		if t.ctx.Err() == nil {
			// The destination is the user's traffic: it goes to the debug log
			// only, never into the recorded error or the warning.
			t.log.Debug("dial through the server failed", "dst", dst, "err", err)
			t.recordError(fmt.Errorf("could not open a TCP stream through the server: %w", err))
		}
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		_ = remote.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)

	t.tcpFlows.Add(1)
	defer t.tcpFlows.Add(-1)
	if !t.flows.add(local) {
		_ = remote.Close()
		return
	}
	defer t.flows.remove(local)
	if !t.flows.add(remote) {
		return
	}
	defer t.flows.remove(remote)
	defer local.Close()
	defer remote.Close()

	t.relayTCP(local, remote)
}

// relayTCP copies both directions. A clean EOF becomes a half-close of the
// peer so the other direction can finish; an error tears both sides down.
func (t *Tunnel) relayTCP(local, remote halfCloser) {
	done := make(chan struct{})
	started := t.spawn(func() {
		defer close(done)
		t.copyHalf(remote, local, &t.bytesOut, local, remote)
	})
	if !started {
		return
	}
	t.copyHalf(local, remote, &t.bytesIn, local, remote)
	<-done
}

// copyHalf copies src to dst; on error both ends close, on EOF only dst's
// write side does.
func (t *Tunnel) copyHalf(dst, src halfCloser, n *atomic.Uint64, a, b io.Closer) {
	bufp := tcpCopyBufPool.Get().(*[]byte)
	defer tcpCopyBufPool.Put(bufp)
	_, err := io.CopyBuffer(dst, countReader{r: src, n: n}, *bufp)
	if err != nil {
		_ = a.Close()
		_ = b.Close()
		return
	}
	_ = dst.CloseWrite()
}

// handleUDP is called by the stack for the first datagram of each (src, dst)
// pair; later datagrams of that pair go straight to the created endpoint. The
// flow is admitted to the table first, which closes the least recently used flow
// when the tunnel already holds MaxUDPFlows.
func (t *Tunnel) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	local := gonet.NewUDPConn(&wq, ep)
	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(dstIP, id.LocalPort))

	flow := newUDPFlow(t.now())
	t.udp.admit(flow)
	if !flow.add(local) || !t.spawn(func() { t.serveUDP(flow, local, dst) }) {
		flow.close()
		t.udp.remove(flow)
		_ = local.Close()
	}
}

// serveUDP relays datagrams of one flow until it idles out, is evicted, or
// fails. A flow to port 53 ends after its first reply: every DNS query is a new
// flow from a new source port, and holding each for the idle timeout would
// fill the table with finished lookups.
func (t *Tunnel) serveUDP(flow *udpFlow, local net.Conn, dst *net.UDPAddr) {
	defer t.udp.remove(flow)
	defer flow.close()
	defer local.Close()
	ctx, cancel := context.WithTimeout(t.ctx, dialTimeout)
	pc, err := t.dialer.ListenPacket(ctx)
	cancel()
	if err != nil {
		if t.ctx.Err() == nil {
			t.log.Debug("udp flow could not open", "dst", dst.String(), "err", err)
			t.recordError(fmt.Errorf("could not open a UDP flow through the server: %w", err))
		}
		return
	}
	defer pc.Close()

	t.udpFlows.Add(1)
	defer t.udpFlows.Add(-1)
	if !flow.add(pc) {
		return
	}
	if !t.flows.add(local) {
		return
	}
	defer t.flows.remove(local)
	if !t.flows.add(pc) {
		return
	}
	defer t.flows.remove(pc)

	// Activity in either direction postpones the idle drop; the timer closing
	// both sockets unblocks the two read loops.
	idle := time.AfterFunc(t.idle, flow.close)
	defer idle.Stop()
	oneShot := dst.Port == 53

	done := make(chan struct{})
	started := t.spawn(func() {
		defer close(done)
		defer flow.close()
		bufp := getUDPBuf()
		defer putUDPBuf(bufp)
		buf := *bufp
		for {
			n, err := local.Read(buf)
			if err != nil {
				return
			}
			idle.Reset(t.idle)
			flow.touch(t.now())
			if _, err := pc.WriteTo(buf[:n], dst); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.log.Debug("udp send failed", "dst", dst.String(), "err", err)
					t.recordError(fmt.Errorf("could not send a UDP datagram through the server: %w", err))
				}
				return
			}
			t.bytesOut.Add(uint64(n))
		}
	})
	if !started {
		return
	}
	bufp := getUDPBuf()
	defer putUDPBuf(bufp)
	buf := *bufp
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		idle.Reset(t.idle)
		flow.touch(t.now())
		if _, err := local.Write(buf[:n]); err != nil {
			break
		}
		t.bytesIn.Add(uint64(n))
		if oneShot {
			break
		}
	}
	flow.close()
	<-done
}
