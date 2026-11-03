package proxyclient

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	dnsPort = 53
	// dnsExchangeTimeout bounds one query carried over TCP, dial included.
	dnsExchangeTimeout = 10 * time.Second
	// associateTimeout bounds opening the UDP relay.
	associateTimeout = 10 * time.Second
	// pendingDNSReplies is how many answers may wait to be read. A resolver that
	// retries before the first answer can earn more than one, and the flow ends after
	// the first it reads.
	pendingDNSReplies = 4
)

type dnsReply struct {
	body []byte
	from net.Addr
}

// packetConn is one UDP flow of the tunnel. A flow to port 53 is carried over TCP:
// an HTTP proxy cannot relay UDP and many SOCKS5 proxies do not, and a machine whose lookups fail is broken in a way that
// every other kind of UDP failing is not, since apps fall back from QUIC by themselves.
// Any other flow opens the proxy's UDP relay at its first datagram, so a DNS query
// costs no relay it would not use.
type packetConn struct {
	streams streamDialer
	// associate opens the proxy's UDP relay.
	associate func(context.Context) (net.PacketConn, error)
	ctx       context.Context
	cancel    context.CancelFunc

	dnsReplies chan dnsReply

	// relayReady closes once relay is set, after which relay is read without mu.
	relayReady chan struct{}
	mu         sync.Mutex
	relay      net.PacketConn
	closeOnce  sync.Once
}

func newPacketConn(ctx context.Context, streams streamDialer, associate func(context.Context) (net.PacketConn, error)) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The flow outlives ctx, which bounds only opening it.
	flow, cancel := context.WithCancel(context.Background())
	return &packetConn{
		streams: streams, associate: associate, ctx: flow, cancel: cancel,
		dnsReplies: make(chan dnsReply, pendingDNSReplies),
		relayReady: make(chan struct{}),
	}, nil
}

// WriteTo sends one datagram. A query goes off on its own stream without waiting for
// the answer, which arrives through ReadFrom as a datagram's would.
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, net.ErrClosed
	}
	if udp, ok := addr.(*net.UDPAddr); ok && udp.Port == dnsPort {
		if len(b) > 0xFFFF {
			return 0, errors.New("a DNS query is too long")
		}
		query := append(make([]byte, 0, len(b)), b...)
		go c.exchangeDNS(query, addr)
		return len(b), nil
	}
	relay, err := c.openRelay()
	if err != nil {
		return 0, err
	}
	return relay.WriteTo(b, addr)
}

func (c *packetConn) openRelay() (net.PacketConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.relay != nil {
		return c.relay, nil
	}
	ctx, cancel := context.WithTimeout(c.ctx, associateTimeout)
	defer cancel()
	relay, err := c.associate(ctx)
	if err != nil {
		return nil, fmt.Errorf("open the proxy's UDP relay: %w", err)
	}
	if c.ctx.Err() != nil {
		_ = relay.Close()
		return nil, net.ErrClosed
	}
	c.relay = relay
	close(c.relayReady)
	return relay, nil
}

// exchangeDNS asks one query in TCP framing. A failure is a lost datagram: the
// resolver retries or moves on, as it would with UDP.
func (c *packetConn) exchangeDNS(query []byte, server net.Addr) {
	ctx, cancel := context.WithTimeout(c.ctx, dnsExchangeTimeout)
	defer cancel()
	conn, err := c.streams.DialStream(ctx, server.String())
	if err != nil {
		return
	}
	defer conn.Close()
	// Closing the stream is what interrupts a blocked read or write.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	framed := binary.BigEndian.AppendUint16(make([]byte, 0, len(query)+2), uint16(len(query)))
	if _, err := conn.Write(append(framed, query...)); err != nil {
		return
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return
	}
	body := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return
	}
	select {
	case c.dnsReplies <- dnsReply{body: body, from: server}:
	default:
	}
}

// ReadFrom returns the next datagram: an answer carried over TCP, or what the relay
// delivers once a datagram has opened it.
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case reply := <-c.dnsReplies:
		if len(reply.body) > len(b) {
			return 0, nil, io.ErrShortBuffer
		}
		return copy(b, reply.body), reply.from, nil
	case <-c.relayReady:
		return c.relay.ReadFrom(b)
	}
}

// Close ends the flow and what it holds open at the proxy.
func (c *packetConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.cancel()
		// Waiting here for a relay being opened is bounded by the cancel above.
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.relay != nil {
			err = c.relay.Close()
		}
	})
	return err
}

// LocalAddr is unspecified: the flow's sockets belong to its streams and its relay.
func (c *packetConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

// The tunnel ends a flow by closing it, so deadlines are not needed.
func (c *packetConn) SetDeadline(time.Time) error      { return nil }
func (c *packetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *packetConn) SetWriteDeadline(time.Time) error { return nil }
