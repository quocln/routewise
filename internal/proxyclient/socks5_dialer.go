package proxyclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/socks5"
)

const (
	// noAcceptableMethod is how the SDK reports the RFC 1928 "no acceptable methods"
	// reply (0xFF). It has no error value for it, so a test holds this text to the SDK.
	noAcceptableMethod = "authentication method 255"
	// authRefused starts the SDK's error for a refused username and password.
	authRefused = "authentication failed"
)

// SOCKS5Dialer opens flows through one proxy. It holds a client with the credentials, when
// there are any, and one without: the SDK offers a proxy a single method, and a proxy
// that needs no password answers an offer of a password by refusing it.
type SOCKS5Dialer struct {
	withCredentials *socks5.Client
	anonymous       *socks5.Client
	// noCredentialsNeeded remembers that the proxy refused the offer, so each flow
	// after the first skips the round trip.
	noCredentialsNeeded atomic.Bool
}

// NewSOCKS5Dialer builds the dialer for a proxy whose host was resolved to server.
func NewSOCKS5Dialer(c Config, server netip.AddrPort) (*SOCKS5Dialer, error) {
	newClient := func() (*socks5.Client, error) {
		client, err := socks5.NewClient(watchedEndpoint{endpoint: &transport.TCPEndpoint{Address: server.String()}})
		if err != nil {
			return nil, fmt.Errorf("socks5 client: %w", err)
		}
		client.EnablePacket(&transport.UDPDialer{})
		return client, nil
	}
	anonymous, err := newClient()
	if err != nil {
		return nil, err
	}
	d := &SOCKS5Dialer{anonymous: anonymous}
	if c.Username != "" {
		if d.withCredentials, err = newClient(); err != nil {
			return nil, err
		}
		if err := d.withCredentials.SetCredentials([]byte(c.Username), []byte(c.Password)); err != nil {
			return nil, errors.New("the proxy username or password is not usable")
		}
	}
	return d, nil
}

// connect runs one request through the client that fits the proxy.
func connect[T any](ctx context.Context, d *SOCKS5Dialer, request func(context.Context, *socks5.Client) (T, error)) (T, error) {
	if d.withCredentials != nil && !d.noCredentialsNeeded.Load() {
		out, err := withinContext(ctx, d.withCredentials, request)
		if err == nil || !strings.Contains(err.Error(), noAcceptableMethod) {
			return out, explain(err)
		}
		out, err = withinContext(ctx, d.anonymous, request)
		if err != nil {
			// It refuses the credentials and takes nothing else either.
			return out, explain(err)
		}
		d.noCredentialsNeeded.Store(true)
		return out, nil
	}
	out, err := withinContext(ctx, d.anonymous, request)
	return out, explain(err)
}

// withinContext makes ctx bound the whole of one request. The SDK uses ctx only to
// connect, and then waits for the proxy's replies with no limit, so a proxy that
// accepts and goes quiet would hold a flow, or a health check, for good. Only the
// handshake is bounded: the stream outlives ctx, which callers cancel once it is open.
func withinContext[T any](ctx context.Context, client *socks5.Client, request func(context.Context, *socks5.Client) (T, error)) (T, error) {
	h := &handshake{}
	defer h.finish()
	return request(context.WithValue(ctx, handshakeKey{}, h), client)
}

// watchedEndpoint connects to the proxy and enrols the connection in its handshake.
type watchedEndpoint struct {
	endpoint transport.StreamEndpoint
}

func (e watchedEndpoint) ConnectStream(ctx context.Context) (transport.StreamConn, error) {
	conn, err := e.endpoint.ConnectStream(ctx)
	if err != nil {
		return nil, err
	}
	if h, ok := ctx.Value(handshakeKey{}).(*handshake); ok {
		h.watch(ctx, conn)
	}
	return conn, nil
}

// explain turns the SDK's handshake errors into the ones a person can act on.
func explain(err error) error {
	switch {
	case err == nil:
		return nil
	case strings.Contains(err.Error(), noAcceptableMethod):
		return ErrAuthRequired
	case strings.Contains(err.Error(), authRefused):
		return ErrAuthRefused
	default:
		return err
	}
}

// DialStream opens a TCP stream through the proxy to addr (ip:port).
func (d *SOCKS5Dialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	return connect(ctx, d, func(ctx context.Context, c *socks5.Client) (transport.StreamConn, error) {
		return c.DialStream(ctx, addr)
	})
}

// ListenPacket opens a UDP flow. Nothing reaches the proxy until the first datagram.
func (d *SOCKS5Dialer) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return newPacketConn(ctx, d, d.associate)
}

// associate opens a UDP relay through the proxy.
func (d *SOCKS5Dialer) associate(ctx context.Context) (net.PacketConn, error) {
	pc, err := connect(ctx, d, func(ctx context.Context, c *socks5.Client) (net.PacketConn, error) {
		return c.ListenPacket(ctx)
	})
	if errors.Is(err, socks5.ErrCommandNotSupported) {
		return nil, ErrUDPUnsupported
	}
	return pc, err
}

// Check proves the proxy answers and accepts the credentials: see proxy_check.go. A
// proxy that reports the target unreachable or forbidden has done its job, while a
// general failure, a hang or a refused login counts as down.
func (d *SOCKS5Dialer) Check(ctx context.Context) error {
	return check(ctx, d, func(err error) bool {
		for _, about := range []socks5.ReplyCode{
			socks5.ErrConnectionNotAllowedByRuleset, socks5.ErrNetworkUnreachable,
			socks5.ErrHostUnreachable, socks5.ErrConnectionRefused, socks5.ErrTTLExpired,
		} {
			if errors.Is(err, about) {
				return true
			}
		}
		return false
	})
}
