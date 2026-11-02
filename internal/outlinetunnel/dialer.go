package outlinetunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"

	"github.com/quocln/routewise/internal/tunnelnet"
)

// Dialer is how forwarded flows leave through the Shadowsocks server. It is an
// interface so tests can stand in for a real server.
type Dialer interface {
	// DialStream opens a proxied TCP stream to addr (ip:port).
	DialStream(ctx context.Context, addr string) (transport.StreamConn, error)
	// ListenPacket opens a proxied UDP socket; each WriteTo names the target.
	ListenPacket(ctx context.Context) (net.PacketConn, error)
}

// DialerFactory builds the Dialer for a key whose server host was resolved to
// server. It is called once per tunnel.
type DialerFactory func(key Key, server netip.AddrPort) (Dialer, error)

// ssDialer is the production Dialer over the SDK.
type ssDialer struct {
	stream   *shadowsocks.StreamDialer
	listener shadowsocks.PacketListener
}

// NewShadowsocksDialer is the default DialerFactory. It connects to the
// pre-resolved server address so no DNS lookup can recurse into the tunnel.
func NewShadowsocksDialer(key Key, server netip.AddrPort) (Dialer, error) {
	ek, err := key.encryptionKey()
	if err != nil {
		return nil, err
	}
	addr := server.String()
	sd, err := shadowsocks.NewStreamDialer(&transport.TCPEndpoint{Address: addr}, ek)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks stream dialer: %w", err)
	}
	pl, err := shadowsocks.NewPacketListener(&transport.UDPEndpoint{Address: addr}, ek)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks packet listener: %w", err)
	}
	if len(key.Prefix) > 0 {
		sg := shadowsocks.NewPrefixSaltGenerator(key.Prefix)
		sd.SaltGenerator = sg
		pl.SetSaltGenerator(sg)
	}
	return &ssDialer{stream: sd, listener: pl}, nil
}

func (d *ssDialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	return d.stream.DialStream(ctx, addr)
}

func (d *ssDialer) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return d.listener.ListenPacket(ctx)
}

// Resolver resolves the server host name. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// resolveServer returns the server's IPv4-preferred address. IP literals skip
// the resolver.
func resolveServer(ctx context.Context, r Resolver, key Key) (netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(key.Host); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), key.Port), nil
	}
	addrs, err := r.LookupNetIP(ctx, "ip", key.Host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve server %q: %w", key.Host, err)
	}
	if a, ok := tunnelnet.PreferIPv4(addrs); ok {
		return netip.AddrPortFrom(a, key.Port), nil
	}
	return netip.AddrPort{}, fmt.Errorf("resolve server %q: no addresses", key.Host)
}
