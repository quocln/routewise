package wgtunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/quocln/routewise/internal/tunnelnet"
)

// Resolver turns an endpoint host name into addresses. It is injectable so
// tests and the daemon can control (and bound) name resolution.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// DefaultResolver uses the system resolver. It runs before the tunnel exists,
// so a profile's own endpoint name is never looked up through that tunnel.
func DefaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ResolveEndpoints resolves every peer endpoint, keyed by the peer public key.
// IPv4 is preferred; an IPv6 address is used only when the name has no A
// record. Peers without an endpoint are omitted.
func (c Config) ResolveEndpoints(ctx context.Context, resolve Resolver) (map[Key]netip.AddrPort, error) {
	if resolve == nil {
		resolve = DefaultResolver
	}
	out := make(map[Key]netip.AddrPort, len(c.Peers))
	for i, p := range c.Peers {
		if p.Endpoint.IsZero() {
			continue
		}
		if a, err := netip.ParseAddr(p.Endpoint.Host); err == nil {
			out[p.PublicKey] = netip.AddrPortFrom(a.Unmap(), p.Endpoint.Port)
			continue
		}
		addrs, err := resolve(ctx, p.Endpoint.Host)
		if err != nil {
			return nil, fmt.Errorf("resolve endpoint of peer %d (%s): %w", i+1, p.Endpoint.Host, err)
		}
		chosen, ok := tunnelnet.PreferIPv4(addrs)
		if !ok {
			return nil, fmt.Errorf("resolve endpoint of peer %d (%s): no addresses", i+1, p.Endpoint.Host)
		}
		out[p.PublicKey] = netip.AddrPortFrom(chosen, p.Endpoint.Port)
	}
	return out, nil
}

// UAPI renders the configuration in the WireGuard cross-platform userspace
// protocol (the text accepted by Device.IpcSet). resolved maps each peer public
// key to its already-resolved endpoint; a peer that has an endpoint host but no
// entry is an error rather than being silently left unreachable.
//
// replace_peers and replace_allowed_ips make the text idempotent: applying it
// again yields exactly this configuration.
func (c Config) UAPI(resolved map[Key]netip.AddrPort) (string, error) {
	var b strings.Builder
	line := func(k, v string) {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}

	line("private_key", c.PrivateKey.hex())
	if c.ListenPort > 0 {
		line("listen_port", strconv.Itoa(c.ListenPort))
	}
	line("replace_peers", "true")

	for i, p := range c.Peers {
		line("public_key", p.PublicKey.hex())
		if !p.PresharedKey.IsZero() {
			line("preshared_key", p.PresharedKey.hex())
		}
		if !p.Endpoint.IsZero() {
			ep, ok := resolved[p.PublicKey]
			if !ok || !ep.IsValid() {
				return "", fmt.Errorf("peer %d has endpoint %q but no resolved address", i+1, p.Endpoint.Host)
			}
			line("endpoint", ep.String())
		}
		if p.PersistentKeepalive > 0 {
			line("persistent_keepalive_interval", strconv.Itoa(p.PersistentKeepalive))
		}
		line("replace_allowed_ips", "true")
		for _, ip := range p.AllowedIPs {
			line("allowed_ip", ip.String())
		}
	}
	return b.String(), nil
}
