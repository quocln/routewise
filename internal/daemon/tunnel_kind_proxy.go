package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/outlinetunnel"
	"github.com/quocln/routewise/internal/proxyclient"
)

// proxyDialer is what a tunnel through a proxy needs of its protocol.
type proxyDialer interface {
	outlinetunnel.Dialer
	Check(ctx context.Context) error
}

// proxyKind runs a profile as a tunnel through a proxy, from a
// scheme://[username:password@]host:port secret. It shares Outline's tunnel, whose
// flows leave through whatever dialer it is given. Its DNS default and health pacing
// are Outline's too, since nothing about either depends on the protocol.
type proxyKind struct {
	name      string
	label     string
	protocol  proxyclient.Protocol
	newDialer func(proxyclient.Config, netip.AddrPort) (proxyDialer, error)
}

var socks5Kind = proxyKind{
	name: "SOCKS5", label: config.ProfileKindSOCKS5, protocol: proxyclient.SOCKS5,
	newDialer: func(c proxyclient.Config, server netip.AddrPort) (proxyDialer, error) {
		return proxyclient.NewSOCKS5Dialer(c, server)
	},
}

var httpProxyKind = proxyKind{
	name: "HTTP proxy", label: config.ProfileKindHTTP, protocol: proxyclient.HTTP,
	newDialer: func(c proxyclient.Config, server netip.AddrPort) (proxyDialer, error) {
		return proxyclient.NewHTTPDialer(c, server), nil
	},
}

func (k proxyKind) displayName() string { return k.name }

func (k proxyKind) pickSecret(wireguardConfig, accessKey string) (string, error) {
	if wireguardConfig != "" {
		return "", fmt.Errorf("%w: a %s profile takes accessKey, not wireguardConfig", api.ErrRejected, k.name)
	}
	return accessKey, nil
}

func (k proxyKind) validateSecret(secret string) (dns []string, label string, err error) {
	cfg, err := proxyclient.ParseURL(k.protocol, secret)
	if err != nil {
		return nil, "", fmt.Errorf("invalid %s: %w", k.name, err)
	}
	return []string{defaultOutlineDNS}, cfg.Host, nil
}

func (k proxyKind) redactionTokens(secret string) []string {
	cfg, err := proxyclient.ParseURL(k.protocol, secret)
	if err != nil {
		return nil
	}
	var out []string
	// The URL holds them percent-encoded, which may differ from what they decode to.
	// The whole login goes first: redacting a part of it would hide it from a later match.
	if u, err := url.Parse(strings.TrimSpace(secret)); err == nil && u.User != nil {
		login := u.User.String()
		username, password, _ := strings.Cut(login, ":")
		out = append(out, login, password, username)
	}
	return append(out, cfg.Password, cfg.Username)
}

// healthPolicy: like Outline, except that a wrong password or a server that is no
// proxy shows at once, instead of as "connecting" for the length of three probes.
func (proxyKind) healthPolicy() healthPolicy {
	return healthPolicy{interval: outlineProbeInterval, failures: outlineFailuresToDown, conclusive: proxyclient.IsRefusal}
}

// start resolves the proxy afresh, so a reconnect picks up a new address.
func (k proxyKind) start(ctx context.Context, req tunnelStartRequest, logger *slog.Logger) (builtinTunnel, error) {
	cfg, err := proxyclient.ParseURL(k.protocol, req.Secret)
	if err != nil {
		return nil, err
	}
	server, err := cfg.Resolve(ctx, net.DefaultResolver)
	if err != nil {
		return nil, err
	}
	dialer, err := k.newDialer(cfg, server)
	if err != nil {
		return nil, err
	}
	t, err := outlinetunnel.StartWithDialer(ctx, server, dialer, outlinetunnel.Options{
		Address: req.Address, Logger: logger, Label: k.label,
	})
	if err != nil {
		return nil, err
	}
	return proxyAdapter{t: t, dialer: dialer, host: cfg.HostPort()}, nil
}

// needsSyntheticAddress is true: a proxy address names no interface address.
func (proxyKind) needsSyntheticAddress() bool { return true }

func (proxyKind) reservedAddrs(func() (string, error)) []netip.Addr { return nil }

func (proxyKind) checkUnique(string, func() []profileSecret) error { return nil }

type proxyAdapter struct {
	t      *outlinetunnel.Tunnel
	dialer proxyDialer
	host   string
}

func (a proxyAdapter) AllowedIPs() []netip.Prefix { return nil }

func (a proxyAdapter) Check(ctx context.Context, _ time.Time) error { return a.dialer.Check(ctx) }

func (a proxyAdapter) Name() string          { return a.t.Name() }
func (a proxyAdapter) Stop() error           { return a.t.Stop() }
func (a proxyAdapter) Done() <-chan struct{} { return a.t.Done() }
func (a proxyAdapter) Server() string        { return a.host }

// Endpoints is empty for a proxy on this machine, such as ssh -D. It needs no route
// through the LAN, and a route to 127.0.0.1 through the LAN would break it. What it
// connects onward to is not known here, which is also why such a proxy cannot be the
// default VPN: see carryAllReason.
func (a proxyAdapter) Endpoints() []netip.Addr { return proxyEndpoints(a.t.ServerAddr().Addr()) }

func proxyEndpoints(server netip.Addr) []netip.Addr {
	if server = server.Unmap(); server.Is4() && !server.IsLoopback() {
		return []netip.Addr{server}
	}
	return nil
}

func (a proxyAdapter) IPv6Transport() bool { return proxyIPv6Transport(a.t.ServerAddr().Addr()) }

func proxyIPv6Transport(server netip.Addr) bool {
	server = server.Unmap()
	return !server.Is4() && !server.IsLoopback()
}

func (a proxyAdapter) Stats() *api.ProfileStats {
	st := a.t.Stats()
	tcp, udp := st.TCPFlows, st.UDPFlows
	return &api.ProfileStats{RxBytes: st.BytesIn, TxBytes: st.BytesOut, TCPFlows: &tcp, UDPFlows: &udp}
}
