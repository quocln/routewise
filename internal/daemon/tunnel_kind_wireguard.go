package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/wgtunnel"
)

// wireguardKind runs a profile as a WireGuard tunnel from a .conf.
type wireguardKind struct{}

func (wireguardKind) displayName() string { return "WireGuard" }

func (wireguardKind) pickSecret(wireguardConfig, accessKey string) (string, error) {
	if accessKey != "" {
		return "", fmt.Errorf("%w: a WireGuard profile takes wireguardConfig, not accessKey", api.ErrRejected)
	}
	return wireguardConfig, nil
}

func (wireguardKind) validateSecret(secret string) (dns []string, label string, err error) {
	cfg, perr := wgtunnel.Parse(secret)
	if perr != nil {
		return nil, "", fmt.Errorf("invalid WireGuard config: %s", redact(perr.Error(), config.ProfileKindWireGuard, secret))
	}
	for _, a := range cfg.DNS {
		if a.Is4() && !a.IsUnspecified() {
			dns = append(dns, a.String())
		}
	}
	return dns, "", nil
}

func (wireguardKind) redactionTokens(secret string) []string {
	var out []string
	for line := range strings.SplitSeq(secret, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "privatekey", "presharedkey":
			out = append(out, v)
		}
	}
	return out
}

// healthPolicy: the handshake window is itself the hysteresis, so one failed
// check is enough to go unhealthy.
func (wireguardKind) healthPolicy() healthPolicy {
	return healthPolicy{interval: wgCheckInterval, failures: 1}
}

// start resolves each peer endpoint afresh, so a reconnect picks up new
// addresses.
func (wireguardKind) start(ctx context.Context, req tunnelStartRequest, logger *slog.Logger) (builtinTunnel, error) {
	cfg, err := wgtunnel.Parse(req.Secret)
	if err != nil {
		return nil, err
	}
	t, err := wgtunnel.Start(ctx, cfg, wgtunnel.Options{Logger: logger})
	if err != nil {
		return nil, err
	}
	server := ""
	for _, p := range cfg.Peers {
		if !p.Endpoint.IsZero() {
			server = p.Endpoint.String()
			break
		}
	}
	return wgAdapter{t: t, server: server}, nil
}

// needsSyntheticAddress is false: the .conf names the interface address.
func (wireguardKind) needsSyntheticAddress() bool { return false }

func (wireguardKind) reservedAddrs(load func() (string, error)) []netip.Addr {
	stored, err := load()
	if err != nil {
		return nil
	}
	cfg, err := wgtunnel.Parse(stored)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range cfg.IPv4Addresses() {
		out = append(out, a.Addr())
	}
	return out
}

// checkUnique rejects a WireGuard config whose private key, interface address,
// or fixed listen port another WireGuard profile already uses: two tunnels with
// one key evict each other at the server, two with one address cannot both be
// addressed, and the second of two with one listen port could never bind it.
func (wireguardKind) checkUnique(secret string, others func() []profileSecret) error {
	mine, err := wgtunnel.Parse(secret)
	if err != nil {
		return nil // validateSecret already reported it
	}
	myAddrs := make(map[netip.Addr]bool)
	for _, a := range mine.IPv4Addresses() {
		myAddrs[a.Addr()] = true
	}
	for _, other := range others() {
		theirs, err := wgtunnel.Parse(other.secret)
		if err != nil {
			continue
		}
		if theirs.PrivateKey == mine.PrivateKey {
			return fmt.Errorf("%w: this WireGuard key is already used by profile %s", api.ErrRejected, other.name)
		}
		if mine.ListenPort > 0 && theirs.ListenPort == mine.ListenPort {
			return fmt.Errorf("%w: listen port %d is already used by profile %s", api.ErrRejected, mine.ListenPort, other.name)
		}
		for _, a := range theirs.IPv4Addresses() {
			if myAddrs[a.Addr()] {
				return fmt.Errorf("%w: address %s is already used by profile %s", api.ErrRejected, a.Addr(), other.name)
			}
		}
	}
	return nil
}

type wgAdapter struct {
	t       *wgtunnel.Tunnel
	server  string
	allowed []netip.Prefix
}

func (a wgAdapter) AllowedIPs() []netip.Prefix { return a.allowed }

func (a wgAdapter) Check(_ context.Context, now time.Time) error {
	last, ok, err := a.t.LastHandshake()
	if err != nil {
		return err
	}
	return checkHandshake(last, ok, now)
}

func (a wgAdapter) Name() string          { return a.t.Name() }
func (a wgAdapter) Stop() error           { a.t.Stop(); return nil }
func (a wgAdapter) Done() <-chan struct{} { return a.t.Done() }
func (a wgAdapter) Server() string        { return a.server }

func (a wgAdapter) Endpoints() []netip.Addr {
	var out []netip.Addr
	for _, ep := range a.t.PeerEndpoints() {
		if addr := ep.Addr().Unmap(); addr.Is4() {
			out = append(out, addr)
		}
	}
	return out
}

func (a wgAdapter) IPv6Transport() bool {
	return slices.ContainsFunc(a.t.PeerEndpoints(), func(ep netip.AddrPort) bool { return !ep.Addr().Unmap().Is4() })
}

func (a wgAdapter) Stats() *api.ProfileStats {
	st, err := a.t.Stats()
	if err != nil {
		return &api.ProfileStats{}
	}
	out := &api.ProfileStats{}
	var last time.Time
	for _, p := range st.Peers {
		out.RxBytes += p.RxBytes
		out.TxBytes += p.TxBytes
		if p.LastHandshake.After(last) {
			last = p.LastHandshake
		}
	}
	if !last.IsZero() {
		ms := last.UnixMilli()
		out.LastHandshakeMs = &ms
	}
	return out
}
