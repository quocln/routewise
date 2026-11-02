package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/outlinetunnel"
)

// defaultOutlineDNS serves an Outline profile's names through its tunnel. It
// is routed into the utun as a /32, so every app's traffic to it goes through
// Outline while the profile is connected. 1.0.0.1 (Cloudflare's secondary)
// is used rather than 1.1.1.1, which RouteWise's own dns.servers and many
// Macs use as their main resolver.
const defaultOutlineDNS = "1.0.0.1"

// outlineKind runs a profile as an Outline (Shadowsocks) tunnel from an access
// key.
type outlineKind struct{}

func (outlineKind) displayName() string { return "Outline" }

func (outlineKind) pickSecret(wireguardConfig, accessKey string) (string, error) {
	if wireguardConfig != "" {
		return "", fmt.Errorf("%w: an Outline profile takes accessKey, not wireguardConfig", api.ErrRejected)
	}
	return accessKey, nil
}

func (outlineKind) validateSecret(secret string) (dns []string, label string, err error) {
	secret = strings.TrimSpace(secret)
	if isDynamicKey(secret) {
		// A dynamic key is fetched when the profile connects; here only its
		// shape is checked, so importing needs no network.
		if u, uerr := url.Parse(secret); uerr != nil || u.Host == "" {
			return nil, "", errors.New("invalid Outline key: the dynamic key is not a URL with a host")
		}
		return []string{defaultOutlineDNS}, "", nil
	}
	key, perr := outlinetunnel.ParseAccessKey(secret)
	if perr != nil {
		return nil, "", fmt.Errorf("invalid Outline key: %s", redact(perr.Error(), config.ProfileKindOutline, secret))
	}
	return []string{defaultOutlineDNS}, key.Tag, nil
}

func (outlineKind) redactionTokens(secret string) []string {
	if isDynamicKey(secret) {
		return nil
	}
	var out []string
	if key, err := outlinetunnel.ParseAccessKey(secret); err == nil {
		out = append(out, key.Password)
	}
	// The base64 userinfo of an ss:// key encodes the method and password.
	if rest, ok := strings.CutPrefix(strings.TrimSpace(secret), "ss://"); ok {
		if userinfo, _, found := strings.Cut(rest, "@"); found {
			out = append(out, userinfo)
		}
	}
	return out
}

// healthPolicy: a probe every outlineProbeInterval, and outlineFailuresToDown
// failures in a row, so a single lost probe does not flap the routes.
func (outlineKind) healthPolicy() healthPolicy {
	return healthPolicy{interval: outlineProbeInterval, failures: outlineFailuresToDown}
}

// start resolves the server afresh, so a reconnect picks up a new address.
func (outlineKind) start(ctx context.Context, req tunnelStartRequest, logger *slog.Logger) (builtinTunnel, error) {
	key, err := resolveOutlineKey(ctx, req.Secret)
	if err != nil {
		return nil, err
	}
	t, err := outlinetunnel.Start(ctx, key, outlinetunnel.Options{Address: req.Address, Logger: logger})
	if err != nil {
		return nil, err
	}
	return outlineAdapter{t: t, server: key.Addr(), dns: probeTarget(req.Profile.DNS)}, nil
}

// needsSyntheticAddress is true: an access key names no interface address.
func (outlineKind) needsSyntheticAddress() bool { return true }

// reservedAddrs is empty: the helper hands out an Outline utun's address itself.
func (outlineKind) reservedAddrs(func() (string, error)) []netip.Addr { return nil }

// checkUnique accepts everything: two Outline profiles may share a key.
func (outlineKind) checkUnique(string, func() []profileSecret) error { return nil }

// resolveOutlineKey turns the stored secret into a key: an ss:// key is
// parsed, an ssconf:// (or https://) dynamic key is fetched.
func resolveOutlineKey(ctx context.Context, secret string) (outlinetunnel.Key, error) {
	if isDynamicKey(secret) {
		return outlinetunnel.FetchDynamicKey(ctx, nil, secret)
	}
	return outlinetunnel.ParseAccessKey(secret)
}

func isDynamicKey(secret string) bool {
	s := strings.ToLower(strings.TrimSpace(secret))
	return strings.HasPrefix(s, "ssconf://") || strings.HasPrefix(s, "https://")
}

// probeTarget is the DNS server an Outline tunnel is probed through: the
// profile's first IPv4 DNS server on port 53, or the default when it names none.
func probeTarget(dns []string) netip.AddrPort {
	for _, text := range dns {
		if a, err := netip.ParseAddr(text); err == nil && a.Is4() && !a.IsUnspecified() {
			return netip.AddrPortFrom(a, 53)
		}
	}
	return netip.AddrPortFrom(netip.MustParseAddr(defaultOutlineDNS), 53)
}

type outlineAdapter struct {
	t      *outlinetunnel.Tunnel
	server string
	dns    netip.AddrPort
}

func (a outlineAdapter) AllowedIPs() []netip.Prefix { return nil }

func (a outlineAdapter) Check(ctx context.Context, _ time.Time) error { return a.t.Probe(ctx, a.dns) }

func (a outlineAdapter) Name() string          { return a.t.Name() }
func (a outlineAdapter) Stop() error           { return a.t.Stop() }
func (a outlineAdapter) Done() <-chan struct{} { return a.t.Done() }
func (a outlineAdapter) Server() string        { return a.server }

func (a outlineAdapter) Endpoints() []netip.Addr {
	if addr := a.t.ServerAddr().Addr().Unmap(); addr.Is4() {
		return []netip.Addr{addr}
	}
	return nil
}

func (a outlineAdapter) IPv6Transport() bool {
	return !a.t.ServerAddr().Addr().Unmap().Is4()
}

func (a outlineAdapter) Stats() *api.ProfileStats {
	st := a.t.Stats()
	tcp, udp := st.TCPFlows, st.UDPFlows
	return &api.ProfileStats{RxBytes: st.BytesIn, TxBytes: st.BytesOut, TCPFlows: &tcp, UDPFlows: &udp}
}
