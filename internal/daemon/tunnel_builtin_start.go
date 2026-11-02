package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
)

// builtinTunnel is a running built-in VPN as the tunnel manager sees it. The
// WireGuard and Outline packages are adapted to it so the manager, and the
// tests, never depend on a real utun.
type builtinTunnel interface {
	// Name is the utun interface.
	Name() string
	// Stop tears the tunnel down; it is idempotent.
	Stop() error
	// Done closes when the tunnel stops being usable.
	Done() <-chan struct{}
	// Endpoints are the transport addresses (WireGuard peer endpoints, the
	// Outline server) that must never be routed into any tunnel.
	Endpoints() []netip.Addr
	// IPv6Transport reports whether the tunnel connects over IPv6, so that
	// blocking IPv6 would cut its own traffic.
	IPv6Transport() bool
	// Server is the remote host:port, as shown to the user.
	Server() string
	// Stats is the live traffic view.
	Stats() *api.ProfileStats
	// Check measures at now whether the tunnel is proven to carry traffic, and
	// returns nil when it is. An error wrapping errNotProvenYet means it has not
	// worked yet, as opposed to having stopped working. It must honor ctx.
	Check(ctx context.Context, now time.Time) error
	// AllowedIPs are the destinations the tunnel's peers accept, as a non-nil
	// slice; nil means the tunnel carries any destination.
	AllowedIPs() []netip.Prefix
}

// tunnelStartRequest is everything needed to start one tunnel. Secret is the
// stored .conf text or access key; it must never be logged.
type tunnelStartRequest struct {
	Profile config.TunnelProfile
	Secret  string
	// Address is the /32 for an Outline utun; WireGuard uses its .conf address.
	Address netip.Addr
}

// tunnelStarter starts a tunnel. Tests replace it. The production starter,
// startBuiltinTunnel, hands the request to the profile's tunnelKind.
type tunnelStarter func(ctx context.Context, req tunnelStartRequest, logger *slog.Logger) (builtinTunnel, error)
