package wgtunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/quocln/routewise/internal/tunnelnet"
)

// DefaultMTU is wg-quick's default and leaves room for the WireGuard overhead
// on a 1500-byte path.
const DefaultMTU = 1420

// Options carries the injectable collaborators of Start. Every field is
// optional.
type Options struct {
	// Runner executes ifconfig on macOS. Defaults to ExecRunner. Unused when
	// Links is set, and on Linux, where addresses are set over netlink.
	Runner CommandRunner
	// Links addresses and raises the interface. Defaults to
	// tunnelnet.SystemLinks over Runner. Tests inject a recorder so no root or
	// real device is needed.
	Links tunnelnet.Links
	// Resolver resolves endpoint host names. Defaults to DefaultResolver.
	Resolver Resolver
	// Logger receives wireguard-go's log output at debug (errors at error).
	// Defaults to slog.Default().
	Logger *slog.Logger
	// CreateTUN opens the device. Defaults to tunnelnet.CreateTUN.
	// Tests inject an in-memory device so no root is needed.
	CreateTUN func(mtu int) (tun.Device, error)
}

// Tunnel is a running WireGuard device bound to a helper-owned utun.
type Tunnel struct {
	name string
	dev  *device.Device

	stopOnce sync.Once
}

// Start brings up a tunnel for cfg: it creates the utun, configures the
// device, assigns the IPv4 addresses and starts the device. It never adds
// routes. If any step fails, everything created so far is torn down.
func Start(ctx context.Context, cfg Config, opts Options) (*Tunnel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if opts.Links == nil {
		opts.Links = tunnelnet.SystemLinks{Run: opts.Runner}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.CreateTUN == nil {
		opts.CreateTUN = tunnelnet.CreateTUN
	}

	// Resolve and render before touching the system so a bad profile or a
	// failed lookup creates nothing.
	cfg = EnsureKeepalive(cfg)
	resolved, err := cfg.ResolveEndpoints(ctx, opts.Resolver)
	if err != nil {
		return nil, err
	}
	uapi, err := cfg.UAPI(resolved)
	if err != nil {
		return nil, err
	}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	tunDev, err := opts.CreateTUN(mtu)
	if err != nil {
		return nil, fmt.Errorf("create tunnel device: %w", err)
	}
	name, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("read tunnel device name: %w", err)
	}

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), deviceLogger(opts.Logger, name))
	// From here the device owns the tun: Device.Close closes it too.
	fail := func(step string, err error) (*Tunnel, error) {
		dev.Close()
		return nil, fmt.Errorf("%s on %s: %w", step, name, err)
	}

	if err := dev.IpcSet(uapi); err != nil {
		return fail("configure device", err)
	}
	if err := assignAddresses(ctx, opts.Links, name, cfg.Addresses); err != nil {
		return fail("assign addresses", err)
	}
	if err := dev.Up(); err != nil {
		return fail("bring device up", err)
	}
	return &Tunnel{name: name, dev: dev}, nil
}

// Name returns the real interface name (for example "utun7").
func (t *Tunnel) Name() string { return t.name }

// Done is closed when the device is closed, by Stop or by wireguard-go itself
// after a fatal utun error. A caller that supervises the tunnel restarts it
// when Done closes.
func (t *Tunnel) Done() <-chan struct{} { return t.dev.Wait() }

// Stop closes the device and its utun. It is idempotent and safe to call from
// several goroutines; the interface disappears once it returns.
func (t *Tunnel) Stop() {
	t.stopOnce.Do(func() { t.dev.Close() })
}

// Stats reads the live per-peer state from the device.
func (t *Tunnel) Stats() (Stats, error) {
	text, err := t.dev.IpcGet()
	if err != nil {
		return Stats{}, fmt.Errorf("read device state: %w", err)
	}
	return ParseStats(text)
}

// LastHandshake returns the most recent completed handshake over all peers, and
// false when none has completed yet.
func (t *Tunnel) LastHandshake() (time.Time, bool, error) {
	st, err := t.Stats()
	if err != nil {
		return time.Time{}, false, err
	}
	var last time.Time
	for _, p := range st.Peers {
		if p.LastHandshake.After(last) {
			last = p.LastHandshake
		}
	}
	return last, !last.IsZero(), nil
}

// PeerEndpoints returns the endpoints actually in use (after any roaming).
// Peers with no known endpoint are omitted. It returns nil if the device state
// cannot be read.
func (t *Tunnel) PeerEndpoints() []netip.AddrPort {
	st, err := t.Stats()
	if err != nil {
		return nil
	}
	var out []netip.AddrPort
	for _, p := range st.Peers {
		if p.Endpoint.IsValid() {
			out = append(out, p.Endpoint)
		}
	}
	return out
}

// deviceLogger adapts wireguard-go's logger to slog: verbose output is debug
// noise, errors are real errors.
func deviceLogger(l *slog.Logger, name string) *device.Logger {
	l = l.With("component", "wireguard", "iface", name)
	return &device.Logger{
		Verbosef: func(format string, args ...any) { l.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { l.Error(fmt.Sprintf(format, args...)) },
	}
}
