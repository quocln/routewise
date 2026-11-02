package outlinetunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/quocln/routewise/internal/tunnelnet"
)

const (
	// DefaultMTU matches a standard Ethernet path; the Shadowsocks overhead is
	// carried by the outer connection, not by this interface.
	DefaultMTU = 1500
	// DefaultUDPIdleTimeout is how long a UDP flow may stay silent before it is
	// dropped.
	DefaultUDPIdleTimeout = 60 * time.Second
	// dialTimeout bounds opening one proxied flow.
	dialTimeout = 10 * time.Second
)

// DefaultAddress is used when Options.Address is unset. Callers that run more
// than one tunnel must pass distinct addresses from 10.233.0.0/16.
var DefaultAddress = netip.MustParseAddr("10.233.0.2")

// CommandRunner executes an external command and returns its combined output.
// name must be an absolute path.
type CommandRunner = tunnelnet.CommandRunner

// ExecRunner runs real commands via os/exec, refusing non-absolute names.
type ExecRunner = tunnelnet.ExecRunner

// Options carries the injectable collaborators of Start. Every field is
// optional.
type Options struct {
	// MTU of the utun. Defaults to DefaultMTU.
	MTU int
	// Address is the /32 assigned to the utun as a point-to-point alias.
	// Defaults to DefaultAddress. It must be IPv4.
	Address netip.Addr
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Runner executes ifconfig on macOS. Defaults to ExecRunner. Unused when
	// Links is set, and on Linux, where addresses are set over netlink.
	Runner CommandRunner
	// Links addresses and raises the interface. Defaults to
	// tunnelnet.SystemLinks over Runner. Tests inject a recorder so no root or
	// real device is needed.
	Links tunnelnet.Links
	// Resolver resolves the server host. Defaults to net.DefaultResolver.
	Resolver Resolver
	// NewDialer builds the Shadowsocks dialer. Defaults to NewShadowsocksDialer.
	NewDialer DialerFactory
	// CreateTUN opens the device. Defaults to tunnelnet.CreateTUN.
	// Tests inject an in-memory device so no root is needed.
	CreateTUN func(mtu int) (tun.Device, error)
	// UDPIdleTimeout drops a silent UDP flow. Defaults to DefaultUDPIdleTimeout.
	UDPIdleTimeout time.Duration
	// MaxUDPFlows caps concurrent UDP flows; the least recently used flow is
	// closed to make room. Defaults to MaxUDPFlows.
	MaxUDPFlows int
	// Now is the clock for flow recency and error-log rate limiting. Defaults to
	// time.Now.
	Now func() time.Time
}

// Stats is a point-in-time view of tunnel activity. Bytes count payload.
type Stats struct {
	// BytesIn is data received from the server toward local applications.
	BytesIn uint64
	// BytesOut is data sent from local applications to the server.
	BytesOut uint64
	TCPFlows int
	UDPFlows int
	// LastDialError is the most recent failure to open a proxied flow or move
	// packets; empty if none. It never contains the key, the password, or the
	// destination of the failed flow.
	LastDialError   string
	LastDialErrorAt time.Time
	// UDPEvictions counts UDP flows closed to stay under the flow cap.
	UDPEvictions uint64
}

// Tunnel is a running Outline tunnel bound to a helper-owned utun.
type Tunnel struct {
	name   string
	server netip.AddrPort
	log    *slog.Logger
	idle   time.Duration

	dev    tun.Device
	ns     *netStack
	dialer Dialer

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex // guards stopped and wg.Add so Stop's Wait cannot race a late spawn
	stopped bool
	wg      sync.WaitGroup
	live    atomic.Int64 // goroutines started through spawn that have not returned

	flows    closers
	udp      *udpFlowTable
	now      func() time.Time
	stopOnce sync.Once
	stopErr  error

	// done closes when the tunnel stops being usable: Stop was called, or a
	// packet pump ended because the utun failed.
	done     chan struct{}
	doneOnce sync.Once

	bytesIn, bytesOut  atomic.Uint64
	tcpFlows, udpFlows atomic.Int64

	errMu     sync.Mutex
	lastErr   string
	lastErrAt time.Time
	// lastErrLog and errSuppressed rate-limit the warning for recorded errors.
	lastErrLog    time.Time
	errSuppressed int
}

// errLogInterval is the least time between two warnings for recorded errors.
// A dead server or a full utun makes every packet or flow fail; one line per
// interval, with a count of what was held back, keeps the log readable.
const errLogInterval = 10 * time.Second

// Start brings up a tunnel for key: it resolves the server, creates the utun,
// assigns the address, builds the packet stack and starts the pumps. It never
// adds routes. If any step fails, everything created so far is torn down.
func Start(ctx context.Context, key Key, opts Options) (*Tunnel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := key.validate(); err != nil {
		return nil, err
	}
	if opts.MTU == 0 {
		opts.MTU = DefaultMTU
	}
	if opts.MTU < 576 || opts.MTU > 9000 {
		return nil, fmt.Errorf("mtu %d out of range", opts.MTU)
	}
	if !opts.Address.IsValid() {
		opts.Address = DefaultAddress
	}
	if !opts.Address.Is4() {
		return nil, fmt.Errorf("tunnel address %s must be IPv4", opts.Address)
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if opts.Links == nil {
		opts.Links = tunnelnet.SystemLinks{Run: opts.Runner}
	}
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.NewDialer == nil {
		opts.NewDialer = NewShadowsocksDialer
	}
	if opts.CreateTUN == nil {
		opts.CreateTUN = tunnelnet.CreateTUN
	}
	if opts.UDPIdleTimeout <= 0 {
		opts.UDPIdleTimeout = DefaultUDPIdleTimeout
	}
	if opts.MaxUDPFlows <= 0 {
		opts.MaxUDPFlows = MaxUDPFlows
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	// Resolve and build the dialer before touching the system so a bad host
	// creates nothing.
	server, err := resolveServer(ctx, opts.Resolver, key)
	if err != nil {
		return nil, err
	}
	dialer, err := opts.NewDialer(key, server)
	if err != nil {
		return nil, err
	}

	dev, err := opts.CreateTUN(opts.MTU)
	if err != nil {
		return nil, fmt.Errorf("create tunnel device: %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("read tunnel device name: %w", err)
	}

	t := &Tunnel{
		name: name, server: server, idle: opts.UDPIdleTimeout,
		log: opts.Logger.With("component", "outline-tunnel", "interface", name),
		dev: dev, dialer: dialer, done: make(chan struct{}),
		udp: newUDPFlowTable(opts.MaxUDPFlows), now: opts.Now,
	}
	t.ctx, t.cancel = context.WithCancel(context.Background())

	fail := func(step string, err error) (*Tunnel, error) {
		_ = t.Stop()
		return nil, fmt.Errorf("%s: %w", step, err)
	}

	if err := assignAddress(ctx, opts.Links, name, opts.Address); err != nil {
		return fail("configure tunnel device", err)
	}
	ns, err := newNetStack(opts.MTU, t.handleTCP, t.handleUDP)
	if err != nil {
		return fail("build packet stack", err)
	}
	t.ns = ns

	if !t.spawn(func() { defer t.signalDone(); pumpTunToStack(t.ctx, dev, ns.ep, t.recordError) }) ||
		!t.spawn(func() { defer t.signalDone(); pumpStackToTun(t.ctx, dev, ns.ep, t.recordError) }) ||
		!t.spawn(func() { drainEvents(t.ctx, dev.Events()) }) {
		return fail("start packet pumps", errors.New("tunnel stopped"))
	}
	t.log.Info("outline tunnel up", "server", server.String(), "address", opts.Address.String(), "mtu", opts.MTU)
	return t, nil
}

// assignAddress mirrors wg-quick: the address is a point-to-point alias whose
// peer is itself, then the interface is brought up. No route is added; routing
// belongs to the caller.
func assignAddress(ctx context.Context, links tunnelnet.Links, name string, addr netip.Addr) error {
	a := addr.String()
	if err := links.AddAlias(ctx, name, a, a); err != nil {
		return err
	}
	return links.Up(ctx, name)
}

// Done is closed when the tunnel is no longer usable: after Stop, or when the
// utun failed and a packet pump ended. A caller that supervises the tunnel
// restarts it when Done closes.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

func (t *Tunnel) signalDone() { t.doneOnce.Do(func() { close(t.done) }) }

// Name is the utun interface name, e.g. "utun7".
func (t *Tunnel) Name() string { return t.name }

// ServerAddr is the resolved Shadowsocks server address. The caller must keep
// it out of the tunnel's routes, or the transport would route into itself.
func (t *Tunnel) ServerAddr() netip.AddrPort { return t.server }

// Stats returns a snapshot of counters and the last error.
func (t *Tunnel) Stats() Stats {
	t.errMu.Lock()
	msg, at := t.lastErr, t.lastErrAt
	t.errMu.Unlock()
	return Stats{
		BytesIn:         t.bytesIn.Load(),
		BytesOut:        t.bytesOut.Load(),
		TCPFlows:        int(t.tcpFlows.Load()),
		UDPFlows:        int(t.udpFlows.Load()),
		LastDialError:   msg,
		LastDialErrorAt: at,
		UDPEvictions:    t.udp.evictions.Load(),
	}
}

// Stop tears the tunnel down: it closes every flow, the utun and the stack,
// and waits for all goroutines. It is idempotent and safe to call
// concurrently; every call returns the first call's result.
func (t *Tunnel) Stop() error {
	t.stopOnce.Do(func() {
		t.mu.Lock()
		t.stopped = true
		t.mu.Unlock()
		t.signalDone()
		t.cancel()
		t.udp.closeAll()
		t.flows.closeAll()
		// Close the device first: the TUN device is a non-blocking file in the
		// runtime poller on macOS and Linux alike, and Wintun wakes a blocked
		// read when it closes, so closing it unblocks the reader goroutine, and
		// no packet can be injected into a stack that is being destroyed.
		if err := t.dev.Close(); err != nil {
			t.stopErr = fmt.Errorf("close tunnel device: %w", err)
		}
		if t.ns != nil {
			t.ns.close()
		}
		t.wg.Wait()
		t.log.Info("outline tunnel down")
	})
	return t.stopErr
}

// spawn runs fn on a tracked goroutine; it refuses once Stop has begun.
func (t *Tunnel) spawn(fn func()) bool {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return false
	}
	t.wg.Add(1)
	t.mu.Unlock()
	t.live.Add(1)
	go func() {
		defer t.wg.Done()
		defer t.live.Add(-1)
		// A panic in the SDK or the packet stack, which parse bytes from the
		// network, must end one flow, not the root helper. The deferred cleanups
		// of fn have already run by the time the panic reaches this frame.
		defer func() {
			if r := recover(); r != nil {
				t.log.Error("outline tunnel goroutine panicked", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
				t.recordError(errors.New("internal error in a tunnel goroutine"))
			}
		}()
		fn()
	}()
	return true
}

// drainEvents discards the TUN device's up/down/MTU events. The device blocks
// once its small event queue is full, and nothing here acts on them.
func drainEvents(ctx context.Context, events <-chan tun.Event) {
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// recordError keeps err as the last error and logs it, at most once per
// errLogInterval; the others are counted and reported with the next line.
func (t *Tunnel) recordError(err error) {
	now := t.now()
	t.errMu.Lock()
	t.lastErr, t.lastErrAt = err.Error(), now
	logIt := t.lastErrLog.IsZero() || now.Sub(t.lastErrLog) >= errLogInterval
	suppressed := t.errSuppressed
	if logIt {
		t.lastErrLog, t.errSuppressed = now, 0
	} else {
		t.errSuppressed++
	}
	t.errMu.Unlock()
	if logIt {
		t.log.Warn("outline tunnel error", "err", err, "suppressed_since_last", suppressed)
	}
}

// handleTCP and handleUDP are the stack's forwarder callbacks.
var (
	_ func(*tcp.ForwarderRequest) = (*Tunnel)(nil).handleTCP
	_ func(*udp.ForwarderRequest) = (*Tunnel)(nil).handleUDP
)
