package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/dailylog"
	"github.com/quocln/routewise/internal/dns"
	"github.com/quocln/routewise/internal/dnsproxy"
	"github.com/quocln/routewise/internal/dnswatch"
	"github.com/quocln/routewise/internal/history"
	"github.com/quocln/routewise/internal/ifacename"
	"github.com/quocln/routewise/internal/monitor"
	"github.com/quocln/routewise/internal/resolverfiles"
	"github.com/quocln/routewise/internal/route"
	"github.com/quocln/routewise/internal/telemetry"
	"github.com/quocln/routewise/internal/vpnclient"
)

// transitionJoinTimeout bounds how long shutdown waits for the workers of the
// running generation. A stuck worker must not stall shutdown forever; by the
// time the bound elapses it has already been detached and can mutate nothing.
const transitionJoinTimeout = 10 * time.Second

// Learned wildcard routes outlive the DNS TTL that produced them: a connection
// opened on an answer keeps using that address long after the TTL, and removing
// its route would cut the connection over to the local network mid-stream.
const (
	learnedRouteMinLifetime = 30 * time.Minute
	// maxLearnedRoutes bounds how many addresses wildcard lookups can add, so a
	// busy domain cannot grow the routing table without limit.
	maxLearnedRoutes = 2000
)

// logRetentionDays is how many days of dated helper logs are kept.
const logRetentionDays = 14

// vpnDNSRouteLabel is the source shown for routes to the VPN's DNS servers.
const vpnDNSRouteLabel = "VPN DNS"

const (
	// vpnDNSGuessDelay is how long after connecting the VPN gets to bind its
	// DNS servers before RouteWise guesses them.
	vpnDNSGuessDelay = 10 * time.Second
	// dnsBaselineGrace: a VPN detected this soon after the daemon started was
	// most likely already up, so its servers are in the baseline.
	dnsBaselineGrace = 15 * time.Second
)

// vpnWatcher is the runtime surface a generation needs from a VPN monitor.
// Keeping it an interface lets a test drive the daemon without a real monitor
// shelling out to the live routing table.
type vpnWatcher interface {
	Start(ctx context.Context)
	Stop()
	Events() <-chan monitor.VPNEvent
	IsConnected() bool
	CurrentInterface() string
	CurrentGateway() netip.Addr
	// Tunnels lists every managed tunnel, sorted by interface name.
	Tunnels() []monitor.Tunnel
	Recheck()
}

// generation is the daemon's route-managing runtime: a monitor, a context, and
// the workers that act on them. A generation may mutate routes only while it is
// the daemon's current one, which is what makes an event that was buffered
// before shutdown harmless afterwards.
type generation struct {
	id      uint64
	monitor vpnWatcher
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// learnedRoute is one address a wildcard lookup resolved to.
type learnedRoute struct {
	domain  string
	expires time.Time
}

// daemonHooks are the points where the daemon reaches outside itself: the host's
// network, DNS, and process table, and the clock and starter of built-in
// tunnels. New wires the production behavior; tests replace fields after New
// and before Start, and nothing may replace one once the daemon runs.
type daemonHooks struct {
	// newMonitor builds the VPN monitor a generation runs on.
	newMonitor func(pollInterval time.Duration) vpnWatcher
	// vpnNameservers discovers the VPN's DNS servers and whether they were
	// bound to the tunnel rather than guessed.
	vpnNameservers func(ctx context.Context, iface string, allowGuess bool) ([]netip.Addr, bool, error)
	// systemNameservers lists every configured DNS server.
	systemNameservers func(ctx context.Context) ([]netip.Addr, error)
	// resolveExact resolves a tunnel's exact domains through that tunnel's
	// resolver.
	resolveExact func(ctx context.Context, s *tunnelSession, domains []string) (map[string][]net.IP, error)
	// resolveExcepted resolves the exact names excepted from the default VPN.
	resolveExcepted func(ctx context.Context, domains []string) (map[string][]net.IP, error)
	// flushSystemDNS empties the operating system's DNS cache.
	flushSystemDNS func(ctx context.Context) error
	// identifyClient names the program that owns a tunnel.
	identifyClient func(ctx context.Context, iface string) (vpnclient.Client, error)
	// scanClients lists the VPN clients installed on this machine.
	scanClients func() []vpnclient.Client
	// localPrefixes lists the subnets of the machine's non-tunnel interfaces.
	localPrefixes func() []netip.Prefix
	// interfaceUp, when set, replaces how route managers probe whether a tunnel
	// interface exists.
	interfaceUp func(string) bool

	// startTunnel brings a built-in tunnel up, so tests need no root or utun.
	startTunnel tunnelStarter
	// tunnelAfter, tunnelJitter, and tunnelNow are the reconnect clock: the
	// wait, the random extra, and the current time. tunnelHealthAfter paces the
	// health checks of built-in tunnels; it is separate from tunnelAfter so tests
	// drive reconnect backoff and health checks independently.
	tunnelAfter       func(time.Duration) <-chan time.Time
	tunnelHealthAfter func(time.Duration) <-chan time.Time
	tunnelJitter      func(time.Duration) time.Duration
	tunnelNow         func() time.Time
	// controlEvery is how often the control loop wakes up.
	controlEvery time.Duration
}

// visibilityState is what the daemon records for the Activity tab and the access
// history: what was asked, what was answered, and what connected.
type visibilityState struct {
	// activity is the in-memory log of routing decisions the app shows. While
	// history is enabled its events are also persisted through activityStore,
	// which is nil when it could not be opened and, like history, is set before
	// Start and never changed.
	activity      *activity.Log
	activityStore *activity.Store
	// dnsWatcher captures DNS answers for the activity log; nil disables it.
	dnsWatcher     *dnswatch.Watcher
	dnsWatchRescan chan struct{}
	dnsWatchDone   chan struct{}
	// answers holds captured DNS answers through their settle delay; one
	// goroutine, which Stop waits for, records them.
	answers     *answerQueue
	answersDone chan struct{}
	// dnsSeenMu guards dnsSeen, recent answers used to drop duplicates. It
	// is a leaf lock.
	dnsSeenMu sync.Mutex
	dnsSeen   map[string]time.Time

	// names maps an IP to the name it was last resolved from; its lock is a
	// leaf. history stores every outbound connection start; nil when it could
	// not be opened. It is set by OpenHistory before Start and never changed.
	names   *history.NameMap
	history *history.Store
	// historyOn mirrors history.enabled and historyDays history.retention_days,
	// so the capture path and settings.get read them without a lock.
	historyOn   atomic.Bool
	historyDays atomic.Int64
}

// vpnClientState is what the daemon knows about who owns each tunnel.
type vpnClientState struct {
	// clientMu guards the VPN client state below. It is a leaf lock.
	clientMu    sync.Mutex
	clientCache map[string]cachedClient
	// pending are the full-tunnel VPNs RouteWise detected but leaves alone
	// because their client is not allowed, keyed by interface.
	pending map[string]*pendingTunnel
}

// dnsSideState is what the daemon knows about DNS outside the tunnels' resolvers.
type dnsSideState struct {
	// dnsMu guards the DNS-side status below and every session's vpnDNS,
	// vpnDNSBound and conflicts fields.
	dnsMu sync.Mutex
	// dnsBaseline holds the DNS servers configured while no VPN was up. A
	// guess never picks one of them: they belong to the network, not the VPN.
	dnsBaseline     map[netip.Addr]bool
	startedAt       time.Time
	forwarderErr    string
	wildcardSkipped []string
	resolverFileErr string
}

// Daemon orchestrates all components for selective VPN routing. It holds the shared
// runtime and lock order; each area's state is in a group of its own above.
type Daemon struct {
	// store is the only owner of mutable configuration. The daemon never keeps a
	// *config.Config that anything else can write to.
	store *ConfigStore

	// Settings fixed for the lifetime of the process, captured at construction so
	// runtime code never reaches back into a shared config value.
	pidFile string
	// dnsServers are the configured upstream servers as of start. Every
	// resolver, including those of tunnels that connect later, uses them, so a
	// config import cannot change some resolvers and not others before the
	// restart that applies it.
	dnsServers   []string
	dnsCacheTTL  time.Duration
	pollInterval time.Duration

	// useVPNDNS mirrors dns.use_vpn_dns. It is the one setting the app can
	// change at runtime, through SetUseVPNDNS.
	useVPNDNS atomic.Bool
	// allowIPv6 mirrors routing.allow_ipv6, and ipv6Block holds the reject
	// routes that apply while it is false.
	allowIPv6 atomic.Bool
	ipv6Block *ipv6Blocker

	// resolver asks the configured servers only. Each tunnel session has its
	// own resolver that prefers that tunnel's VPN DNS; this one answers for
	// names no session owns.
	resolver *dns.Resolver
	// routeManager is the base manager: it captures the LAN gateway before
	// any VPN connects, answers kernel route lookups, and recovers the
	// legacy journal. Routes themselves live in the per-tunnel managers.
	routeManager  *route.Manager
	socketServer  *SocketServer
	forwarder     *dnsproxy.Forwarder
	resolverFiles resolverfiles.Configurator

	// hooks are the daemon's seams to the host; see daemonHooks.
	hooks daemonHooks

	// tunnels runs the built-in VPN profiles. secrets holds their credentials;
	// both are set before Start and never replaced.
	tunnels *tunnelManager
	secrets SecretStore
	// prefs stores per-user app preferences; set before Start.
	prefs PrefStore
	// defaultVPN holds the role of the VPN that carries what no list claims.
	defaultVPN *defaultVPNController

	// healthEpoch counts health changes of built-in tunnels; a sync planned
	// before a change is discarded.
	healthEpoch atomic.Uint64

	visibilityState

	// logFile is the dated helper log, closed at Stop; nil when logging to
	// stderr.
	logFile io.Closer

	vpnClientState

	baseCtx context.Context
	cancel  context.CancelFunc
	logger  *slog.Logger

	// ignoreTermSignals stops the daemon listening for SIGTERM and SIGINT; see
	// IgnoreTermSignals.
	ignoreTermSignals bool

	// mutationMu makes generation ownership validation and route mutation one
	// critical section. It also serializes every change to DNS-side state
	// (resolver files, VPN DNS servers, learned addresses) and to the set of
	// tunnel sessions, so a disconnect can never interleave with a
	// connect-time update. Lock order is:
	// syncMu -> mutationMu -> mu -> route.Manager.mu (any tunnel's manager)
	// -> the host/network route registry's lock (one registry, one lock, for
	// both /32 routes and CIDR routes), and
	// mutationMu -> the session registry's lock, dnsMu, learnedMu, the resolver's
	// lock, the forwarder's Start lock, or the config store's write lock (the
	// store's readers take no lock, see ConfigStore). dnsMu -> the resolver file
	// manager's lock (DNSStatus asks which domains are active while holding
	// dnsMu); nothing takes dnsMu while holding that one. The history store
	// has leaf locks (its handle, its wake-up channel), and so do the IP-to-name
	// map and the capture watcher's dedupe table: take them last, never hold
	// one while taking another lock, and never do history DB I/O while holding
	// mutationMu or any other daemon lock. Nothing may take
	// mutationMu while holding any of those, and nothing may take syncMu
	// while holding mutationMu: a sync resolves names for seconds with no
	// lock but syncMu, and takes mutationMu only to apply its plan.
	//
	// Built-in VPN tunnels add three locks. tunnelManager.profileMu is the
	// outermost of all: a profile import or update holds it across its
	// uniqueness check and the reconnect that may follow, and a config import
	// holds it from its snapshot of the profiles to the end of reconciling the
	// tunnels with the imported ones, so it is taken before ctlMu and while
	// holding no other lock. tunnelManager.ctlMu comes next: a
	// connect, a disconnect, or a profile removal holds it while it waits for a
	// profile's supervisor to finish, and that supervisor takes syncMu and
	// mutationMu, so nothing may take ctlMu while holding any other daemon lock
	// (Stop takes it only after releasing mutationMu). A removal also holds ctlMu
	// across the config store's own lock, which nothing holds while taking ctlMu.
	// The health loop of a profile runs in its supervisor goroutine, with no lock
	// held, and takes syncMu and mutationMu only through setOwnedHealth and
	// syncRoutes. tunnelManager.mu is a leaf like dnsMu:
	// it guards the run table, the owned-interface set, and the transport
	// addresses, and is never held while a tunnel starts or stops or while any
	// other lock is taken. mutationMu -> tunnelManager.mu is therefore fine (the
	// LAN guard reads the transport addresses under mutationMu) and the reverse
	// never happens.
	//
	// syncMu serializes route syncs. Only one plan is computed and applied at
	// a time, and the plan is re-checked against the sessions and config
	// revision it was built from once mutationMu is held, so a sync that
	// started before a tunnel connected never applies over the newer state.
	//
	// The session registry's own lock is a leaf like dnsMu: it is held only to
	// read or change the registry and released before calling into a manager,
	// the store, or anything else. Readers that need priority order go through
	// sessionList, which serves a cached view built after that lock is
	// released. The config store takes no lock for readers: it publishes a
	// compiled policy, so a policy read orders before nothing.
	syncMu     sync.Mutex
	mutationMu sync.Mutex

	// hostRoutes records which tunnel's manager owns each /32 and each CIDR
	// network route RouteWise has added, so one tunnel never adopts another's
	// route.
	hostRoutes *route.HostRouteRegistry
	// sessions are the connected managed tunnels and the managers that could
	// not be torn down. Only code holding mutationMu adds or removes sessions.
	sessions *sessionRegistry

	mu             sync.RWMutex
	isRunning      bool
	current        *generation
	nextGeneration uint64
	// syncTrigger carries a request for a route sync (see TriggerSync). It holds
	// at most one, so requests made while one is pending merge into it.
	syncTrigger chan struct{}

	// learnedMu guards every session's learned map, the addresses wildcard
	// lookups resolved to.
	learnedMu sync.Mutex

	dnsSideState
}

// New creates a new daemon with the provided configuration.
func New(cfg *config.Config, persist config.Persister) (*Daemon, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	// Create logger based on config
	level := slog.LevelInfo
	switch cfg.Daemon.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	var handler slog.Handler
	var logFile io.Closer
	if cfg.Daemon.LogFile != "" {
		// One file per local day beside the configured path. launchd's own
		// stdout/stderr file stays for crash output.
		w, err := dailylog.New(cfg.Daemon.LogFile, logRetentionDays)
		if err != nil {
			// Fall back to stderr
			handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
		} else {
			logFile = w
			handler = slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
		}
	} else {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	}

	rm := route.NewManager()
	if cfg.IsAdditiveMode() {
		rm.SetAdditiveMode(true)
	}

	// Records reach the reporting server too when telemetry is on; the file
	// or stderr handler keeps its own level.
	logger := slog.New(telemetry.WrapHandler(handler))
	d := &Daemon{
		store:         NewConfigStore(cfg, persist),
		pidFile:       cfg.Daemon.PidFile,
		dnsServers:    slices.Clone(cfg.DNS.Servers),
		dnsCacheTTL:   time.Duration(cfg.DNS.CacheTTL) * time.Second,
		pollInterval:  time.Duration(cfg.Daemon.PollInterval) * time.Second,
		resolver:      dns.NewResolver(cfg.DNS.Servers, time.Duration(cfg.DNS.CacheTTL)*time.Second),
		routeManager:  rm,
		resolverFiles: resolverfiles.NewSystem(dnsproxy.ListenHost, dnsproxy.ListenPort),
		logger:        logger,
		logFile:       logFile,
		sessions:      newSessionRegistry(),
		hostRoutes:    route.NewHostRouteRegistry(),
		syncTrigger:   make(chan struct{}, 1),
	}
	d.useVPNDNS.Store(cfg.DNS.UseVPNDNS)
	d.allowIPv6.Store(cfg.Routing.AllowIPv6)
	d.defaultVPN = newDefaultVPNController(d, logger)
	d.ipv6Block = newIPv6Blocker(d.allowIPv6.Load,
		func() route.Table { return d.routeManager.Table() },
		func() string {
			return filepath.Join(filepath.Dir(d.routeManager.JournalPath()), ipv6BlockJournalName)
		}, logger)
	// Reporting follows every committed change: its settings, and the profile
	// names and domains the scrubber must hide.
	d.store.OnCommit(telemetry.Apply)
	telemetry.Apply(d.currentConfig())
	d.tunnels = newTunnelManager()
	d.hooks = daemonHooks{
		startTunnel:       startBuiltinTunnel,
		tunnelAfter:       time.After,
		tunnelHealthAfter: time.After,
		tunnelJitter:      randomJitter,
		tunnelNow:         time.Now,
		flushSystemDNS:    resolverfiles.FlushSystemCache,
		vpnNameservers: func(ctx context.Context, iface string, allowGuess bool) ([]netip.Addr, bool, error) {
			return dns.VPNNameservers(ctx, iface, dns.FallbackOptions{
				Enabled: allowGuess,
				IsLocal: d.onLocalNetwork,
				Known:   d.inDNSBaseline,
			})
		},
		resolveExact: func(ctx context.Context, s *tunnelSession, domains []string) (map[string][]net.IP, error) {
			return s.resolver.ResolveAll(ctx, domains)
		},
		resolveExcepted: func(ctx context.Context, domains []string) (map[string][]net.IP, error) {
			return d.resolver.ResolveAll(ctx, domains)
		},
		systemNameservers: dns.SystemNameservers,
		identifyClient:    vpnclient.Identify,
		scanClients:       vpnclient.Scan,
		localPrefixes:     lanPrefixes.get,
		controlEvery:      controlTick,
	}
	d.activity = activity.New(activityCapacity)
	d.dnsSeen = make(map[string]time.Time)
	d.names = history.NewNameMap()
	d.historyOn.Store(cfg.History.Enabled)
	d.historyDays.Store(int64(cfg.History.RetentionDays))
	d.dnsWatcher = dnswatch.NewWatcher(d.onDNSAnswer, logger)
	d.dnsWatcher.SetFlowHandler(d.onFlow)
	// Flows are recorded once OpenHistory has a store to put them in.
	d.dnsWatcher.SetFlowsEnabled(false)
	d.dnsWatchRescan = make(chan struct{}, 1)
	d.dnsWatchDone = make(chan struct{})
	d.answers = newAnswerQueue(dnsAnswerSettle)
	d.answersDone = make(chan struct{})
	rm.SetChangeObserver(d.onRouteChange)
	d.clientCache = make(map[string]cachedClient)
	d.pending = make(map[string]*pendingTunnel)
	d.hooks.newMonitor = func(interval time.Duration) vpnWatcher {
		m := monitor.NewVPNMonitor(interval)
		m.SetAdmission(d.admitTunnel)
		return m
	}
	d.forwarder = dnsproxy.New(dnsproxy.Config{
		Upstreams: d.upstreamsFor,
		Matches:   d.matchesWildcard,
		OnMatch:   d.onWildcardAnswer,
		Logger:    logger,
	})
	return d, nil
}

// NoteConfigRecovery logs, loudly, that the configuration database was rebuilt
// at start because it was corrupt, and from what. An empty notice is ignored.
func (d *Daemon) NoteConfigRecovery(notice string) {
	if notice != "" {
		d.logger.Error("configuration database was recovered at start", "detail", notice)
	}
}

// Start begins the daemon operation.
func (d *Daemon) Start() error {
	d.mu.Lock()
	if d.isRunning {
		d.mu.Unlock()
		return fmt.Errorf("daemon already running")
	}
	d.mu.Unlock()

	RaiseFileLimit(d.logger)

	// Write PID file atomically (handles stale PID check internally)
	if err := EnsurePIDFileDir(d.pidFile); err != nil {
		d.logger.Warn("could not create PID file directory", "error", err)
	}
	if err := WritePIDFile(d.pidFile); err != nil {
		return fmt.Errorf("PID file: %w", err)
	}

	// Capture original gateway BEFORE VPN connects (for inverted split tunnel)
	if err := d.routeManager.CaptureOriginalGateway(); err != nil {
		d.logger.Warn("could not capture original gateway", "error", err)
	} else {
		d.logger.Info("captured original gateway", "gateway", d.routeManager.GetOriginalGateway())
	}

	// Recover any transition journal left by a process that crashed mid-mutation.
	// This must run before the VPN monitor, event loop, DNS/gateway loops, or the
	// socket server start, so nothing observes a half-applied route change as
	// steady state.
	if err := d.routeManager.RecoverTransition(); err != nil {
		d.logger.Error("route transition recovery failed", "error", err)
	}
	d.recoverSessionJournals()
	d.ipv6Block.recoverLeftovers()
	d.defaultVPN.recoverLeftovers()

	d.startedAt = time.Now()
	d.captureDNSBaseline(context.Background())

	// A previous process that died with the VPN up left resolver files pointing
	// at a forwarder that no longer exists, which breaks lookups for those
	// domains. Remove them before anything else can depend on DNS.
	if err := d.resolverFiles.RemoveAll(); err != nil {
		d.logger.Warn("could not remove stale resolver files", "error", err)
	}

	degradedAtStart, degradedReason := d.Degraded()
	if degradedAtStart {
		d.logger.Warn("route manager degraded after startup recovery", "reason", degradedReason)
	}

	// Setup context with signal handling
	if d.ignoreTermSignals {
		d.baseCtx, d.cancel = context.WithCancel(context.Background())
		d.holdTermSignals(d.baseCtx)
	} else {
		d.baseCtx, d.cancel = signal.NotifyContext(context.Background(),
			syscall.SIGTERM, syscall.SIGINT)
	}

	// Mark as running
	d.mu.Lock()
	d.isRunning = true
	d.mu.Unlock()

	go d.dnsWatchLoop(d.baseCtx)
	go d.ipv6Block.run(d.baseCtx)
	go func(ctx context.Context) {
		defer close(d.answersDone)
		d.answers.run(ctx, d.recordDNSAnswer)
	}(d.baseCtx)

	// The forwarder only answers lookups once a resolver file points at it, and
	// resolver files are only written while the VPN is up, so starting it here
	// changes nothing until then. A failure only disables wildcard routing.
	d.mutationMu.Lock()
	if !d.ensureForwarderLocked() {
		d.logger.Warn("DNS forwarder failed to start; RouteWise retries before routing wildcards",
			"addr", d.forwarder.Addr())
	}
	d.mutationMu.Unlock()

	if degradedAtStart {
		// Degraded means route ownership is unverified, so the daemon runs no
		// mutators at all: it serves status so an operator can see the problem,
		// and nothing else.
		d.logger.Warn("starting without route management because route state is unverified")
	} else {
		d.startGeneration()
		d.autoConnectProfiles()
	}

	// Start socket server for GUI communication
	handler := api.NewHandler(d, NewConsoleUserAuthorizer())
	d.socketServer = NewSocketServer(handler, d.logger)
	if err := d.socketServer.Start(d.baseCtx); err != nil {
		if ipcListenFailureIsFatal {
			// The pipe name is shared by every user, so a failure to create it
			// means someone else already holds it. Clients would talk to that
			// holder, not to this helper; stop so the service manager retries and
			// the failure is visible.
			d.logger.Error("socket server failed to start", "error", err)
			d.Stop()
			return fmt.Errorf("start IPC server: %w", err)
		}
		d.logger.Warn("socket server failed to start", "error", err)
		// Continue without socket server - daemon still works via CLI
	}

	if d.hasWildcardPatterns() && !d.useVPNDNS.Load() {
		d.logger.Warn("wildcard domains resolve through dns.servers while a VPN is up; " +
			"enable dns.use_vpn_dns if names under them exist only in company DNS")
	}

	snapshot, _ := d.store.Snapshot()
	d.logger.Info("daemon started",
		"pid", os.Getpid(),
		"domains", snapshot.PatternCount(),
		"poll_interval", snapshot.Daemon.PollInterval,
		"use_vpn_dns", d.useVPNDNS.Load(),
	)

	return nil
}

// IgnoreTermSignals makes the daemon stop only through Stop. A Windows service
// receives SIGTERM from the Go runtime for every user logoff and for system
// shutdown, and must not end on the first; the service manager's own stop
// request is the only one that counts. Call it before Start.
func (d *Daemon) IgnoreTermSignals() { d.ignoreTermSignals = true }

// holdTermSignals subscribes to SIGTERM and discards it until ctx ends. With no
// subscriber the Go runtime lets Windows end the process on logoff; with one it
// leaves the process running.
func (d *Daemon) holdTermSignals(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ch:
				d.logger.Info("ignoring a termination notice; only the service manager stops the helper")
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Wait blocks until the daemon receives a shutdown signal.
func (d *Daemon) Wait() {
	<-d.baseCtx.Done()
}

// Stop gracefully shuts down the daemon.
func (d *Daemon) Stop() {
	d.mutationMu.Lock()
	d.mu.Lock()
	if !d.isRunning {
		d.mu.Unlock()
		d.mutationMu.Unlock()
		return
	}
	d.isRunning = false
	gen := d.current
	d.current = nil
	d.mu.Unlock()
	d.mutationMu.Unlock()
	// A request raised for the generation that just ended must not trigger the
	// next one.
	select {
	case <-d.syncTrigger:
	default:
	}

	d.logger.Info("shutting down")

	// Cancel context to stop all goroutines
	if d.cancel != nil {
		d.cancel()
	}

	// Stop socket server
	if d.socketServer != nil {
		d.socketServer.Stop()
	}

	d.stopGeneration(gen)
	<-d.dnsWatchDone
	<-d.answersDone
	// No answer can add a reject route now; take every one out.
	d.ipv6Block.shutdown()
	// Nothing records flows any more: write what is queued and close.
	d.closeHistory()

	// Resolver files go first: once they are gone, no lookup can reach the
	// forwarder, so nothing learns a route while the routes are torn down.
	if err := d.resolverFiles.RemoveAll(); err != nil {
		d.logger.Error("resolver file cleanup failed", "error", err)
	}
	d.forwarder.Stop()

	d.mutationMu.Lock()
	// Newest first: each tunnel's compensation then sees the routing state its
	// own activation left, whichever tunnel has priority.
	sessions := d.sessions.takeAll()
	if gen != nil {
		for _, s := range sessions {
			if err := d.tearDownSessionRoutes(s); err != nil {
				d.logger.Error("tunnel cleanup failed", "interface", s.iface, "error", err)
			}
		}
		d.defaultVPN.releaseRoutesLocked()
		for _, m := range d.sessions.takeRetired() {
			if err := deactivateAndCleanup(m); err != nil {
				d.logger.Error("retried cleanup failed", "journal", m.JournalPath(), "error", err)
			}
		}
	}
	d.resetDNSStateLocked()
	d.mutationMu.Unlock()

	// Built-in tunnels go once their routes are gone: each loop sees its
	// generation detached, so it only closes its device.
	d.stopAllTunnels()
	// Tearing the tunnels down recorded activity; write it before closing.
	d.closeActivityStore()

	for _, s := range sessions {
		s.resolver.Close()
	}
	d.resolver.Close()

	// Remove PID file
	if err := RemovePIDFile(d.pidFile); err != nil {
		d.logger.Warn("could not remove PID file", "error", err)
	}

	d.logger.Info("daemon stopped")
	telemetry.Close()
	if d.logFile != nil {
		d.logFile.Close()
	}
}

// startGeneration builds and starts a fresh runtime and publishes it as the
// current generation.
func (d *Daemon) startGeneration() *generation {
	gen := &generation{monitor: d.hooks.newMonitor(d.pollInterval)}
	gen.ctx, gen.cancel = context.WithCancel(d.baseCtx)

	d.mu.Lock()
	d.nextGeneration++
	gen.id = d.nextGeneration
	d.current = gen
	d.mu.Unlock()

	gen.wg.Add(4)
	go func() { defer gen.wg.Done(); gen.monitor.Start(gen.ctx) }()
	go func() { defer gen.wg.Done(); d.eventLoop(gen) }()
	go func() { defer gen.wg.Done(); d.dnsRefreshLoop(gen) }()
	go func() { defer gen.wg.Done(); d.controlLoop(gen) }()

	d.logger.Info("route runtime started", "generation", gen.id)
	return gen
}

// stopGeneration cancels a detached generation and joins its workers within a
// bound. A worker that overruns the bound is already unable to mutate anything.
func (d *Daemon) stopGeneration(gen *generation) {
	if gen == nil {
		return
	}
	gen.cancel()
	gen.monitor.Stop()
	if !waitBounded(&gen.wg, transitionJoinTimeout) {
		d.logger.Warn("route runtime did not stop within the shutdown bound", "generation", gen.id)
	}
}

// waitBounded waits for wg, reporting false if the timeout elapsed first.
func waitBounded(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// currentGeneration returns the runtime that currently owns route state, or nil
// while the daemon is stopped or degraded.
func (d *Daemon) currentGeneration() *generation {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.current
}

// ownsGeneration reports whether gen is still the daemon's live generation,
// whether or not route state is degraded.
func (d *Daemon) ownsGeneration(gen *generation) bool {
	return gen != nil && gen.ctx.Err() == nil && d.currentGeneration() == gen
}

// mayMutate reports whether gen still owns route and DNS state. It is re-checked
// immediately before every mutation, so an event that was already buffered when
// shutdown began cannot apply once shutdown has detached its generation.
func (d *Daemon) mayMutate(gen *generation) bool {
	if gen == nil || gen.ctx.Err() != nil {
		return false
	}
	// Take d.mu and release it before touching the route lock. Holding both at
	// once would establish a d.mu -> route.Manager.mu order that any future
	// route-side callback into the daemon could invert into a deadlock.
	if d.currentGeneration() != gen {
		return false
	}
	return !d.globalDegraded()
}

// mayMutateSession reports whether gen may mutate state owned by session s:
// the generation must own route state, s must still be a live session, and
// neither the shared managers nor s's own manager may be degraded. A session
// whose manager is degraded stops mutating on its own; the others carry on.
func (d *Daemon) mayMutateSession(gen *generation, s *tunnelSession) bool {
	if !d.mayMutate(gen) || s == nil || s.ctx.Err() != nil || !d.sessions.isRegistered(s) {
		return false
	}
	degraded, _ := s.manager.Degraded()
	return !degraded
}

// withGenerationMutation makes the ownership check and route-manager mutation
// atomic with respect to shutdown. Checks outside this helper may avoid work,
// but never authorize a mutation by themselves.
func (d *Daemon) withGenerationMutation(gen *generation, mutate func() error) (bool, error) {
	d.mutationMu.Lock()
	defer d.mutationMu.Unlock()

	if !d.mayMutate(gen) {
		return false, nil
	}
	return true, mutate()
}

// withSessionMutation is withGenerationMutation for state owned by one tunnel
// session: it also fails when s was torn down or degraded in the meantime.
func (d *Daemon) withSessionMutation(gen *generation, s *tunnelSession, mutate func() error) (bool, error) {
	d.mutationMu.Lock()
	defer d.mutationMu.Unlock()

	if !d.mayMutateSession(gen, s) {
		return false, nil
	}
	return true, mutate()
}

// IsRunning returns whether the daemon is currently running.
func (d *Daemon) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.isRunning
}

// ListDomains returns the configured host patterns and the config revision they
// came from, so a client can make its next write conditional on that revision.
func (d *Daemon) ListDomains(vpn string) ([]string, uint64, error) {
	patterns, err := d.store.DomainList(vpn)
	if err != nil {
		return nil, 0, classifyConfigError(err)
	}
	return patterns, d.store.Revision(), nil
}

// AddDomain adds one pattern to a VPN client's list, or to Any VPN for "".
func (d *Daemon) AddDomain(vpn, pattern string) error {
	_, err := d.store.AddDomain(vpn, pattern)
	return classifyConfigError(err)
}

// RemoveDomain drops one pattern from a VPN client's list, or from Any VPN.
func (d *Daemon) RemoveDomain(vpn, pattern string) error {
	_, err := d.store.RemoveDomain(vpn, pattern)
	return classifyConfigError(err)
}

// SetDomains replaces a VPN client's list, or the Any VPN list for "".
func (d *Daemon) SetDomains(vpn string, patterns []string, expectedRevision uint64) error {
	_, err := d.store.SetDomains(vpn, patterns, expectedRevision)
	return classifyConfigError(err)
}

// Settings reports the settings the app can change at runtime.
func (d *Daemon) Settings() api.Settings {
	return api.Settings{
		UseVPNDNS:            d.useVPNDNS.Load(),
		AllowIPv6:            d.allowIPv6.Load(),
		DefaultVPN:           d.store.Policy().cfg.Routing.DefaultVPN,
		DefaultVPNFallback:   d.store.Policy().cfg.Routing.DefaultVPNFallback,
		DefaultVPNExcept:     append([]string{}, d.store.Policy().cfg.Routing.DefaultVPNExcept...),
		AllowedVPNClients:    d.AllowedVPNClients(),
		HistoryEnabled:       d.historyOn.Load(),
		HistoryRetentionDays: int(d.historyDays.Load()),
	}
}

// SetUseVPNDNS turns dns.use_vpn_dns on or off, saves it, and applies it to
// every connected tunnel at once: each tunnel's resolver starts or stops
// asking that tunnel's DNS servers first, and the next sync rewrites the
// wildcard resolver files, which wait for those servers while it is on. The
// VPN's DNS servers stay routed through their tunnels either way.
func (d *Daemon) SetUseVPNDNS(enabled bool) error {
	d.mutationMu.Lock()
	defer d.mutationMu.Unlock()

	if _, err := d.store.SetUseVPNDNS(enabled); err != nil {
		return classifyConfigError(err)
	}
	d.applyUseVPNDNSLocked(enabled)
	d.logger.Info("dns.use_vpn_dns changed", "enabled", enabled)
	d.TriggerSync()
	return nil
}

// classifyConfigError marks failures the caller can correct, so the RPC layer can
// distinguish a bad request from a helper-side fault such as an unwritable file.
func classifyConfigError(err error) error {
	if err == nil {
		return nil
	}
	// A persistence failure is the helper's problem, not the caller's.
	if errors.Is(err, ErrPersistFailed) {
		return err
	}
	return fmt.Errorf("%w: %w", api.ErrRejected, err)
}

// TriggerSync asks the running generation to sync routes now. Requests made
// before it runs the sync merge into one.
func (d *Daemon) TriggerSync() {
	d.mu.RLock()
	gen := d.current
	d.mu.RUnlock()
	if gen == nil || gen.ctx.Err() != nil {
		return
	}
	select {
	case d.syncTrigger <- struct{}{}:
	default:
	}
}

// Status represents the current daemon status.
type Status struct {
	Running      bool
	VPNConnected bool
	VPNInterface string
	VPNGateway   netip.Addr
	RouteCount   int
}

// eventLoop processes VPN state change events for one generation.
func (d *Daemon) eventLoop(gen *generation) {
	for {
		select {
		case <-gen.ctx.Done():
			return
		case event := <-gen.monitor.Events():
			// An event buffered before this generation was detached must never
			// reach the route layer. A degraded generation still receives
			// events: a disconnect must clear DNS-side state even when route
			// state cannot be touched, and every route mutation below is
			// gated by withGenerationMutation on its own.
			if !d.ownsGeneration(gen) {
				continue
			}
			d.handleVPNEvent(gen, event)
		}
	}
}

// handleVPNEvent processes a VPN state change event.
func (d *Daemon) handleVPNEvent(gen *generation, event monitor.VPNEvent) {
	switch event.State {
	case monitor.VPNConnected:
		d.logger.Info("VPN connected",
			"interface", event.Interface,
			"gateway", event.Gateway,
		)
		d.onVPNConnect(gen, event)

	case monitor.VPNDisconnected:
		d.logger.Info("VPN disconnected",
			"interface", event.Interface,
		)
		d.onVPNDisconnect(gen, event.Interface)
	}
}

// onLocalNetwork reports whether ip sits on a directly connected network.
func (d *Daemon) onLocalNetwork(ip netip.Addr) bool {
	for _, prefix := range d.hooks.localPrefixes() {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// localInterfacePrefixes lists the IPv4 subnets of every up, non-loopback,
// non-tunnel interface.
func localInterfacePrefixes() []netip.Prefix {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, iface := range ifaces {
		// Only VPN tunnel devices are left out: any other interface's subnet
		// counts as directly connected, so the LAN guard keeps refusing routes
		// into it.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || ifacename.IsVPNDevice(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP.To4())
			if !ok {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			out = append(out, netip.PrefixFrom(addr, ones).Masked())
		}
	}
	return out
}

// captureDNSBaseline records the DNS servers configured right now, taken as
// the network's own while no VPN is up.
func (d *Daemon) captureDNSBaseline(ctx context.Context) {
	servers, err := d.hooks.systemNameservers(ctx)
	if err != nil {
		d.logger.Debug("could not read the DNS configuration", "error", err)
		return
	}
	baseline := make(map[netip.Addr]bool, len(servers))
	for _, s := range servers {
		baseline[s] = true
	}
	d.dnsMu.Lock()
	d.dnsBaseline = baseline
	d.dnsMu.Unlock()
}

// inDNSBaseline reports whether ip was a configured DNS server before the
// VPN connected.
func (d *Daemon) inDNSBaseline(ip netip.Addr) bool {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	return d.dnsBaseline[ip]
}

// netIPToNetipAddr converts net.IP to netip.Addr.
func netIPToNetipAddr(ip net.IP) netip.Addr {
	if ip4 := ip.To4(); ip4 != nil {
		addr, _ := netip.AddrFromSlice(ip4)
		return addr
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr
}

// currentConfig returns a copy of the stored configuration.
func (d *Daemon) currentConfig() *config.Config {
	cfg, _ := d.store.Snapshot()
	return cfg
}
