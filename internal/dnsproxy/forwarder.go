// Package dnsproxy runs the local DNS forwarder that makes wildcard domain
// patterns routable.
//
// A wildcard such as *.corp.example.com cannot be resolved up front: the names
// under it are only known when something asks for them. macOS sends lookups for
// a domain to the nameserver named in /etc/resolver/<domain>, so RouteWise
// points that file at this forwarder. Every query is passed on unchanged to the
// real upstream servers; when the name matches a wildcard pattern, the A
// records in the answer are handed to a callback that installs the VPN routes
// before the answer is returned. The client therefore never sees an address
// that is not routed yet.
package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ListenHost is the loopback address the forwarder listens on, and ListenPort
// (per OS, in listen_port_*.go) its port. They are fixed because the resolver
// configuration RouteWise writes must name them.
const ListenHost = "127.0.0.1"

// upstreamTimeout bounds one upstream exchange. macOS retries a lookup itself,
// so a short bound keeps one dead upstream from stalling every client.
const upstreamTimeout = 3 * time.Second

const (
	// startTimeout bounds how long Start waits for both listeners to serve.
	startTimeout = 5 * time.Second
	// stopTimeout bounds how long Stop waits for in-flight handlers. A handler
	// can sit in upstream timeouts or in a route install, and shutdown must
	// not wait on either.
	stopTimeout = 5 * time.Second
	// DefaultMaxInFlight caps queries handled at once. Under normal load a
	// query takes milliseconds, so the cap only bites during an upstream
	// outage, when clients keep retrying into queries that each live for
	// the upstream timeout.
	DefaultMaxInFlight = 512
)

// MatchHandler receives the IPv4 addresses a wildcard-matched name resolved to,
// with the smallest TTL among them. It runs before the answer is sent and must
// return once the routes are in place.
type MatchHandler func(name string, ips []netip.Addr, ttl time.Duration)

// Config wires the forwarder to the daemon.
type Config struct {
	// Upstreams returns the servers to forward a query for name to, as groups
	// in the order to try them. Servers of one group are interchangeable and
	// may be asked at once (see askGroup); a later group is asked only after
	// every server of the one before it failed, so a name reaches it only as a
	// fallback. Names under different wildcard suffixes may belong to different
	// VPNs and so have different upstreams. name is lowercase without a
	// trailing dot, and empty when the query does not carry exactly one
	// question.
	Upstreams func(name string) [][]string
	// HedgeDelay is how long to wait for an upstream before also asking the
	// next server of its group. Zero means DefaultHedgeDelay.
	HedgeDelay time.Duration
	// Matches reports whether a query name falls under a wildcard pattern.
	Matches func(name string) bool
	// OnMatch is called with the answer for every matching A query.
	OnMatch MatchHandler
	// MaxInFlight caps concurrent queries; beyond it a query is answered
	// SERVFAIL at once so the client retries. Zero means DefaultMaxInFlight.
	MaxInFlight int
	// FallbackHosts are other hosts to listen on, at the same port, when the
	// primary address cannot be bound. A caller that sets them must read the
	// address actually bound from Forwarder.Addr and give that to the system
	// resolver configuration.
	FallbackHosts []string
	Logger        *slog.Logger
}

// Forwarder is a UDP and TCP DNS forwarder bound to loopback.
type Forwarder struct {
	cfg    Config
	addr   string
	logger *slog.Logger

	// inflight holds one token per query being handled.
	inflight chan struct{}
	// serve runs one listener until it stops; tests replace it to inject
	// failures.
	serve       func(*dns.Server) error
	stopTimeout time.Duration

	// mu serializes Start and Stop only. Running and ServeDNS never take it,
	// so a Stop waiting for in-flight handlers can never block a caller that
	// only asks whether the forwarder is up.
	mu    sync.Mutex
	udp   *dns.Server
	tcp   *dns.Server
	bound atomic.Value // string: the listening address while running

	running atomic.Bool
	// hedgeDelay is the resolved Config.HedgeDelay.
	hedgeDelay time.Duration
	// failed is set when a listener stops serving on its own; resolver files
	// must not keep pointing at it.
	failed atomic.Bool
	// gen identifies the current Start. A listener that fails after its Start
	// was abandoned or replaced must not mark the new run failed.
	gen atomic.Uint64
}

// New creates a forwarder on ListenHost:ListenPort. It does not listen until Start.
func New(cfg Config) *Forwarder {
	return NewAt(net.JoinHostPort(ListenHost, fmt.Sprint(ListenPort)), cfg)
}

// NewAt creates a forwarder on a specific address; tests use a free port.
func NewAt(addr string, cfg Config) *Forwarder {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	limit := cfg.MaxInFlight
	if limit <= 0 {
		limit = DefaultMaxInFlight
	}
	hedgeDelay := cfg.HedgeDelay
	if hedgeDelay <= 0 {
		hedgeDelay = DefaultHedgeDelay
	}
	return &Forwarder{
		cfg:         cfg,
		addr:        addr,
		logger:      logger,
		hedgeDelay:  hedgeDelay,
		inflight:    make(chan struct{}, limit),
		serve:       (*dns.Server).ActivateAndServe,
		stopTimeout: stopTimeout,
	}
}

// Addr returns the address the forwarder listens on: the bound address while
// running (which resolves a ":0" port), the configured one otherwise.
func (f *Forwarder) Addr() string {
	if bound, ok := f.bound.Load().(string); ok && f.running.Load() {
		return bound
	}
	return f.addr
}

// Start binds both listeners and waits until both serve before returning, so
// a caller that sees no error can immediately point resolver files at the
// forwarder, and a Stop right after Start always closes the listeners.
func (f *Forwarder) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.running.Load() {
		return nil
	}

	pc, ln, err := f.listen()
	if err != nil {
		return err
	}

	started := make(chan struct{}, 2)
	serveErr := make(chan error, 2)
	notify := func() { started <- struct{}{} }
	f.udp = &dns.Server{PacketConn: pc, Handler: f, NotifyStartedFunc: notify}
	f.tcp = &dns.Server{Listener: ln, Handler: f, NotifyStartedFunc: notify}
	f.failed.Store(false)
	gen := f.gen.Add(1)
	serve := f.serve
	for _, srv := range []*dns.Server{f.udp, f.tcp} {
		go func(srv *dns.Server) {
			err := serve(srv)
			if err == nil {
				return
			}
			if f.gen.Load() == gen {
				f.failed.Store(true)
				f.logger.Warn("dns forwarder stopped serving", "error", err)
			}
			// Sent after the failed flag so Start, which clears the flag for
			// a run it abandons, always has the last word. serveErr holds
			// one slot per listener, so this never blocks.
			serveErr <- err
		}(srv)
	}

	// A listener that fails before it signals started must end Start with an
	// error instead of leaving it waiting forever with the lock held.
	timer := time.NewTimer(startTimeout)
	defer timer.Stop()
	for ready := 0; ready < 2; {
		var failure error
		select {
		case <-started:
			ready++
			continue
		case err := <-serveErr:
			failure = fmt.Errorf("serve dns forwarder on %s: %w", f.addr, err)
		case <-timer.C:
			failure = fmt.Errorf("serve dns forwarder on %s: %w", f.addr, errStartTimeout)
		}
		// Retire this run, then close the sockets so any listener that did
		// start unwinds on its own.
		f.gen.Add(1)
		f.failed.Store(false)
		pc.Close()
		ln.Close()
		return failure
	}

	f.bound.Store(pc.LocalAddr().String())
	f.running.Store(true)
	return nil
}

var errStartTimeout = errors.New("listeners did not start in time")

// listenAttempt is one address to try binding. shared sets SO_REUSEADDR where
// the OS supports it, which on Windows lets a specific address be bound while
// another service holds the same port on the wildcard address.
type listenAttempt struct {
	addr   string
	shared bool
}

// attempts lists the addresses to try in order: the primary one, each fallback
// host at the same port, and last the primary address again with a shared bind.
// The shared bind also lets another local process bind the same address, so it
// is only tried when the caller opted into fallbacks.
func (f *Forwarder) attempts() []listenAttempt {
	out := []listenAttempt{{addr: f.addr}}
	if len(f.cfg.FallbackHosts) == 0 {
		return out
	}
	if _, port, err := net.SplitHostPort(f.addr); err == nil {
		for _, host := range f.cfg.FallbackHosts {
			out = append(out, listenAttempt{addr: net.JoinHostPort(host, port)})
		}
	}
	if shareListener != nil {
		out = append(out, listenAttempt{addr: f.addr, shared: true})
	}
	return out
}

// listen binds the UDP and TCP listeners at the first address that works. When
// none does, it returns the error of the primary address.
func (f *Forwarder) listen() (net.PacketConn, net.Listener, error) {
	var first error
	for i, a := range f.attempts() {
		pc, ln, err := listenBoth(a)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if i > 0 {
			f.logger.Warn("dns forwarder address is taken; listening elsewhere",
				"wanted", f.addr, "listening", pc.LocalAddr().String(), "shared", a.shared)
		}
		return pc, ln, nil
	}
	return nil, nil, first
}

func listenBoth(a listenAttempt) (net.PacketConn, net.Listener, error) {
	var lc net.ListenConfig
	if a.shared {
		lc.Control = shareListener
	}
	ctx := context.Background()
	pc, err := lc.ListenPacket(ctx, "udp", a.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen udp %s: %w", a.addr, err)
	}
	// TCP shares the UDP port, so an ephemeral ":0" request binds both
	// protocols to the same number.
	ln, err := lc.Listen(ctx, "tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return nil, nil, fmt.Errorf("listen tcp %s: %w", a.addr, err)
	}
	return pc, ln, nil
}

// Running reports whether the forwarder is listening and both listeners are
// still serving.
func (f *Forwarder) Running() bool {
	return f.running.Load() && !f.failed.Load()
}

// Stop closes both listeners and waits for in-flight handlers, but no longer
// than stopTimeout. It is safe to call more than once.
func (f *Forwarder) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.running.Load() {
		return
	}
	f.running.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), f.stopTimeout)
	defer cancel()
	for _, srv := range []*dns.Server{f.udp, f.tcp} {
		if err := srv.ShutdownContext(ctx); err != nil {
			f.logger.Debug("dns forwarder shutdown", "error", err)
		}
	}
}

// ServeDNS forwards one query and, for wildcard-matched names, routes the answer
// before replying.
func (f *Forwarder) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	select {
	case f.inflight <- struct{}{}:
		defer func() { <-f.inflight }()
	default:
		// Saturated: fail fast so the client retries rather than queueing
		// behind queries that may be waiting out an upstream timeout.
		f.logger.Debug("dns forwarder saturated, answering SERVFAIL")
		fail := new(dns.Msg)
		fail.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(fail)
		return
	}

	network := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		network = "tcp"
	}

	reply := f.exchange(req, network)
	if reply == nil {
		fail := new(dns.Msg)
		fail.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(fail)
		return
	}

	if len(req.Question) == 1 && f.cfg.Matches != nil {
		q := req.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		if f.cfg.Matches(name) {
			switch q.Qtype {
			case dns.TypeA:
				f.routeAnswer(name, reply)
			case dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
				// RouteWise routes IPv4 only. Hiding IPv6 answers, and the
				// HTTPS/SVCB records that can carry address hints, makes
				// the client connect to the A answer, through the route
				// installed for it, instead of bypassing the VPN.
				reply.Answer = nil
			}
		}
	}

	reply.Id = req.Id
	if err := w.WriteMsg(reply); err != nil {
		f.logger.Debug("dns forwarder write failed", "error", err)
	}
}

// exchange asks the upstream groups in order and returns the first usable answer.
// SERVFAIL, REFUSED, and no reply move on to the next group once every server of
// the current one has failed; any other rcode, including NXDOMAIN, is an answer.
func (f *Forwarder) exchange(req *dns.Msg, network string) *dns.Msg {
	if f.cfg.Upstreams == nil {
		return nil
	}
	name := ""
	if len(req.Question) == 1 {
		name = strings.TrimSuffix(strings.ToLower(req.Question[0].Name), ".")
	}
	client := &dns.Client{Net: network, Timeout: upstreamTimeout}
	var last *dns.Msg
	for _, group := range f.cfg.Upstreams(name) {
		if len(group) == 0 {
			continue
		}
		answer, failure := f.askGroup(client, req, group)
		if answer != nil {
			return answer
		}
		if failure != nil {
			last = failure
		}
	}
	return last
}

func (f *Forwarder) routeAnswer(name string, reply *dns.Msg) {
	if f.cfg.OnMatch == nil || reply.Rcode != dns.RcodeSuccess {
		return
	}
	var ips []netip.Addr
	minTTL := uint32(0)
	for _, rr := range reply.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(a.A.To4())
		if !ok {
			continue
		}
		ips = append(ips, addr)
		if minTTL == 0 || a.Hdr.Ttl < minTTL {
			minTTL = a.Hdr.Ttl
		}
	}
	if len(ips) > 0 {
		f.cfg.OnMatch(name, ips, time.Duration(minTTL)*time.Second)
	}
}

// upstreamAddr adds the DNS port to a bare server address. An address that
// already names a port is used as is.
func upstreamAddr(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}
