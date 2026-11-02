package dnsproxy

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeUpstream is a loopback DNS server that answers every A query with addr,
// every AAAA query with an IPv6 address, or with rcode when rcode is set.
func fakeUpstream(t *testing.T, addr string, rcode int) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)
		if rcode != dns.RcodeSuccess {
			reply.Rcode = rcode
			_ = w.WriteMsg(reply)
			return
		}
		q := req.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			rr, _ := dns.NewRR(q.Name + " 120 IN A " + addr)
			reply.Answer = append(reply.Answer, rr)
		case dns.TypeAAAA:
			rr, _ := dns.NewRR(q.Name + " 120 IN AAAA 2001:db8::1")
			reply.Answer = append(reply.Answer, rr)
		}
		_ = w.WriteMsg(reply)
	})
	// Real DNS servers answer on TCP too, on the same port.
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("listen upstream tcp: %v", err)
	}
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: ln, Handler: handler}} {
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return pc.LocalAddr().String()
}

type recorder struct {
	mu    sync.Mutex
	names []string
	ips   []netip.Addr
	ttl   time.Duration
}

func (r *recorder) onMatch(name string, ips []netip.Addr, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, name)
	r.ips = append(r.ips, ips...)
	r.ttl = ttl
}

func (r *recorder) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.names)
}

func startForwarder(t *testing.T, upstreams []string, rec *recorder) *Forwarder {
	t.Helper()
	f := NewAt("127.0.0.1:0", Config{
		Upstreams: func(string) [][]string { return [][]string{upstreams} },
		Matches:   func(name string) bool { return strings.HasSuffix(name, ".corp.example.com") },
		OnMatch:   rec.onMatch,
	})
	if err := f.Start(); err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	t.Cleanup(f.Stop)
	return f
}

func query(t *testing.T, f *Forwarder, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	reply, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, f.Addr())
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return reply
}

func TestForwarderRoutesMatchingAnswerBeforeReplying(t *testing.T) {
	rec := &recorder{}
	f := startForwarder(t, []string{fakeUpstream(t, "10.20.30.40", dns.RcodeSuccess)}, rec)

	reply := query(t, f, "api.corp.example.com", dns.TypeA)

	if len(reply.Answer) != 1 {
		t.Fatalf("expected the upstream answer to be passed through, got %v", reply.Answer)
	}
	// The callback runs synchronously before WriteMsg, so by the time the
	// client holds the reply the route request has already been made.
	if rec.calls() != 1 {
		t.Fatalf("expected one route request before the reply, got %d", rec.calls())
	}
	if rec.names[0] != "api.corp.example.com" || rec.ips[0] != netip.MustParseAddr("10.20.30.40") {
		t.Errorf("route request = %v %v, want api.corp.example.com 10.20.30.40", rec.names, rec.ips)
	}
	if rec.ttl != 120*time.Second {
		t.Errorf("ttl = %v, want 120s", rec.ttl)
	}
}

func TestForwarderPassesOtherNamesThroughUntouched(t *testing.T) {
	rec := &recorder{}
	f := startForwarder(t, []string{fakeUpstream(t, "10.20.30.40", dns.RcodeSuccess)}, rec)

	reply := query(t, f, "www.example.com", dns.TypeA)

	if len(reply.Answer) != 1 {
		t.Fatalf("expected a pass-through answer, got %v", reply.Answer)
	}
	if rec.calls() != 0 {
		t.Error("a name outside every wildcard must not be routed")
	}
}

func TestForwarderHidesIPv6ForMatchingNames(t *testing.T) {
	rec := &recorder{}
	f := startForwarder(t, []string{fakeUpstream(t, "10.20.30.40", dns.RcodeSuccess)}, rec)

	if reply := query(t, f, "api.corp.example.com", dns.TypeAAAA); len(reply.Answer) != 0 {
		t.Errorf("AAAA answer for a routed name must be empty, got %v", reply.Answer)
	}
	if reply := query(t, f, "www.example.com", dns.TypeAAAA); len(reply.Answer) != 1 {
		t.Errorf("AAAA answer for an unrelated name must pass through, got %v", reply.Answer)
	}
}

func TestForwarderFallsBackPastAFailingUpstream(t *testing.T) {
	rec := &recorder{}
	failing := fakeUpstream(t, "", dns.RcodeServerFailure)
	working := fakeUpstream(t, "10.9.9.9", dns.RcodeSuccess)
	f := startForwarder(t, []string{failing, working}, rec)

	reply := query(t, f, "api.corp.example.com", dns.TypeA)

	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
		t.Fatalf("expected the second upstream's answer, got rcode %d answers %v", reply.Rcode, reply.Answer)
	}
	if rec.calls() != 1 || rec.ips[0] != netip.MustParseAddr("10.9.9.9") {
		t.Errorf("expected the fallback answer to be routed, got %v", rec.ips)
	}
}

func TestForwarderAnswersServfailWithoutUpstreams(t *testing.T) {
	rec := &recorder{}
	f := startForwarder(t, nil, rec)

	reply := query(t, f, "api.corp.example.com", dns.TypeA)

	if reply.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %d, want SERVFAIL", reply.Rcode)
	}
	if rec.calls() != 0 {
		t.Error("a failed lookup must not route anything")
	}
}

func TestUpstreamAddr(t *testing.T) {
	if got := upstreamAddr("10.0.0.2"); got != "10.0.0.2:53" {
		t.Errorf("bare address = %q, want 10.0.0.2:53", got)
	}
	if got := upstreamAddr("127.0.0.1:5300"); got != "127.0.0.1:5300" {
		t.Errorf("address with port = %q, want it unchanged", got)
	}
}

func TestForwarderStopRightAfterStartReleasesThePort(t *testing.T) {
	f := NewAt("127.0.0.1:0", Config{})
	if err := f.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	addr := f.Addr()
	f.Stop()

	if f.Running() {
		t.Error("Running() after Stop must be false")
	}
	again := NewAt(addr, Config{})
	if err := again.Start(); err != nil {
		t.Fatalf("the port must be free after Stop, got %v", err)
	}
	again.Stop()
}

func TestForwarderAnswersOverTCP(t *testing.T) {
	rec := &recorder{}
	f := startForwarder(t, []string{fakeUpstream(t, "10.20.30.40", dns.RcodeSuccess)}, rec)

	m := new(dns.Msg)
	m.SetQuestion("api.corp.example.com.", dns.TypeA)
	reply, _, err := (&dns.Client{Net: "tcp", Timeout: 2 * time.Second}).Exchange(m, f.Addr())
	if err != nil {
		t.Fatalf("tcp query: %v", err)
	}
	if len(reply.Answer) != 1 || rec.calls() != 1 {
		t.Errorf("tcp answers=%d routed=%d, want 1 and 1", len(reply.Answer), rec.calls())
	}
}

func TestForwarderHidesHTTPSRecordsForMatchingNames(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)
		rr, _ := dns.NewRR(req.Question[0].Name + ` 300 IN HTTPS 1 . alpn="h2" ipv6hint=2001:db8::1`)
		reply.Answer = append(reply.Answer, rr)
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	f := startForwarder(t, []string{pc.LocalAddr().String()}, &recorder{})

	if reply := query(t, f, "api.corp.example.com", dns.TypeHTTPS); len(reply.Answer) != 0 {
		t.Errorf("HTTPS records carry address hints and must be hidden for routed names, got %v", reply.Answer)
	}
	if reply := query(t, f, "www.example.com", dns.TypeHTTPS); len(reply.Answer) != 1 {
		t.Errorf("HTTPS records for unrelated names must pass through, got %v", reply.Answer)
	}
}

// Names under different suffixes may belong to different VPNs, so the
// upstreams are asked for per name.
func TestForwarderChoosesUpstreamsPerName(t *testing.T) {
	corp := fakeUpstream(t, "10.1.1.1", dns.RcodeSuccess)
	lab := fakeUpstream(t, "10.2.2.2", dns.RcodeSuccess)
	f := NewAt("127.0.0.1:0", Config{
		Upstreams: func(name string) [][]string {
			if strings.HasSuffix(name, ".lab.example.com") {
				return [][]string{{lab}}
			}
			return [][]string{{corp}}
		},
	})
	if err := f.Start(); err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	t.Cleanup(f.Stop)

	answerOf := func(name string) string {
		reply := query(t, f, name, dns.TypeA)
		if len(reply.Answer) != 1 {
			t.Fatalf("answer for %s = %v", name, reply.Answer)
		}
		return reply.Answer[0].(*dns.A).A.String()
	}
	if got := answerOf("git.corp.example.com"); got != "10.1.1.1" {
		t.Errorf("corp name answered by %s, want the corp upstream", got)
	}
	if got := answerOf("wiki.lab.example.com"); got != "10.2.2.2" {
		t.Errorf("lab name answered by %s, want the lab upstream", got)
	}
}

func TestStartReturnsErrorWhenListenerFailsBeforeServing(t *testing.T) {
	f := NewAt("127.0.0.1:0", Config{})
	f.serve = func(*dns.Server) error { return errors.New("socket options rejected") }

	done := make(chan error, 1)
	go func() { done <- f.Start() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "socket options rejected") {
			t.Fatalf("Start error = %v, want the serve failure", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start hung after a listener failed before signalling started")
	}
	if f.Running() {
		t.Error("a forwarder whose Start failed must not report running")
	}

	stopped := make(chan struct{})
	go func() { f.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop hung after a failed Start")
	}
}

func TestStartCanRetryAfterFailure(t *testing.T) {
	f := NewAt("127.0.0.1:0", Config{})
	real := f.serve
	f.serve = func(*dns.Server) error { return errors.New("boom") }
	if err := f.Start(); err == nil {
		t.Fatal("expected the first Start to fail")
	}
	f.serve = real
	if err := f.Start(); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	defer f.Stop()
	if !f.Running() {
		t.Error("forwarder must be running after a successful retry")
	}
}

// blockingUpstream returns an Upstreams func whose first call parks until
// release is closed, and a channel signalling that a query reached it.
func blockingUpstream(upstream string) (up func(string) [][]string, entered chan struct{}, release chan struct{}) {
	entered = make(chan struct{}, 16)
	release = make(chan struct{})
	up = func(string) [][]string {
		entered <- struct{}{}
		<-release
		return [][]string{{upstream}}
	}
	return up, entered, release
}

func TestStopIsBoundedWhileAHandlerIsStuck(t *testing.T) {
	up, entered, release := blockingUpstream(fakeUpstream(t, "10.20.30.40", dns.RcodeSuccess))
	defer close(release)
	f := NewAt("127.0.0.1:0", Config{Upstreams: up})
	f.stopTimeout = 200 * time.Millisecond
	if err := f.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	m := new(dns.Msg)
	m.SetQuestion("slow.example.com.", dns.TypeA)
	go func() { _, _, _ = (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, f.Addr()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("query never reached the handler")
	}

	stopped := make(chan struct{})
	go func() { f.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop waited on a stuck handler past its bound")
	}
}

func TestSaturatedForwarderAnswersServfailImmediately(t *testing.T) {
	up, entered, release := blockingUpstream(fakeUpstream(t, "10.20.30.40", dns.RcodeSuccess))
	defer close(release)
	f := NewAt("127.0.0.1:0", Config{Upstreams: up, MaxInFlight: 1})
	f.stopTimeout = 100 * time.Millisecond
	if err := f.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer f.Stop()

	first := new(dns.Msg)
	first.SetQuestion("one.example.com.", dns.TypeA)
	go func() { _, _, _ = (&dns.Client{Timeout: 3 * time.Second}).Exchange(first, f.Addr()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first query never reached the handler")
	}

	start := time.Now()
	reply := query(t, f, "two.example.com", dns.TypeA)
	if reply.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL while saturated", dns.RcodeToString[reply.Rcode])
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("saturated answer took %v, want immediate", elapsed)
	}
}

func TestInFlightSlotIsReleasedAfterQuery(t *testing.T) {
	rec := &recorder{}
	f := startForwarder(t, []string{fakeUpstream(t, "10.20.30.40", dns.RcodeSuccess)}, rec)
	for i := 0; i < 3*cap(f.inflight); i++ {
		if reply := query(t, f, "www.example.com", dns.TypeA); reply.Rcode != dns.RcodeSuccess {
			t.Fatalf("query %d rcode = %s", i, dns.RcodeToString[reply.Rcode])
		}
	}
	if len(f.inflight) != 0 {
		t.Errorf("%d in-flight slots leaked", len(f.inflight))
	}
}
