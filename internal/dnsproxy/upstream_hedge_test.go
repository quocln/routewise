package dnsproxy

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// countingUpstream is a loopback DNS server that waits for delay, then answers A
// queries with addr, or with rcode when rcode is set. The counter says how many
// queries reached it.
func countingUpstream(t *testing.T, addr string, rcode int, delay time.Duration) (string, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	asked := new(atomic.Int32)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		asked.Add(1)
		time.Sleep(delay)
		reply := new(dns.Msg)
		reply.SetReply(req)
		reply.Rcode = rcode
		if rcode == dns.RcodeSuccess && addr != "" {
			rr, _ := dns.NewRR(req.Question[0].Name + " 120 IN A " + addr)
			reply.Answer = append(reply.Answer, rr)
		}
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), asked
}

// silentUpstream is an address that accepts queries and never answers.
func silentUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

func startHedgingForwarder(t *testing.T, rec *recorder, groups ...[]string) *Forwarder {
	t.Helper()
	cfg := Config{
		Upstreams:  func(string) [][]string { return groups },
		HedgeDelay: 20 * time.Millisecond,
	}
	if rec != nil {
		cfg.Matches = func(string) bool { return true }
		cfg.OnMatch = rec.onMatch
	}
	f := NewAt("127.0.0.1:0", cfg)
	if err := f.Start(); err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	t.Cleanup(f.Stop)
	return f
}

func answerAddr(t *testing.T, reply *dns.Msg) string {
	t.Helper()
	if len(reply.Answer) != 1 {
		t.Fatalf("rcode %d answers %v, want one answer", reply.Rcode, reply.Answer)
	}
	return reply.Answer[0].(*dns.A).A.String()
}

func TestHedgeAsksTheNextServerWhenTheFirstIsSilent(t *testing.T) {
	rec := &recorder{}
	second, _ := countingUpstream(t, "10.2.2.2", dns.RcodeSuccess, 0)
	f := startHedgingForwarder(t, rec, []string{silentUpstream(t), second})

	start := time.Now()
	reply := query(t, f, "api.corp.example.com", dns.TypeA)

	if got := answerAddr(t, reply); got != "10.2.2.2" {
		t.Errorf("answer = %s, want the second server's", got)
	}
	if took := time.Since(start); took >= upstreamTimeout {
		t.Errorf("took %v, a silent server must not cost its whole timeout", took)
	}
	if rec.calls() != 1 || rec.ips[0] != netip.MustParseAddr("10.2.2.2") {
		t.Errorf("routed %v, want the winning answer routed once", rec.ips)
	}
}

func TestHedgeLeavesTheNextServerAloneWhenTheFirstIsQuick(t *testing.T) {
	first, _ := countingUpstream(t, "10.1.1.1", dns.RcodeSuccess, 0)
	second, askedSecond := countingUpstream(t, "10.2.2.2", dns.RcodeSuccess, 0)
	f := NewAt("127.0.0.1:0", Config{
		Upstreams:  func(string) [][]string { return [][]string{{first, second}} },
		HedgeDelay: 2 * time.Second, // far longer than a loopback reply takes
	})
	if err := f.Start(); err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	t.Cleanup(f.Stop)

	if got := answerAddr(t, query(t, f, "api.corp.example.com", dns.TypeA)); got != "10.1.1.1" {
		t.Errorf("answer = %s, want the first server's", got)
	}
	if n := askedSecond.Load(); n != 0 {
		t.Errorf("second server asked %d times, want none", n)
	}
}

// The next group may be public DNS. However slow the VPN's server is, an internal
// name must not reach it unless the VPN's server actually failed.
func TestHedgeNeverCrossesIntoTheNextGroup(t *testing.T) {
	vpn, _ := countingUpstream(t, "10.1.1.1", dns.RcodeSuccess, 200*time.Millisecond)
	public, askedPublic := countingUpstream(t, "93.184.216.34", dns.RcodeSuccess, 0)
	f := startHedgingForwarder(t, nil, []string{vpn}, []string{public})

	if got := answerAddr(t, query(t, f, "api.corp.example.com", dns.TypeA)); got != "10.1.1.1" {
		t.Errorf("answer = %s, want the slow VPN server's", got)
	}
	if n := askedPublic.Load(); n != 0 {
		t.Errorf("public server asked %d times while the VPN server was only slow", n)
	}
}

func TestNextGroupIsAskedOnlyAfterTheWholeGroupFailed(t *testing.T) {
	failing, askedFailing := countingUpstream(t, "", dns.RcodeServerFailure, 0)
	refusing, askedRefusing := countingUpstream(t, "", dns.RcodeRefused, 0)
	fallback, _ := countingUpstream(t, "10.9.9.9", dns.RcodeSuccess, 0)
	f := startHedgingForwarder(t, nil, []string{failing, refusing}, []string{fallback})

	if got := answerAddr(t, query(t, f, "api.corp.example.com", dns.TypeA)); got != "10.9.9.9" {
		t.Errorf("answer = %s, want the fallback group's", got)
	}
	if askedFailing.Load() != 1 || askedRefusing.Load() != 1 {
		t.Errorf("asked %d and %d times, want both servers of the group tried once", askedFailing.Load(), askedRefusing.Load())
	}
}

// A hedge that lost the race for being fast must not overrule a server that knows
// the zone: split-horizon servers disagree exactly like this.
func TestPositiveAnswerBeatsAFasterNegativeOne(t *testing.T) {
	knows, _ := countingUpstream(t, "10.1.1.1", dns.RcodeSuccess, 100*time.Millisecond)
	doesNot, _ := countingUpstream(t, "", dns.RcodeNameError, 0)
	f := startHedgingForwarder(t, nil, []string{knows, doesNot})

	reply := query(t, f, "api.corp.example.com", dns.TypeA)
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want the positive answer", dns.RcodeToString[reply.Rcode])
	}
	if got := answerAddr(t, reply); got != "10.1.1.1" {
		t.Errorf("answer = %s", got)
	}
}

func TestNegativeAnswerIsFinalWhenNothingElseIsInFlight(t *testing.T) {
	first, _ := countingUpstream(t, "", dns.RcodeNameError, 0)
	sameGroup, askedSameGroup := countingUpstream(t, "10.2.2.2", dns.RcodeSuccess, 0)
	nextGroup, askedNextGroup := countingUpstream(t, "10.3.3.3", dns.RcodeSuccess, 0)
	f := NewAt("127.0.0.1:0", Config{
		Upstreams:  func(string) [][]string { return [][]string{{first, sameGroup}, {nextGroup}} },
		HedgeDelay: 2 * time.Second,
	})
	if err := f.Start(); err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	t.Cleanup(f.Stop)

	reply := query(t, f, "nope.corp.example.com", dns.TypeA)
	if reply.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[reply.Rcode])
	}
	if askedSameGroup.Load() != 0 || askedNextGroup.Load() != 0 {
		t.Errorf("asked %d and %d more servers after NXDOMAIN", askedSameGroup.Load(), askedNextGroup.Load())
	}
}

func TestNegativeAnswerStandsWhenTheHedgedServerFails(t *testing.T) {
	slowNo, _ := countingUpstream(t, "", dns.RcodeNameError, 100*time.Millisecond)
	failing, _ := countingUpstream(t, "", dns.RcodeServerFailure, 0)
	nextGroup, askedNextGroup := countingUpstream(t, "10.3.3.3", dns.RcodeSuccess, 0)
	f := startHedgingForwarder(t, nil, []string{slowNo, failing}, []string{nextGroup})

	reply := query(t, f, "nope.corp.example.com", dns.TypeA)
	if reply.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[reply.Rcode])
	}
	if askedNextGroup.Load() != 0 {
		t.Error("an answer from the group must keep the name from the next one")
	}
}

func TestEveryGroupFailingAnswersServfail(t *testing.T) {
	a, _ := countingUpstream(t, "", dns.RcodeServerFailure, 0)
	b, _ := countingUpstream(t, "", dns.RcodeServerFailure, 0)
	f := startHedgingForwarder(t, nil, []string{a}, []string{b})

	if reply := query(t, f, "api.corp.example.com", dns.TypeA); reply.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", dns.RcodeToString[reply.Rcode])
	}
}

// A query that lost the race must let go of its socket at once. Without this,
// the sockets of finished queries pile up for the whole upstream timeout.
func TestCancellingAnUpstreamQueryReturnsAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := new(dns.Msg)
	m.SetQuestion("api.corp.example.com.", dns.TypeA)
	client := &dns.Client{Net: "udp", Timeout: upstreamTimeout}

	silent := silentUpstream(t)
	done := make(chan error, 1)
	go func() {
		_, err := askUpstream(ctx, client, m, silent)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("an abandoned query must report an error")
		}
	case <-time.After(upstreamTimeout / 2):
		t.Fatal("the cancelled query kept waiting for its upstream")
	}
}
