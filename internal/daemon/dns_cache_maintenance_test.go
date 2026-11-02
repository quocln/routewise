package daemon

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// learnRoute drives a wildcard answer through the real path and waits for its route.
func learnRoute(t *testing.T, d *Daemon, name string, ip netip.Addr) {
	t.Helper()
	d.onWildcardAnswer(name, []netip.Addr{ip}, time.Hour)
	waitFor(t, "the learned route", func() bool {
		_, ok := d.sessions.get("utun9").manager.GetRoute(ip)
		return ok
	})
}

func countFlushes(d *Daemon, err error) *atomic.Int32 {
	flushes := new(atomic.Int32)
	d.hooks.flushSystemDNS = func(context.Context) error {
		flushes.Add(1)
		return err
	}
	return flushes
}

func TestResolversCoverTheDaemonAndEveryTunnel(t *testing.T) {
	d, watcher, _ := newDNSTestDaemon(t, "*.corp.example.com")
	connect(watcher)
	s := waitForSession(t, d, "utun9")

	got := d.resolvers()
	if !slices.Contains(got, d.resolver) || !slices.Contains(got, s.resolver) {
		t.Errorf("resolvers = %v, want the daemon's and the tunnel's", got)
	}
}

func TestClearDNSCacheFlushesTheSystemAndLeavesRoutesAlone(t *testing.T) {
	d, watcher, _ := newDNSTestDaemon(t, "*.corp.example.com")
	connect(watcher)
	s := waitForSession(t, d, "utun9")
	ip := netip.MustParseAddr("10.1.2.3")
	learnRoute(t, d, "git.corp.example.com", ip)
	flushes := countFlushes(d, nil)

	if err := d.ClearDNSCache(); err != nil {
		t.Fatalf("ClearDNSCache: %v", err)
	}

	if flushes.Load() != 1 {
		t.Errorf("system cache flushed %d times, want once", flushes.Load())
	}
	if _, ok := s.manager.GetRoute(ip); !ok {
		t.Error("clearing the cache must not remove a route")
	}
	if _, ok := d.learnedSnapshot(s)[ip]; !ok {
		t.Error("clearing the cache must not forget a learned address")
	}
	if len(d.syncTrigger) != 0 {
		t.Error("clearing the cache must not trigger a sync, which could drop routes")
	}
}

func TestClearDNSCacheReportsASystemFlushFailure(t *testing.T) {
	d, _, _ := newDNSTestDaemon(t, "*.corp.example.com")
	countFlushes(d, errors.New("no such tool"))

	err := d.ClearDNSCache()
	if err == nil || !strings.Contains(err.Error(), "no such tool") {
		t.Fatalf("err = %v, want the flush failure", err)
	}
}

func TestCleanDNSRemovesLearnedRoutesAndKeepsOthers(t *testing.T) {
	d, watcher, _, runner := newDNSTestDaemonWith(t, func(*Daemon) {}, "*.corp.example.com")
	connect(watcher)
	s := waitForSession(t, d, "utun9")
	learned := netip.MustParseAddr("10.1.2.3")
	learnRoute(t, d, "git.corp.example.com", learned)
	// A name's address that another name's route now relies on must stay.
	shared := netip.MustParseAddr("10.1.2.4")
	if err := s.manager.AddRoute(shared, "exact.example.com", false); err != nil {
		t.Fatalf("add route: %v", err)
	}
	d.rememberLearned(s, "api.corp.example.com", []netip.Addr{shared}, time.Hour)
	flushes := countFlushes(d, nil)

	removed, err := d.CleanDNS()
	if err != nil {
		t.Fatalf("CleanDNS: %v", err)
	}

	if removed != 1 {
		t.Errorf("removed = %d, want the one learned route", removed)
	}
	if _, ok := s.manager.GetRoute(learned); ok {
		t.Error("the learned route must be gone")
	}
	if !runner.has("delete -host 10.1.2.3") {
		t.Error("the learned route must be deleted from the system's table")
	}
	if len(d.learnedSnapshot(s)) != 0 {
		t.Errorf("learned = %v, want every address forgotten", d.learnedSnapshot(s))
	}
	if flushes.Load() != 1 {
		t.Errorf("system cache flushed %d times, want once", flushes.Load())
	}
}

// After a clean, a fresh lookup must be routed again.
func TestCleanDNSLetsTheNextLookupRouteAgain(t *testing.T) {
	d, watcher, _ := newDNSTestDaemon(t, "*.corp.example.com")
	connect(watcher)
	waitForSession(t, d, "utun9")
	ip := netip.MustParseAddr("10.1.2.3")
	learnRoute(t, d, "git.corp.example.com", ip)

	if _, err := d.CleanDNS(); err != nil {
		t.Fatalf("CleanDNS: %v", err)
	}
	learnRoute(t, d, "git.corp.example.com", ip)
}

func TestCleanDNSWithoutAVPNStillFlushes(t *testing.T) {
	d, _, _ := newDNSTestDaemon(t, "*.corp.example.com")
	flushes := countFlushes(d, nil)

	removed, err := d.CleanDNS()
	if err != nil || removed != 0 {
		t.Fatalf("CleanDNS = %d, %v; want nothing removed and no error", removed, err)
	}
	if flushes.Load() != 1 {
		t.Errorf("system cache flushed %d times, want once", flushes.Load())
	}
}

func TestCleanDNSReportsWhatItRemovedWhenTheFlushFails(t *testing.T) {
	d, watcher, _ := newDNSTestDaemon(t, "*.corp.example.com")
	connect(watcher)
	waitForSession(t, d, "utun9")
	learnRoute(t, d, "git.corp.example.com", netip.MustParseAddr("10.1.2.3"))
	countFlushes(d, errors.New("no such tool"))

	removed, err := d.CleanDNS()
	if removed != 1 {
		t.Errorf("removed = %d, want the route removed despite the failed flush", removed)
	}
	if err == nil || !strings.Contains(err.Error(), "removed 1 learned routes") || !strings.Contains(err.Error(), "no such tool") {
		t.Errorf("err = %v, want the count and the failure", err)
	}
}
