package daemon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/dnswatch"
)

const (
	listedName = "api.rw-test.invalid"
	listedV6   = "2001:db8::1"
	listedV4   = "93.184.216.34"
)

// blockClock is a clock a test moves by hand.
type blockClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *blockClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *blockClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ipv6Env is a started daemon whose route commands run against a fake kernel
// and whose block clock is the test's.
type ipv6Env struct {
	d     *Daemon
	k     *fakeKernel
	clock *blockClock
	// journal is where the daemon records blocked addresses.
	journal string
}

func newIPv6Env(t *testing.T, before func(k *fakeKernel, journal string), patterns ...string) *ipv6Env {
	t.Helper()
	env := &ipv6Env{k: newFakeKernel(), clock: &blockClock{t: time.Unix(1_800_000_000, 0)}}
	if len(patterns) == 0 {
		patterns = []string{listedName}
	}
	env.d, _, _, _ = newDNSTestDaemonWith(t, func(d *Daemon) {
		d.routeManager.SetCommandRunner(env.k)
		d.ipv6Block.now = env.clock.now
		env.journal = filepath.Join(filepath.Dir(d.routeManager.JournalPath()), ipv6BlockJournalName)
		if before != nil {
			before(env.k, env.journal)
		}
	}, patterns...)
	return env
}

func answerOf(name string, ttl time.Duration, addrs ...string) dnswatch.Answer {
	a := dnswatch.Answer{Name: name, Server: netip.MustParseAddr("1.1.1.1"), Interface: "en0", TTL: ttl}
	for _, s := range addrs {
		a.Addresses = append(a.Addresses, netip.MustParseAddr(s))
	}
	return a
}

func readJournal(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var j ipv6Journal
	if err := json.Unmarshal(data, &j); err != nil {
		t.Fatal(err)
	}
	return j.Addresses
}

func TestListedAAAAAnswerGetsARejectRouteAndAnUnlistedOneDoesNot(t *testing.T) {
	env := newIPv6Env(t, nil)

	env.d.onDNSAnswer(answerOf(listedName, time.Minute, listedV4, listedV6))
	env.d.onDNSAnswer(answerOf("unlisted.example.org", time.Minute, "2001:db8::2"))

	if !env.k.hasReject(listedV6) {
		t.Fatalf("no reject route for %s: %v", listedV6, env.k.log())
	}
	if env.k.hasReject("2001:db8::2") || env.k.rejectCount() != 1 {
		t.Fatal("only the listed name's IPv6 address may be blocked")
	}
	if env.k.has("add -host " + listedV4) {
		t.Fatal("an IPv4 address must never get a reject route")
	}
	if got := readJournal(t, env.journal); len(got) != 1 || got[0] != listedV6 {
		t.Fatalf("journal = %v, want %s", got, listedV6)
	}
	if !env.k.has("route -n add -inet6 -host " + listedV6 + " ::1 -reject") {
		t.Fatalf("commands = %v, want a reject (not blackhole) route", env.k.log())
	}

	env.d.recordDNSAnswer(answerOf(listedName, time.Minute, listedV4, listedV6))
	events := eventsOfKind(env.d, activity.KindDNS)
	if len(events) != 1 {
		t.Fatalf("DNS events = %d, want 1", len(events))
	}
	for _, a := range events[0].Addresses {
		if want := a.IP == listedV6; a.Blocked != want {
			t.Errorf("address %s blocked = %v, want %v", a.IP, a.Blocked, want)
		}
	}
}

func TestEveryListKindBlocksIPv6WhateverItsTunnelDoes(t *testing.T) {
	env := newIPv6Env(t, nil, "*.rw-test.invalid", "exact.rw-test.example")
	// No tunnel is connected, so nothing is routed; the block still applies.
	env.d.blockListedIPv6(answerOf("a.rw-test.invalid", 0, "2001:db8::10"))
	env.d.blockListedIPv6(answerOf("exact.rw-test.example", 0, "2001:db8::11"))
	if !env.k.hasReject("2001:db8::10") || !env.k.hasReject("2001:db8::11") {
		t.Fatalf("wildcard and exact names must both be blocked: %v", env.k.log())
	}
}

func TestNothingIsBlockedWhileIPv6IsAllowed(t *testing.T) {
	env := newIPv6Env(t, nil)
	if err := env.d.SetAllowIPv6(true); err != nil {
		t.Fatal(err)
	}
	env.d.onDNSAnswer(answerOf(listedName, time.Minute, listedV6))
	if env.k.rejectCount() != 0 || env.d.ipv6Block.count() != 0 {
		t.Fatalf("a reject route was added while IPv6 is allowed: %v", env.k.log())
	}
	env.d.recordDNSAnswer(answerOf(listedName, time.Minute, listedV6))
	if a := eventsOfKind(env.d, activity.KindDNS)[0].Addresses[0]; a.Blocked {
		t.Fatalf("address = %+v, want it not blocked", a)
	}
	if readJournal(t, env.journal) != nil {
		t.Fatal("no journal is kept while nothing is blocked")
	}
}

func TestBlockLastsAtLeastFiveMinutesAndLaterAnswersExtendIt(t *testing.T) {
	env := newIPv6Env(t, nil)
	b := env.d.ipv6Block

	env.d.blockListedIPv6(answerOf(listedName, 10*time.Second, listedV6))
	env.clock.advance(4 * time.Minute)
	b.sweep()
	if !env.k.hasReject(listedV6) {
		t.Fatal("a short TTL must still hold the block for five minutes")
	}

	// A later answer with a long TTL extends it from now: expiry is minute 14.
	env.d.blockListedIPv6(answerOf(listedName, 10*time.Minute, listedV6))
	env.clock.advance(time.Minute)
	// A shorter answer afterwards never shortens it.
	env.d.blockListedIPv6(answerOf(listedName, time.Second, listedV6))
	env.clock.advance(8 * time.Minute)
	b.sweep()
	if !env.k.hasReject(listedV6) {
		t.Fatal("a refreshed block must outlive the first answer and keep its longest expiry")
	}
	env.clock.advance(time.Minute)
	b.sweep()
	if env.k.hasReject(listedV6) || b.isBlocked(netip.MustParseAddr(listedV6)) {
		t.Fatal("the block must go once its time has run out")
	}
	if readJournal(t, env.journal) != nil {
		t.Fatal("the journal must be cleared with the last block")
	}
}

func TestTurningAllowIPv6OnRemovesEveryBlock(t *testing.T) {
	env := newIPv6Env(t, nil)
	env.d.blockListedIPv6(answerOf(listedName, 0, listedV6, "2001:db8::3"))
	if env.k.rejectCount() != 2 {
		t.Fatalf("setup: %d reject routes, want 2", env.k.rejectCount())
	}
	if err := env.d.SetAllowIPv6(true); err != nil {
		t.Fatal(err)
	}
	if env.k.rejectCount() != 0 || env.d.ipv6Block.count() != 0 || readJournal(t, env.journal) != nil {
		t.Fatalf("blocks left after allowing IPv6: %v", env.k.log())
	}
	if !env.d.Settings().AllowIPv6 {
		t.Fatal("settings must report allowIpv6")
	}
	// Turning it off blocks again from the next answer.
	if err := env.d.SetAllowIPv6(false); err != nil {
		t.Fatal(err)
	}
	env.d.blockListedIPv6(answerOf(listedName, 0, listedV6))
	if !env.k.hasReject(listedV6) {
		t.Fatal("blocking must resume once IPv6 is not allowed")
	}
}

func TestStoppingTheHelperRemovesEveryBlock(t *testing.T) {
	env := newIPv6Env(t, nil)
	env.d.blockListedIPv6(answerOf(listedName, 0, listedV6))
	env.d.Stop()
	if env.k.rejectCount() != 0 || readJournal(t, env.journal) != nil {
		t.Fatalf("blocks left after stop: %v", env.k.log())
	}
	// A late answer cannot add a route to a stopped helper.
	env.d.blockListedIPv6(answerOf(listedName, 0, listedV6))
	if env.k.rejectCount() != 0 {
		t.Fatal("a stopped helper must not add reject routes")
	}
}

func TestStartRemovesRejectRoutesAJournalSaysAPreviousRunLeft(t *testing.T) {
	env := newIPv6Env(t, func(k *fakeKernel, journal string) {
		k.putReject("2001:db8::aa")
		k.putReject("2001:db8::bb")
		// ::1 in a journal is never touched; the other address is already gone.
		data := `{"schema_version":1,"addresses":["2001:db8::aa","2001:db8::bb","::1","2001:db8::cc","junk"]}`
		if err := os.WriteFile(journal, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if env.k.rejectCount() != 0 {
		t.Fatalf("leftovers remain: %v", env.k.log())
	}
	if env.k.has("delete -inet6 -host ::1") {
		t.Fatal("::1 must never be deleted")
	}
	if _, err := os.Stat(env.journal); !os.IsNotExist(err) {
		t.Fatalf("journal must be cleared after recovery (err=%v)", err)
	}
}

func TestMalformedJournalIsLeftAloneAtStart(t *testing.T) {
	env := newIPv6Env(t, func(k *fakeKernel, journal string) {
		k.putReject("2001:db8::aa")
		if err := os.WriteFile(journal, []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if !env.k.hasReject("2001:db8::aa") {
		t.Fatal("an untrusted journal must not drive deletes")
	}
	if _, err := os.Stat(env.journal); err != nil {
		t.Fatalf("an untrusted journal is kept for inspection: %v", err)
	}
}

func TestInvalidAddressesAreNeverBlocked(t *testing.T) {
	env := newIPv6Env(t, nil)
	for _, bad := range []string{"::1", "fe80::1", "ff02::1", "fd00::1", "::"} {
		if err := env.d.ipv6Block.block(netip.MustParseAddr(bad), time.Hour); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	// Through an answer: refused with a log, never a route.
	env.d.blockListedIPv6(answerOf(listedName, 0, "fe80::1", "::1", "fd00::2", "::ffff:93.184.216.34"))
	if env.k.rejectCount() != 0 || env.d.ipv6Block.count() != 0 {
		t.Fatalf("invalid addresses got routes: %v", env.k.log())
	}
}

func TestBlockCapReleasesTheLongestUnrefreshedAddress(t *testing.T) {
	env := newIPv6Env(t, nil)
	b := env.d.ipv6Block
	b.capacity = 3
	for i := 1; i <= 3; i++ {
		if err := b.block(netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i)), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	// An answer for the first address makes the second the oldest.
	if err := b.block(netip.MustParseAddr("2001:db8::1"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := b.block(netip.MustParseAddr("2001:db8::4"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if b.count() != 3 || env.k.rejectCount() != 3 {
		t.Fatalf("held %d (kernel %d), want the cap of 3", b.count(), env.k.rejectCount())
	}
	if env.k.hasReject("2001:db8::2") || !env.k.hasReject("2001:db8::1") || !env.k.hasReject("2001:db8::4") {
		t.Fatalf("eviction picked the wrong address: %v", env.k.log())
	}
	if got := readJournal(t, env.journal); len(got) != 3 {
		t.Fatalf("journal = %v, want 3 addresses", got)
	}
}

func TestFailedRouteAddIsNotRemembered(t *testing.T) {
	env := newIPv6Env(t, nil)
	env.k.failNext("-inet6", fmt.Errorf("route: writing to routing socket: Operation not permitted"))
	env.d.blockListedIPv6(answerOf(listedName, 0, listedV6))
	if env.d.ipv6Block.isBlocked(netip.MustParseAddr(listedV6)) || readJournal(t, env.journal) != nil {
		t.Fatal("an address whose route failed must not be recorded as blocked")
	}
}

func TestCheckHostSaysAnIPv6AddressIsBlocked(t *testing.T) {
	env := newIPv6Env(t, nil)
	env.d.blockListedIPv6(answerOf(listedName, 0, listedV6))

	got, err := env.d.CheckHost(listedV6)
	if err != nil {
		t.Fatal(err)
	}
	if n := got.Addresses[0].Note; n != "IPv6 blocked so apps use IPv4" {
		t.Fatalf("note = %q, want the blocked note", n)
	}
	other, err := env.d.CheckHost("2001:db8::99")
	if err != nil {
		t.Fatal(err)
	}
	if n := other.Addresses[0].Note; n != "IPv6 is not routed by RouteWise" {
		t.Fatalf("note = %q, want the unrouted note for an address that is not blocked", n)
	}
}

func TestImportAppliesAllowIPv6Live(t *testing.T) {
	env := newIPv6Env(t, nil)
	env.d.blockListedIPv6(answerOf(listedName, 0, listedV6))

	export := env.d.ExportConfig()
	if export.Routing.AllowIPv6 {
		t.Fatal("export must start with the default (blocking)")
	}
	export.Routing.AllowIPv6 = true
	if _, err := env.d.ImportConfig(export); err != nil {
		t.Fatal(err)
	}
	if !env.d.Settings().AllowIPv6 || env.k.rejectCount() != 0 {
		t.Fatalf("import must switch IPv6 on and drop blocks: %v", env.k.log())
	}
	if cfg, _ := env.d.store.Snapshot(); !cfg.Routing.AllowIPv6 {
		t.Fatal("import must persist the setting")
	}
	if !env.d.ExportConfig().Routing.AllowIPv6 {
		t.Fatal("export must carry the setting")
	}
}

func TestSetAllowIPv6PersistsAndDoesNotBumpRevisionWhenUnchanged(t *testing.T) {
	store := newTestStore(t)
	_, rev := store.Snapshot()
	if got, err := store.SetAllowIPv6(false); err != nil || got != rev {
		t.Fatalf("unchanged SetAllowIPv6 = (%d, %v), want revision %d", got, err, rev)
	}
	got, err := store.SetAllowIPv6(true)
	if err != nil || got == rev {
		t.Fatalf("SetAllowIPv6(true) = (%d, %v), want a new revision", got, err)
	}
	if cfg, _ := store.Snapshot(); !cfg.Routing.AllowIPv6 {
		t.Fatal("setting not stored")
	}
}

// One answer with several addresses is one journal write, however many routes
// follow, and a refused address does not stop the rest.
func TestAnAnswersAddressesShareOneJournalWrite(t *testing.T) {
	env := newIPv6Env(t, nil)
	b := env.d.ipv6Block
	writes := 0
	path := b.journalPath
	b.journalPath = func() string { writes++; return path() }

	addrs := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:db8::3"),
	}
	if err := b.blockAll(addrs, time.Hour); err == nil {
		t.Fatal("the link-local address must be reported as refused")
	}
	if writes != 1 {
		t.Fatalf("journal writes = %d, want 1 for the whole answer", writes)
	}
	if env.k.rejectCount() != 3 || b.count() != 3 {
		t.Fatalf("held %d (kernel %d), want the 3 valid addresses blocked", b.count(), env.k.rejectCount())
	}
	if got := readJournal(t, env.journal); len(got) != 3 {
		t.Fatalf("journal = %v, want 3 addresses", got)
	}
}

func BenchmarkIPv6JournalSave(b *testing.B) {
	dir := b.TempDir()
	blocker := newIPv6Blocker(func() bool { return false }, nil, func() string { return filepath.Join(dir, "ipv6-blocked.json") }, slog.New(slog.DiscardHandler))
	for i := range 50 {
		blocker.entries[netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i+1))] = &blockedAddress{}
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := blocker.saveJournalLocked(); err != nil {
			b.Fatal(err)
		}
	}
}
