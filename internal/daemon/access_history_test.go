package daemon

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/configdb"
	"github.com/quocln/routewise/internal/dnswatch"
	"github.com/quocln/routewise/internal/history"
)

// openSharedDB opens the shared database at path, closed with the test.
func openSharedDB(t testing.TB, path string) *configdb.DB {
	t.Helper()
	db, err := configdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newHistoryEnv is a started two-tunnel daemon with an open history store and
// recording on.
func newHistoryEnv(t *testing.T) *tunnelEnv {
	t.Helper()
	env := newTunnelEnv(t, nil, []string{"wg.example.com"}, []string{"aws.example.com"}, func(d *Daemon) {
		d.OpenHistory(openSharedDB(t, filepath.Join(t.TempDir(), configdb.FileName)))
	})
	on := true
	if err := env.d.SetHistory(&on, nil); err != nil {
		t.Fatal(err)
	}
	return env
}

func flowOn(iface, dst string, port uint16, proto dnswatch.Proto) dnswatch.Flow {
	return dnswatch.Flow{
		Time: time.Now(), Interface: iface, Src: netip.MustParseAddr("10.0.0.2"),
		Dst: netip.MustParseAddr(dst), DstPort: port, Proto: proto,
	}
}

func accessEntries(t *testing.T, d *Daemon) []history.Entry {
	t.Helper()
	d.history.Flush()
	res, err := d.AccessList(api.AccessListParams{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Entries
}

func TestFlowVerdictFollowsTheCaptureInterface(t *testing.T) {
	env := newHistoryEnv(t)
	env.connectWG()
	waitForSession(t, env.d, wgIface)

	env.d.onFlow(flowOn(wgIface, "10.100.0.1", 443, dnswatch.ProtoTCP))
	env.d.onFlow(flowOn(unmanagedTunIface, "10.50.0.1", 22, dnswatch.ProtoTCP)) // a tunnel RouteWise does not manage
	env.d.onFlow(flowOn("en0", "93.184.216.34", 443, dnswatch.ProtoUDP))

	got := map[string]history.Entry{}
	for _, e := range accessEntries(t, env.d) {
		got[e.Interface] = e
	}
	if e := got[wgIface]; e.Verdict != "vpn" || e.VPN != "WireGuard" || e.IP != "10.100.0.1" || e.Port != 443 || e.Proto != "tcp" {
		t.Errorf("managed tunnel flow = %+v, want vpn through WireGuard", e)
	}
	if e := got[unmanagedTunIface]; e.Verdict != "other" || e.VPN != "" {
		t.Errorf("unmanaged tunnel flow = %+v, want other with no client", e)
	}
	if e := got["en0"]; e.Verdict != "direct" || e.VPN != "" || e.Proto != "udp" {
		t.Errorf("physical interface flow = %+v, want direct", e)
	}
}

func TestFlowsCarryTheNameTheirAddressWasResolvedFrom(t *testing.T) {
	env := newHistoryEnv(t)
	env.answers.set("wg.example.com", "10.100.0.1")
	env.connectWG()
	waitForRoutes(t, env.d, wgIface, "10.100.0.1")

	// Exact-domain resolution in sync named this address.
	env.d.onFlow(flowOn(wgIface, "10.100.0.1", 443, dnswatch.ProtoTCP))
	// A captured DNS answer names another, with the most recent name winning.
	env.d.onDNSAnswer(dnswatch.Answer{Name: "first.example.com", Addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}, TTL: time.Minute})
	env.d.onDNSAnswer(dnswatch.Answer{Name: "second.example.com", Addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}, TTL: time.Minute})
	env.d.onFlow(flowOn("en0", "93.184.216.34", 443, dnswatch.ProtoTCP))
	// A wildcard forwarder answer names a third.
	env.d.names.Add("x.wild.example.com", []netip.Addr{netip.MustParseAddr("203.0.113.7")}, 0)
	env.d.onFlow(flowOn("en0", "203.0.113.7", 443, dnswatch.ProtoTCP))
	env.d.onFlow(flowOn("en0", "198.51.100.1", 443, dnswatch.ProtoTCP)) // never resolved

	names := map[string]string{}
	for _, e := range accessEntries(t, env.d) {
		names[e.IP] = e.Name
	}
	want := map[string]string{
		"10.100.0.1":    "wg.example.com",
		"93.184.216.34": "second.example.com",
		"203.0.113.7":   "x.wild.example.com",
		"198.51.100.1":  "",
	}
	for ip, name := range want {
		if got, ok := names[ip]; !ok || got != name {
			t.Errorf("%s named %q (recorded %v), want %q", ip, got, ok, name)
		}
	}
}

func TestWildcardForwarderAnswersFeedTheNameMap(t *testing.T) {
	env := newHistoryEnv(t)
	// No session owns the name, so nothing is routed, but it is still named.
	env.d.onWildcardAnswer("a.unowned.example.com", []netip.Addr{netip.MustParseAddr("203.0.113.9")}, time.Minute)
	if name, ok := env.d.names.Lookup(netip.MustParseAddr("203.0.113.9")); !ok || name != "a.unowned.example.com" {
		t.Fatalf("name = %q %v, want the wildcard answer remembered", name, ok)
	}
}

func TestDisablingHistoryStopsRecordingAndEnablingResumes(t *testing.T) {
	env := newHistoryEnv(t)
	off, on := false, true

	env.d.onFlow(flowOn("en0", "1.1.1.1", 443, dnswatch.ProtoTCP))
	if err := env.d.SetHistory(&off, nil); err != nil {
		t.Fatal(err)
	}
	env.d.onFlow(flowOn("en0", "2.2.2.2", 443, dnswatch.ProtoTCP))
	if err := env.d.SetHistory(&on, nil); err != nil {
		t.Fatal(err)
	}
	env.d.onFlow(flowOn("en0", "3.3.3.3", 443, dnswatch.ProtoTCP))

	var ips []string
	for _, e := range accessEntries(t, env.d) {
		ips = append(ips, e.IP)
	}
	if len(ips) != 2 || ips[0] != "3.3.3.3" || ips[1] != "1.1.1.1" {
		t.Fatalf("recorded %v, want 3.3.3.3 and 1.1.1.1 but nothing while disabled", ips)
	}
}

func TestHistorySettingsAreReportedPersistedAndValidated(t *testing.T) {
	env := newHistoryEnv(t)
	off, days := false, 30
	if err := env.d.SetHistory(&off, &days); err != nil {
		t.Fatal(err)
	}
	if s := env.d.Settings(); s.HistoryEnabled || s.HistoryRetentionDays != 30 {
		t.Fatalf("Settings = %+v", s)
	}
	cfg, _ := env.d.store.Snapshot()
	if cfg.History.Enabled || cfg.History.RetentionDays != 30 {
		t.Fatalf("stored = %+v, want the change persisted", cfg.History)
	}

	revision := env.d.store.Revision()
	for _, bad := range []int{0, -1, 91} {
		bad := bad
		err := env.d.SetHistory(nil, &bad)
		if !errors.Is(err, api.ErrRejected) {
			t.Errorf("retention %d: err = %v, want a rejection", bad, err)
		}
	}
	if s := env.d.Settings(); s.HistoryRetentionDays != 30 {
		t.Errorf("a rejected value changed the live retention to %d", s.HistoryRetentionDays)
	}
	// A request that changes nothing must not invalidate a client's pending
	// conditional domains.set.
	if err := env.d.SetHistory(&off, &days); err != nil {
		t.Fatal(err)
	}
	if env.d.store.Revision() != revision {
		t.Error("a no-op history change must not bump the config revision")
	}
}

func TestShorteningTheRetentionPurgesAtOnce(t *testing.T) {
	env := newHistoryEnv(t)
	old := flowOn("en0", "1.1.1.1", 443, dnswatch.ProtoTCP)
	old.Time = time.Now().Add(-5 * 24 * time.Hour)
	env.d.onFlow(old)
	env.d.onFlow(flowOn("en0", "2.2.2.2", 443, dnswatch.ProtoTCP))
	if got := len(accessEntries(t, env.d)); got != 2 {
		t.Fatalf("entries = %d, want 2 within the default 7 days", got)
	}

	one := 1
	if err := env.d.SetHistory(nil, &one); err != nil {
		t.Fatal(err)
	}
	entries := accessEntries(t, env.d)
	if len(entries) != 1 || entries[0].IP != "2.2.2.2" {
		t.Fatalf("entries = %+v, want only today's after retention 1", entries)
	}
}

func TestImportedHistorySettingsApplyLive(t *testing.T) {
	env := newHistoryEnv(t)
	cfg, _ := env.d.store.Snapshot()
	export := config.NewExport(cfg, time.Now())
	export.History = &config.ExportHistory{Enabled: false, RetentionDays: 21}
	if _, err := env.d.ImportConfig(export); err != nil {
		t.Fatal(err)
	}
	if s := env.d.Settings(); s.HistoryEnabled || s.HistoryRetentionDays != 21 {
		t.Fatalf("Settings = %+v, want the imported history settings in effect", s)
	}
	env.d.onFlow(flowOn("en0", "1.1.1.1", 443, dnswatch.ProtoTCP))
	if got := len(accessEntries(t, env.d)); got != 0 {
		t.Fatalf("entries = %d, want none: the import disabled history", got)
	}
}

func TestAccessListFollowsAndClearEmptiesTheHistory(t *testing.T) {
	env := newHistoryEnv(t)
	env.d.onFlow(flowOn("en0", "1.1.1.1", 443, dnswatch.ProtoTCP))
	entries := accessEntries(t, env.d)
	after := entries[0].ID

	got := make(chan api.AccessListResult, 1)
	go func() {
		res, _ := env.d.AccessList(api.AccessListParams{AfterID: &after, WaitMs: 10000})
		got <- res
	}()
	time.Sleep(100 * time.Millisecond)
	env.d.onFlow(flowOn("en0", "2.2.2.2", 80, dnswatch.ProtoTCP))
	select {
	case res := <-got:
		if len(res.Entries) != 1 || res.Entries[0].IP != "2.2.2.2" || res.LatestID != res.Entries[0].ID {
			t.Fatalf("result = %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the long-poll never woke")
	}

	n, err := env.d.AccessClear()
	if err != nil || n != 2 {
		t.Fatalf("cleared %d (%v), want 2", n, err)
	}
	if got := len(accessEntries(t, env.d)); got != 0 {
		t.Fatalf("entries after clear = %d", got)
	}
}

func TestAccessListRejectsABadVerdict(t *testing.T) {
	env := newHistoryEnv(t)
	if _, err := env.d.AccessList(api.AccessListParams{Verdict: "maybe"}); !errors.Is(err, api.ErrRejected) {
		t.Fatalf("err = %v, want a rejection the RPC layer answers as invalid params", err)
	}
}

func TestWithoutAHistoryStoreTheListIsEmptyAndAFollowerStillWaits(t *testing.T) {
	d, _, _, _ := newDNSTestDaemonWith(t, nil, "api.rw-test.invalid")
	if d.history != nil {
		t.Fatal("this daemon never opened a history store")
	}
	res, err := d.AccessList(api.AccessListParams{})
	if err != nil || len(res.Entries) != 0 || res.Entries == nil {
		t.Fatalf("result = %+v (%v), want an empty list", res, err)
	}
	if n, err := d.AccessClear(); err != nil || n != 0 {
		t.Fatalf("clear = %d (%v)", n, err)
	}

	after := int64(0)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	d.baseCtx = ctx
	start := time.Now()
	if _, err := d.AccessList(api.AccessListParams{AfterID: &after, WaitMs: 10000}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Fatal("a follower must wait rather than spin when there is no store")
	}
	d.onFlow(flowOn("en0", "1.1.1.1", 443, dnswatch.ProtoTCP)) // no store: must not panic
}

func TestAnUnopenableHistoryNeverStopsTheHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows will not delete the directory of an open database, which is how this test makes it unopenable")
	}
	d, _, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		// The database's directory is gone, so a second handle cannot open it.
		dir := t.TempDir()
		db := openSharedDB(t, filepath.Join(dir, configdb.FileName))
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		d.OpenHistory(db)
	}, "api.rw-test.invalid")
	if d.history != nil || d.activityStore != nil || !d.IsRunning() {
		t.Fatal("the helper must run without history when it cannot be opened")
	}
}

func TestStopFlushesTheQueuedHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), configdb.FileName)
	env := newTunnelEnv(t, nil, []string{"wg.example.com"}, nil, func(d *Daemon) { d.OpenHistory(openSharedDB(t, path)) })
	on := true
	if err := env.d.SetHistory(&on, nil); err != nil {
		t.Fatal(err)
	}
	env.d.onFlow(flowOn("en0", "1.1.1.1", 443, dnswatch.ProtoTCP))
	env.d.Stop()

	logDB, err := openSharedDB(t, path).LogDB()
	if err != nil {
		t.Fatal(err)
	}
	store, err := history.Open(logDB, 7, env.d.logger)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	res, err := store.List(context.Background(), history.Query{})
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("after stop: %+v (%v), want the queued record written", res, err)
	}
}

// openRawSQLite opens a plain SQLite file, for building a database in an older
// build's format.
func openRawSQLite(t testing.TB, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
