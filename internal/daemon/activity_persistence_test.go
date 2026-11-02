package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/configdb"
	"github.com/quocln/routewise/internal/history"
)

// historyDaemon starts a daemon over the shared database at path, with history
// enabled or not, and returns it.
func historyDaemon(t *testing.T, path string, enabled bool) *Daemon {
	t.Helper()
	d, _, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.historyOn.Store(enabled)
		d.historyDays.Store(7) // the test config leaves retention at zero, which purges everything
		d.OpenHistory(openSharedDB(t, path))
	}, "api.rw-test.invalid")
	return d
}

func activityNames(events []activity.Event) []string {
	var out []string
	for _, e := range events {
		if e.Kind == activity.KindDNS {
			out = append(out, e.Name)
		}
	}
	return out
}

func storedEvents(t *testing.T, d *Daemon) []activity.Event {
	t.Helper()
	events, err := d.activityStore.List(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestActivityIsPersistedWhileHistoryIsOnAndSequencesSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), configdb.FileName)
	d1 := historyDaemon(t, path, true)
	d1.recordActivity(activity.Event{Kind: activity.KindDNS, Name: "one.example.com", Detail: "kept",
		Addresses: []activity.Address{{IP: "1.1.1.1", Verdict: activity.Direct}}})
	d1.recordActivity(activity.Event{Kind: activity.KindDNS, Name: "two.example.com"})
	latest, _ := d1.Activity(0, 0, 0)
	d1.Stop()

	d2 := historyDaemon(t, path, true)
	d2.recordActivity(activity.Event{Kind: activity.KindDNS, Name: "three.example.com"})
	latest2, events := d2.Activity(0, 0, 0)
	if names := activityNames(events); len(names) != 3 || names[0] != "one.example.com" || names[2] != "three.example.com" {
		t.Fatalf("events after restart = %v, want the earlier two and the new one", names)
	}
	for i := 1; i < len(events); i++ {
		if events[i].Seq <= events[i-1].Seq {
			t.Fatalf("sequences %d then %d: they must keep rising across a restart", events[i-1].Seq, events[i].Seq)
		}
	}
	if latest2 <= latest || latest2 != events[len(events)-1].Seq {
		t.Errorf("latest = %d, earlier run ended at %d", latest2, latest)
	}
	var first activity.Event
	for _, e := range events {
		if e.Name == "one.example.com" {
			first = e
		}
	}
	if first.Detail != "kept" || len(first.Addresses) != 1 || first.Addresses[0].IP != "1.1.1.1" {
		t.Errorf("first = %+v, want every field kept", first)
	}
}

func TestActivityStaysInMemoryAndWritesNothingWhileHistoryIsOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), configdb.FileName)
	d := historyDaemon(t, path, false)
	d.recordActivity(activity.Event{Kind: activity.KindDNS, Name: "private.example.com"})

	if stored := storedEvents(t, d); len(stored) != 0 {
		t.Fatalf("stored %+v while history is off, want nothing written", stored)
	}
	if _, events := d.Activity(0, 0, 0); len(activityNames(events)) != 1 {
		t.Fatalf("events = %+v, want the one in memory", events)
	}

	// Enabling records from then on; the earlier event was never written.
	on := true
	if err := d.SetHistory(&on, nil); err != nil {
		t.Fatal(err)
	}
	d.recordActivity(activity.Event{Kind: activity.KindDNS, Name: "kept.example.com"})
	if names := activityNames(storedEvents(t, d)); len(names) != 1 || names[0] != "kept.example.com" {
		t.Fatalf("stored = %v, want only the event after enabling", names)
	}
	// A client that followed the ring while history was off still sees every
	// event newer than its position.
	if _, events := d.Activity(0, 0, 0); len(activityNames(events)) != 2 {
		t.Fatalf("events = %v, want both", activityNames(events))
	}
}

func TestACatchUpReadComesFromTheDatabaseAndAFollowerFromTheRing(t *testing.T) {
	path := filepath.Join(t.TempDir(), configdb.FileName)
	d1 := historyDaemon(t, path, true)
	for _, n := range []string{"a", "b", "c"} {
		d1.recordActivity(activity.Event{Kind: activity.KindDNS, Name: n})
	}
	d1.Stop()

	d2 := historyDaemon(t, path, true)
	if d2.activity.Covers(0) {
		t.Fatal("a restarted ring does not hold the earlier events")
	}
	latest, events := d2.Activity(0, 0, 0)
	if names := activityNames(events); len(names) != 3 || names[0] != "a" {
		t.Fatalf("catch-up = %v, want the earlier events from the database", names)
	}
	// Following from the latest sequence needs the ring only, and sees new events at once.
	d2.recordActivity(activity.Event{Kind: activity.KindDNS, Name: "d"})
	next, events := d2.Activity(latest, 0, 0)
	if names := activityNames(events); len(names) != 1 || names[0] != "d" || next <= latest {
		t.Fatalf("follow = %v (latest %d -> %d)", names, latest, next)
	}
}

func TestAnActivityLongPollWakesForANewEventWithHistoryOn(t *testing.T) {
	d := historyDaemon(t, filepath.Join(t.TempDir(), configdb.FileName), true)
	latest, _ := d.Activity(0, 0, 0)
	got := make(chan []activity.Event, 1)
	go func() {
		_, events := d.Activity(latest, 0, 10*time.Second)
		got <- events
	}()
	time.Sleep(100 * time.Millisecond)
	d.recordActivity(activity.Event{Kind: activity.KindDNS, Name: "wake.example.com"})
	select {
	case events := <-got:
		if names := activityNames(events); len(names) != 1 || names[0] != "wake.example.com" {
			t.Fatalf("woke with %v", names)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the long-poll did not wake for a new event")
	}
}

func TestRetentionPurgesAccessAndActivityAndClearTouchesAccessOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), configdb.FileName)
	d := historyDaemon(t, path, true)
	old := time.Now().Add(-5 * 24 * time.Hour)
	d.recordActivity(activity.Event{Kind: activity.KindDNS, Name: "old.example.com", Time: old})
	d.recordActivity(activity.Event{Kind: activity.KindDNS, Name: "new.example.com"})
	d.history.Record(history.Entry{Time: old, IP: "1.1.1.1", Port: 443, Proto: "tcp", Interface: "en0", Verdict: history.VerdictDirect})
	d.history.Record(history.Entry{Time: time.Now(), IP: "2.2.2.2", Port: 443, Proto: "tcp", Interface: "en0", Verdict: history.VerdictDirect})
	d.history.Flush()
	if len(activityNames(storedEvents(t, d))) != 2 || len(accessEntries(t, d)) != 2 {
		t.Fatal("setup: both tables must hold two rows")
	}

	days := 2
	if err := d.SetHistory(nil, &days); err != nil {
		t.Fatal(err)
	}
	if names := activityNames(storedEvents(t, d)); len(names) != 1 || names[0] != "new.example.com" {
		t.Errorf("activity after retention 2 = %v", names)
	}
	if entries := accessEntries(t, d); len(entries) != 1 || entries[0].IP != "2.2.2.2" {
		t.Errorf("access after retention 2 = %+v", entries)
	}

	if n, err := d.AccessClear(); err != nil || n != 1 {
		t.Fatalf("clear = %d (%v)", n, err)
	}
	if len(accessEntries(t, d)) != 0 {
		t.Error("access.clear must empty the access history")
	}
	if len(activityNames(storedEvents(t, d))) != 1 {
		t.Error("access.clear must leave the activity log alone")
	}
}

func TestStopWritesTheQueuedActivity(t *testing.T) {
	path := filepath.Join(t.TempDir(), configdb.FileName)
	d := historyDaemon(t, path, true)
	d.recordActivity(activity.Event{Kind: activity.KindDNS, Name: "queued.example.com"})
	d.Stop()

	logDB, err := openSharedDB(t, path).LogDB()
	if err != nil {
		t.Fatal(err)
	}
	store, err := activity.OpenStore(logDB, 7, d.logger)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	events, err := store.List(0, 0)
	found := false
	for _, e := range events {
		found = found || e.Name == "queued.example.com"
	}
	if err != nil || !found {
		t.Fatalf("after stop: %+v (%v), want the queued event written", events, err)
	}
}

// writeLegacyHistory makes a history.db in the format older builds wrote.
func writeLegacyHistory(t *testing.T, path string) {
	t.Helper()
	raw, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	raw.Close()
	db := openRawSQLite(t, path)
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE access (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, name TEXT,
		ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL, iface TEXT NOT NULL, vpn TEXT, verdict TEXT NOT NULL,
		list TEXT, rule TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO access (ts, name, ip, port, proto, iface, vpn, verdict) VALUES (?, 'legacy.example.com', '8.8.8.8', 443, 'tcp', 'en0', NULL, 'direct')`,
		time.Now().Add(-time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
}

func TestOpeningHistoryMovesALegacyHistoryDatabaseIntoTheSharedFile(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, history.LegacyFileName)
	writeLegacyHistory(t, legacy)

	d := historyDaemon(t, filepath.Join(dir, configdb.FileName), false)
	entries := accessEntries(t, d)
	if len(entries) != 1 || entries[0].Name != "legacy.example.com" || entries[0].List != nil {
		t.Fatalf("access entries = %+v, want the legacy row", entries)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Error("history.db must be set aside")
	}
	if _, err := os.Stat(legacy + ".migrated"); err != nil {
		t.Errorf("history.db.migrated is missing: %v", err)
	}
}

func TestAnUnreadableLegacyHistoryNeverStopsTheHelperOrIsDiscarded(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, history.LegacyFileName)
	if err := os.WriteFile(legacy, []byte("not a database, just text where history.db should be"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := historyDaemon(t, filepath.Join(dir, configdb.FileName), true)
	if d.history == nil || !d.IsRunning() {
		t.Fatal("the helper must run, with history, when the legacy file cannot be imported")
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Errorf("an unreadable history.db must stay in place for the next start: %v", err)
	}
}

func TestAppPreferencesAreStoredPerUIDThroughTheDaemon(t *testing.T) {
	d := historyDaemon(t, filepath.Join(t.TempDir(), configdb.FileName), false)
	if _, err := d.Prefs(501); !errors.Is(err, errNoPrefStore) {
		t.Fatalf("Prefs without a store: %v", err)
	}
	d.SetPrefStore(openSharedDB(t, filepath.Join(t.TempDir(), configdb.FileName)))

	if err := d.SetPref(501, "launchAtLogin", json.RawMessage(`true`)); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPref(0, "launchAtLogin", json.RawMessage(`false`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.Prefs(501); string(got["launchAtLogin"]) != "true" || len(got) != 1 {
		t.Errorf("uid 501 prefs = %v", got)
	}
	if got, _ := d.Prefs(0); string(got["launchAtLogin"]) != "false" {
		t.Errorf("uid 0 prefs = %v", got)
	}
	for _, bad := range []struct {
		key   string
		value json.RawMessage
	}{{"1bad", json.RawMessage(`1`)}, {"k", json.RawMessage(`{broken`)}} {
		if err := d.SetPref(501, bad.key, bad.value); !errors.Is(err, api.ErrRejected) {
			t.Errorf("SetPref(%q, %s) = %v, want a rejection the RPC layer answers as invalid params", bad.key, bad.value, err)
		}
	}
	if err := d.SetPref(501, "launchAtLogin", json.RawMessage(`null`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.Prefs(501); len(got) != 0 {
		t.Errorf("after delete: %v", got)
	}
}
