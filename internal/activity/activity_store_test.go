package activity

import (
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/configdb"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// openActivityStore opens a store over the shared database at path, as a
// restarted helper would; everything it opens closes with the test.
func openActivityStore(t *testing.T, path string, days int) (*Store, *sql.DB) {
	t.Helper()
	cdb, err := configdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cdb.Close() })
	db, err := cdb.LogDB()
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(db, days, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, db
}

func sharedPath(t *testing.T) string { return filepath.Join(t.TempDir(), configdb.FileName) }

func TestStoreKeepsEveryEventField(t *testing.T) {
	s, _ := openActivityStore(t, sharedPath(t), 7)
	at := time.Now().Add(-time.Minute).UTC()
	want := Event{Seq: 41, Time: at, Kind: KindDNS, Name: "jira.corp.example.com",
		Addresses: []Address{{IP: "10.0.0.5", Verdict: ViaVPN}, {IP: "93.184.216.34", Verdict: Direct}},
		Interface: "utun4", Detail: "answered by 10.0.0.2"}
	bare := Event{Seq: 42, Time: at, Kind: KindVPN, Name: "WireGuard", Detail: "connected"}
	s.Record(want)
	s.Record(bare)

	got, err := s.List(0, 0)
	if err != nil || len(got) != 2 {
		t.Fatalf("events = %+v (%v)", got, err)
	}
	if !got[0].Time.Equal(want.Time) || got[0].Seq != 41 || got[0].Kind != want.Kind || got[0].Name != want.Name ||
		got[0].Interface != want.Interface || got[0].Detail != want.Detail || len(got[0].Addresses) != 2 ||
		got[0].Addresses[0] != want.Addresses[0] || got[0].Addresses[1] != want.Addresses[1] {
		t.Errorf("event = %+v, want %+v", got[0], want)
	}
	if got[1].Addresses != nil || got[1].Interface != "" || got[1].Name != "WireGuard" {
		t.Errorf("bare event = %+v, want no addresses and no interface", got[1])
	}
}

func TestStoreListIsOldestFirstWithSinceAndTheNewestLimit(t *testing.T) {
	s, _ := openActivityStore(t, sharedPath(t), 7)
	for i := uint64(1); i <= 5; i++ {
		s.Record(Event{Seq: i, Time: time.Now(), Kind: KindDNS, Name: string(rune('a' + i - 1))})
	}
	cases := []struct {
		since uint64
		limit int
		want  string
	}{
		{0, 0, "abcde"}, {2, 0, "cde"}, {5, 0, ""}, {0, 2, "de"}, {1, 3, "cde"}, {0, 100, "abcde"},
	}
	for _, c := range cases {
		got, err := s.List(c.since, c.limit)
		if err != nil {
			t.Fatal(err)
		}
		var names string
		for _, e := range got {
			names += e.Name
		}
		if names != c.want {
			t.Errorf("List(%d, %d) = %q, want %q", c.since, c.limit, names, c.want)
		}
	}
}

func TestStoreListCapsAnUnboundedRead(t *testing.T) {
	s, db := openActivityStore(t, sharedPath(t), 7)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixNano()
	for i := 1; i <= MaxStoredList+10; i++ {
		if _, err := tx.Exec(`INSERT INTO activity (sequence, time, kind, name, addresses, interface, detail) VALUES (?, ?, 'dns', 'x', '[]', '', '')`, i, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(0, 0)
	if err != nil || len(got) != MaxStoredList || got[len(got)-1].Seq != MaxStoredList+10 {
		t.Fatalf("got %d events (%v), want the newest %d", len(got), err, MaxStoredList)
	}
}

func TestSequenceNumbersKeepRisingAcrossARestart(t *testing.T) {
	path := sharedPath(t)
	s, _ := openActivityStore(t, path, 7)
	l := New(10)
	for range 3 {
		s.Record(l.Add(Event{Kind: KindDNS, Name: "before"}))
	}
	s.Close()

	s2, _ := openActivityStore(t, path, 7)
	latest, err := s2.LatestSeq()
	if err != nil || latest != 3 {
		t.Fatalf("latest = %d (%v), want 3", latest, err)
	}
	l2 := New(10)
	l2.Resume(latest)
	if e := l2.Add(Event{Kind: KindDNS, Name: "after"}); e.Seq != 4 {
		t.Fatalf("seq after restart = %d, want 4", e.Seq)
	}
	if l2.Latest() != 4 {
		t.Errorf("latest = %d", l2.Latest())
	}
	l2.Resume(2) // never lowers
	if l2.Latest() != 4 {
		t.Errorf("Resume lowered the sequence to %d", l2.Latest())
	}
}

func TestStorePurgesByRetention(t *testing.T) {
	path := sharedPath(t)
	s, _ := openActivityStore(t, path, 7)
	now := time.Now()
	s.Record(Event{Seq: 1, Time: now.Add(-10 * 24 * time.Hour), Kind: KindDNS, Name: "old"})
	s.Record(Event{Seq: 2, Time: now.Add(-3 * 24 * time.Hour), Kind: KindDNS, Name: "mid"})
	s.Record(Event{Seq: 3, Time: now, Kind: KindDNS, Name: "new"})
	s.writer.Flush()

	if err := s.Purge(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.List(0, 0); len(got) != 2 || got[0].Name != "mid" {
		t.Fatalf("after a 7-day purge: %+v", got)
	}
	if err := s.SetRetention(1); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.List(0, 0); len(got) != 1 || got[0].Name != "new" {
		t.Fatalf("after retention 1: %+v", got)
	}

	s.Record(Event{Seq: 4, Time: now.Add(-5 * 24 * time.Hour), Kind: KindDNS, Name: "stale"})
	s.Close() // writes the queued event
	s2, _ := openActivityStore(t, path, 2)
	if got, _ := s2.List(0, 0); len(got) != 1 || got[0].Name != "new" {
		t.Fatalf("opening with 2 days must purge the stale event: %+v", got)
	}
}

func TestCloseWritesWhatIsQueued(t *testing.T) {
	path := sharedPath(t)
	s, _ := openActivityStore(t, path, 7)
	s.Record(Event{Seq: 1, Time: time.Now(), Kind: KindVPN, Name: "queued"})
	s.Close()
	s.Record(Event{Seq: 2, Time: time.Now(), Kind: KindVPN, Name: "after-close"}) // must not panic or block

	s2, _ := openActivityStore(t, path, 7)
	if got, _ := s2.List(0, 0); len(got) != 1 || got[0].Name != "queued" {
		t.Fatalf("events = %+v", got)
	}
}

func TestACoveredReadNeedsNoDatabase(t *testing.T) {
	l := New(3)
	if !l.Covers(0) {
		t.Error("an empty log covers a client that is caught up")
	}
	l.Resume(10)
	if l.Covers(0) || !l.Covers(10) {
		t.Error("after Resume, only a client at the resumed sequence is covered")
	}
	for range 2 {
		l.Add(Event{Kind: KindDNS}) // 11, 12
	}
	if !l.Covers(10) || !l.Covers(11) || !l.Covers(12) || l.Covers(9) || l.Covers(0) {
		t.Error("the ring covers from just before its oldest event")
	}
	for range 3 {
		l.Add(Event{Kind: KindDNS}) // 13, 14, 15: the ring now holds 13..15
	}
	if l.Covers(11) || !l.Covers(12) {
		t.Error("a wrapped ring covers from the sequence just before its oldest event")
	}

	fresh := New(5)
	fresh.Add(Event{Kind: KindDNS})
	if !fresh.Covers(0) {
		t.Error("a log that never wrapped and never resumed holds everything")
	}
}

func TestStoreKeepsListRuleAndVPNAndTellsAnyVPNFromNoList(t *testing.T) {
	s, _ := openActivityStore(t, sharedPath(t), 7)
	at := time.Now().Add(-time.Minute).UTC()
	wg, anyVPN := "wg1", ""
	s.Record(Event{Seq: 1, Time: at, Kind: KindDNS, Name: "a.corp", List: &wg, Rule: "*.corp", VPN: "SG"})
	s.Record(Event{Seq: 2, Time: at, Kind: KindDNS, Name: "b.example", List: &anyVPN, Rule: "b.example"})
	s.Record(Event{Seq: 3, Time: at, Kind: KindDNS, Name: "c.example"})

	got, err := s.List(0, 0)
	if err != nil || len(got) != 3 {
		t.Fatalf("events = %+v (%v)", got, err)
	}
	if got[0].List == nil || *got[0].List != "wg1" || got[0].Rule != "*.corp" || got[0].VPN != "SG" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].List == nil || *got[1].List != "" || got[1].Rule != "b.example" || got[1].VPN != "" {
		t.Errorf("second = %+v, want the Any VPN list", got[1])
	}
	if got[2].List != nil || got[2].Rule != "" || got[2].VPN != "" {
		t.Errorf("third = %+v, want no list", got[2])
	}
}
