package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/configdb"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// openStore opens a store over a fresh shared database and returns the
// database's path.
func openStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), configdb.FileName)
	return reopen(t, path, 7), path
}

// reopen opens a store over the shared database at path, as a restarted helper
// would. Everything it opens closes with the test.
func reopen(t *testing.T, path string, retentionDays int) *Store {
	t.Helper()
	cdb, err := configdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cdb.Close() })
	logDB, err := cdb.LogDB()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(logDB, retentionDays, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func entry(ts time.Time, name, ip, verdict string) Entry {
	return Entry{Time: ts, Name: name, IP: ip, Port: 443, Proto: "tcp", Interface: "en0", Verdict: verdict}
}

func ptr[T any](v T) *T { return &v }

func list(t *testing.T, s *Store, q Query) Result {
	t.Helper()
	res, err := s.List(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ids(r Result) []int64 {
	out := make([]int64, len(r.Entries))
	for i, e := range r.Entries {
		out[i] = e.ID
	}
	return out
}

func TestStoreRoundTripsEntries(t *testing.T) {
	s, _ := openStore(t)

	at := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	s.Record(Entry{Time: at, Name: "jira.corp.example.com", IP: "10.20.30.40", Port: 8443, Proto: "tcp",
		Interface: "utun4", VPN: "WireGuard", Verdict: VerdictVPN})
	s.Record(entry(at, "", "93.184.216.34", VerdictDirect))
	s.Flush()

	res := list(t, s, Query{})
	if len(res.Entries) != 2 {
		t.Fatalf("entries = %+v", res.Entries)
	}
	direct, vpn := res.Entries[0], res.Entries[1] // newest first
	if vpn.Name != "jira.corp.example.com" || vpn.VPN != "WireGuard" || vpn.Port != 8443 || vpn.Interface != "utun4" ||
		vpn.Verdict != VerdictVPN || !vpn.Time.Equal(at) {
		t.Errorf("vpn entry = %+v", vpn)
	}
	if direct.Name != "" || direct.VPN != "" || direct.IP != "93.184.216.34" {
		t.Errorf("direct entry = %+v, want no name and no vpn", direct)
	}
	if res.LatestID != direct.ID {
		t.Errorf("latestId = %d, want %d", res.LatestID, direct.ID)
	}
}

func TestStoreListFilters(t *testing.T) {
	s, _ := openStore(t)
	base := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	s.Record(entry(base, "a.example.com", "1.1.1.1", VerdictDirect))                        // 1
	s.Record(entry(base.Add(10*time.Minute), "b.corp.example.com", "10.0.0.5", VerdictVPN)) // 2
	s.Record(entry(base.Add(20*time.Minute), "", "10.0.0.6", VerdictVPN))                   // 3
	s.Record(entry(base.Add(30*time.Minute), "c_d.example.com", "2.2.2.2", VerdictOther))   // 4
	s.Flush()

	cases := []struct {
		name string
		q    Query
		want []int64
	}{
		{"newest first", Query{}, []int64{4, 3, 2, 1}},
		{"limit", Query{Limit: 2}, []int64{4, 3}},
		{"after id is oldest first", Query{AfterID: ptr(int64(1))}, []int64{2, 3, 4}},
		{"after id with limit", Query{AfterID: ptr(int64(1)), Limit: 2}, []int64{2, 3}},
		{"after zero", Query{AfterID: ptr(int64(0))}, []int64{1, 2, 3, 4}},
		{"since", Query{SinceMs: base.Add(15 * time.Minute).UnixMilli()}, []int64{4, 3}},
		{"until", Query{UntilMs: base.Add(15 * time.Minute).UnixMilli()}, []int64{2, 1}},
		{"since and until", Query{SinceMs: base.Add(5 * time.Minute).UnixMilli(), UntilMs: base.Add(25 * time.Minute).UnixMilli()}, []int64{3, 2}},
		{"search name", Query{Search: "corp"}, []int64{2}},
		{"search ip", Query{Search: "10.0.0."}, []int64{3, 2}},
		{"search is case-insensitive", Query{Search: "A.EXAMPLE"}, []int64{1}},
		{"search escapes underscore", Query{Search: "c_d"}, []int64{4}},
		{"underscore is not a wildcard", Query{Search: "c_x"}, nil},
		{"percent is not a wildcard", Query{Search: "%"}, nil},
		{"verdict", Query{Verdict: VerdictVPN}, []int64{3, 2}},
		{"verdict other", Query{Verdict: VerdictOther}, []int64{4}},
		{"verdict with search", Query{Verdict: VerdictVPN, Search: "corp"}, []int64{2}},
	}
	for _, c := range cases {
		if got := ids(list(t, s, c.q)); fmt.Sprint(got) != fmt.Sprint(append([]int64{}, c.want...)) {
			t.Errorf("%s: ids = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStoreLimitDefaultsAndMaximum(t *testing.T) {
	q, _, err := Query{}.normalize()
	if err != nil || q.Limit != DefaultLimit {
		t.Fatalf("default limit = %d (%v), want %d", q.Limit, err, DefaultLimit)
	}
	if q, _, _ = (Query{Limit: 1_000_000}).normalize(); q.Limit != MaxLimit {
		t.Errorf("limit = %d, want it capped at %d", q.Limit, MaxLimit)
	}
	if q, _, _ = (Query{Limit: -3}).normalize(); q.Limit != DefaultLimit {
		t.Errorf("negative limit = %d, want the default", q.Limit)
	}
	if _, _, err := (Query{Verdict: "maybe"}).normalize(); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("err = %v, want ErrInvalidQuery", err)
	}
}

func TestStoreWaitOnlyAppliesWithAfterID(t *testing.T) {
	if _, wait, _ := (Query{WaitMs: 5000}).normalize(); wait != 0 {
		t.Errorf("wait without afterId = %v, want none", wait)
	}
	if _, wait, _ := (Query{AfterID: ptr(int64(1)), WaitMs: 999999}).normalize(); wait != MaxWait {
		t.Errorf("wait = %v, want it capped at %v", wait, MaxWait)
	}
}

func TestStoreLongPollWakesWhenARowArrives(t *testing.T) {
	s, _ := openStore(t)
	s.Record(entry(time.Now(), "old.example.com", "1.1.1.1", VerdictDirect))
	s.Flush()
	latest := list(t, s, Query{}).LatestID

	got := make(chan Result, 1)
	go func() {
		res, _ := s.List(context.Background(), Query{AfterID: &latest, WaitMs: 10000})
		got <- res
	}()
	select {
	case <-got:
		t.Fatal("the long-poll returned before anything new arrived")
	case <-time.After(150 * time.Millisecond):
	}

	s.Record(entry(time.Now(), "new.example.com", "2.2.2.2", VerdictVPN))
	select {
	case res := <-got:
		if len(res.Entries) != 1 || res.Entries[0].Name != "new.example.com" || res.LatestID != res.Entries[0].ID {
			t.Fatalf("result = %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the long-poll never woke (the writer flushes every second)")
	}
}

func TestStoreLongPollRunsOutOfTime(t *testing.T) {
	s, _ := openStore(t)
	after := int64(0)
	start := time.Now()
	res, err := s.List(context.Background(), Query{AfterID: &after, WaitMs: 200})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 180*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("waited %v, want about 200ms", elapsed)
	}
	if len(res.Entries) != 0 || res.Entries == nil {
		t.Errorf("entries = %#v, want an empty (non-nil) list", res.Entries)
	}
}

func TestStoreLongPollStopsWithItsContext(t *testing.T) {
	s, _ := openStore(t)
	after := int64(0)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := s.List(ctx, Query{AfterID: &after, WaitMs: 20000}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("a cancelled context must end the wait")
	}
}

func TestStoreLongPollIgnoresRowsThatDoNotMatchItsFilter(t *testing.T) {
	s, _ := openStore(t)
	after := int64(0)
	got := make(chan Result, 1)
	go func() {
		res, _ := s.List(context.Background(), Query{AfterID: &after, Verdict: VerdictVPN, WaitMs: 10000})
		got <- res
	}()
	time.Sleep(100 * time.Millisecond)
	s.Record(entry(time.Now(), "direct.example.com", "1.1.1.1", VerdictDirect))
	s.Flush()
	select {
	case res := <-got:
		t.Fatalf("returned for a row the filter excludes: %+v", res)
	case <-time.After(200 * time.Millisecond):
	}
	s.Record(entry(time.Now(), "vpn.example.com", "10.0.0.1", VerdictVPN))
	select {
	case res := <-got:
		if len(res.Entries) != 1 || res.Entries[0].Name != "vpn.example.com" {
			t.Fatalf("result = %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("never woke for the matching row")
	}
}

func TestStoreFollowingNeverSkipsATruncatedPage(t *testing.T) {
	s, _ := openStore(t)
	for i := range 5 {
		s.Record(entry(time.Now(), fmt.Sprintf("h%d.example.com", i), "1.1.1.1", VerdictDirect))
	}
	s.Flush()

	after := int64(0)
	var seen []int64
	for range 5 {
		res := list(t, s, Query{AfterID: &after, Limit: 2})
		if len(res.Entries) == 0 {
			break
		}
		seen = append(seen, ids(res)...)
		after = res.LatestID
	}
	if fmt.Sprint(seen) != "[1 2 3 4 5]" {
		t.Fatalf("followed ids = %v, want 1..5 with no gap or repeat", seen)
	}
}

func TestStoreAnswersAClientAheadOfTheDatabaseAtOnce(t *testing.T) {
	s, _ := openStore(t)
	ahead := int64(900)
	start := time.Now()
	res := list(t, s, Query{AfterID: &ahead, WaitMs: 10000})
	if time.Since(start) > 2*time.Second || res.LatestID != 0 {
		t.Fatalf("waited %v, latestId %d: a client ahead of the database must resynchronize at once", time.Since(start), res.LatestID)
	}
}

func TestStoreClearDeletesEverythingIncludingQueuedRows(t *testing.T) {
	s, _ := openStore(t)
	for range 3 {
		s.Record(entry(time.Now(), "a.example.com", "1.1.1.1", VerdictDirect))
	}
	s.Flush()
	s.Record(entry(time.Now(), "queued.example.com", "1.1.1.1", VerdictDirect)) // not yet flushed

	n, err := s.Clear()
	if err != nil || n != 4 {
		t.Fatalf("deleted %d (%v), want 4", n, err)
	}
	if res := list(t, s, Query{}); len(res.Entries) != 0 {
		t.Fatalf("entries after clear = %+v", res.Entries)
	}

	// Ids keep rising, so a client following by id never sees a reused one.
	s.Record(entry(time.Now(), "after.example.com", "1.1.1.1", VerdictDirect))
	s.Flush()
	if res := list(t, s, Query{}); len(res.Entries) != 1 || res.Entries[0].ID <= 4 {
		t.Fatalf("entries after clear = %+v, want an id above 4", res.Entries)
	}
}

func TestStorePurgesByRetention(t *testing.T) {
	s, path := openStore(t)
	now := time.Now()
	s.Record(entry(now.Add(-10*24*time.Hour), "old.example.com", "1.1.1.1", VerdictDirect))
	s.Record(entry(now.Add(-3*24*time.Hour), "mid.example.com", "1.1.1.1", VerdictDirect))
	s.Record(entry(now, "new.example.com", "1.1.1.1", VerdictDirect))
	s.Flush()

	if err := s.Purge(); err != nil {
		t.Fatal(err)
	}
	if got := len(list(t, s, Query{}).Entries); got != 2 {
		t.Fatalf("after a 7-day purge: %d entries, want 2", got)
	}
	if err := s.SetRetention(1); err != nil {
		t.Fatal(err)
	}
	res := list(t, s, Query{})
	if len(res.Entries) != 1 || res.Entries[0].Name != "new.example.com" {
		t.Fatalf("after retention 1: %+v, want only the newest", res.Entries)
	}

	// Opening purges at start too.
	s.Record(entry(now.Add(-5*24*time.Hour), "stale.example.com", "1.1.1.1", VerdictDirect))
	s.Flush()
	s.Close()
	s2 := reopen(t, path, 2)
	if res := list(t, s2, Query{}); len(res.Entries) != 1 {
		t.Fatalf("after reopening with 2 days: %+v, want the stale row purged", res.Entries)
	}
}

func TestStoreFlushesAtBatchSizeWithoutWaiting(t *testing.T) {
	s, _ := openStore(t)
	for range flushBatch {
		s.Record(entry(time.Now(), "a.example.com", "1.1.1.1", VerdictDirect))
	}
	deadline := time.Now().Add(500 * time.Millisecond) // well under the 1 s flush tick
	for time.Now().Before(deadline) {
		if len(list(t, s, Query{Limit: MaxLimit}).Entries) == flushBatch {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("500 queued rows must be written at once, not on the next tick")
}

func TestStoreBatchesWritesOnTheTick(t *testing.T) {
	s, _ := openStore(t)
	s.Record(entry(time.Now(), "a.example.com", "1.1.1.1", VerdictDirect))
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if len(list(t, s, Query{}).Entries) == 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("a queued row must be written within the flush interval")
}

func TestStoreCloseWritesWhatIsQueued(t *testing.T) {
	s, path := openStore(t)
	s.Record(entry(time.Now(), "queued.example.com", "1.1.1.1", VerdictDirect))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s.Record(entry(time.Now(), "after-close.example.com", "1.1.1.1", VerdictDirect)) // must not panic or block

	s2 := reopen(t, path, 7)
	if res := list(t, s2, Query{}); len(res.Entries) != 1 || res.Entries[0].Name != "queued.example.com" {
		t.Fatalf("entries = %+v", res.Entries)
	}
}

func TestStoreSchemaMatchesTheContract(t *testing.T) {
	_, path := openStore(t)
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var cols []string
	rows, err := db.Query(`SELECT name FROM pragma_table_info('access') ORDER BY cid`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var c string
		rows.Scan(&c)
		cols = append(cols, c)
	}
	rows.Close()
	if got := strings.Join(cols, ","); got != "id,ts,name,ip,port,proto,iface,vpn,verdict,list,rule" {
		t.Errorf("columns = %s", got)
	}
	var idx int
	db.QueryRow(`SELECT COUNT(*) FROM pragma_index_list('access') WHERE name = 'access_ts'`).Scan(&idx)
	if idx != 1 {
		t.Error("expected an index on ts")
	}
}

func TestStoreIsSafeForConcurrentUse(t *testing.T) {
	s, _ := openStore(t)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 100 {
				s.Record(entry(time.Now(), fmt.Sprintf("h%d-%d.example.com", i, j), "1.1.1.1", VerdictDirect))
				if j%25 == 0 {
					if _, err := s.List(context.Background(), Query{Limit: 10}); err != nil {
						t.Error(err)
					}
				}
			}
		}()
	}
	wg.Wait()
	s.Flush()
	if got := len(list(t, s, Query{Limit: MaxLimit}).Entries); got != 400 {
		t.Fatalf("entries = %d, want 400", got)
	}
}

func TestStoreRecordsTheMatchedListAndFiltersByIt(t *testing.T) {
	s, _ := openStore(t)
	at := time.Now().Add(-time.Minute)
	withList := func(e Entry, list, rule string) Entry { e.List, e.Rule = &list, rule; return e }
	s.Record(withList(entry(at, "a.corp.example.com", "10.0.0.1", VerdictVPN), "wg", "*.corp.example.com"))
	s.Record(withList(entry(at, "b.example.org", "10.0.0.2", VerdictDirect), "", "b.example.org"))
	s.Record(entry(at, "c.example.net", "10.0.0.3", VerdictDirect))
	s.Flush()

	all := list(t, s, Query{})
	if len(all.Entries) != 3 {
		t.Fatalf("entries = %+v", all.Entries)
	}
	c, b, a := all.Entries[0], all.Entries[1], all.Entries[2]
	if a.List == nil || *a.List != "wg" || a.Rule != "*.corp.example.com" {
		t.Errorf("a = %+v", a)
	}
	if b.List == nil || *b.List != "" || b.Rule != "b.example.org" {
		t.Errorf("b = %+v, want the Any VPN list", b)
	}
	if c.List != nil || c.Rule != "" {
		t.Errorf("c = %+v, want no list", c)
	}

	if got := ids(list(t, s, Query{List: ptr("wg")})); len(got) != 1 || got[0] != a.ID {
		t.Errorf("list wg = %v", got)
	}
	if got := ids(list(t, s, Query{List: ptr("")})); len(got) != 1 || got[0] != b.ID {
		t.Errorf("Any VPN list = %v", got)
	}
}

func TestStoreReadGivesUpWhenTheConnectionStaysBusy(t *testing.T) {
	s, _ := openStore(t)
	s.queryTimeout = 50 * time.Millisecond
	// Hold the only connection, as a long-running read or write would.
	s.db.SetMaxOpenConns(1)
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	start := time.Now()
	_, err = s.List(context.Background(), Query{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("List error = %v, want a deadline error", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("List took %v with a 50ms read bound", elapsed)
	}
}

func TestStoreReadBoundDoesNotShortenTheLongPoll(t *testing.T) {
	s, _ := openStore(t)
	s.queryTimeout = 30 * time.Millisecond
	start := time.Now()
	res, err := s.List(context.Background(), Query{AfterID: ptr(int64(0)), WaitMs: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 0 {
		t.Fatalf("unexpected entries %v", res.Entries)
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Errorf("long poll returned after %v, want it to wait out WaitMs", elapsed)
	}
}

func TestStoreFiltersByExactVPNName(t *testing.T) {
	s, _ := openStore(t)
	at := time.Now().Add(-time.Minute)
	withVPN := func(e Entry, vpn string) Entry { e.VPN = vpn; return e }
	s.Record(withVPN(entry(at, "a.example.com", "10.0.0.1", VerdictVPN), "SG"))
	s.Record(withVPN(entry(at, "b.example.com", "10.0.0.2", VerdictVPN), "SG Backup"))
	s.Record(entry(at, "c.example.com", "10.0.0.3", VerdictDirect))
	s.Flush()

	got := list(t, s, Query{VPN: "SG"}).Entries
	if len(got) != 1 || got[0].Name != "a.example.com" {
		t.Errorf("vpn SG = %+v, want only a.example.com (exact match, not a prefix)", got)
	}
	if got := list(t, s, Query{VPN: "SG", Verdict: VerdictDirect}).Entries; len(got) != 0 {
		t.Errorf("vpn and verdict must combine: %+v", got)
	}
	if got := list(t, s, Query{VPN: "Nope"}).Entries; len(got) != 0 {
		t.Errorf("unknown vpn = %+v", got)
	}
}
