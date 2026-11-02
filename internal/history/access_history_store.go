// Package history stores the access history: one row per outbound connection
// start, in the access table of the shared RouteWise database (see configdb,
// which owns the schema and the file).
package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quocln/routewise/internal/batchwriter"
	"github.com/quocln/routewise/internal/configdb"
)

// Tuning of the writer and of list queries.
const (
	flushInterval = time.Second
	flushBatch    = 500
	// queueSize is how many records may wait for the writer; beyond it new
	// records are dropped rather than slowing packet capture.
	queueSize     = 8192
	purgeInterval = time.Hour
	// reclaimPages bounds how much freed space one purge hands back, so it never
	// holds the write lock for long.
	reclaimPages = 5000

	DefaultLimit = 500
	MaxLimit     = 5000
	// MaxWait bounds a long-poll so it always answers well inside the
	// socket's 30 s read deadline.
	MaxWait = 20 * time.Second
)

// Verdicts an access record can carry.
const (
	VerdictVPN    = "vpn"
	VerdictDirect = "direct"
	VerdictOther  = "other"
)

// Entry is one recorded connection start. Its JSON form is the access.list
// wire format.
type Entry struct {
	ID        int64     `json:"id"`
	Time      time.Time `json:"time"`
	Name      string    `json:"name,omitempty"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`
	Interface string    `json:"interface"`
	VPN       string    `json:"vpn,omitempty"`
	Verdict   string    `json:"verdict"`
	// List is the client id of the domain list whose entry the connection
	// matched when it started: "" is the Any VPN list, nil is no list.
	List *string `json:"list,omitempty"`
	// Rule is the list entry it matched: a domain, a wildcard, an IP or a CIDR.
	Rule string `json:"rule,omitempty"`
}

// Query selects entries; its JSON form is the access.list parameter set.
type Query struct {
	// AfterID returns only entries with a larger id, oldest first. A nil
	// value lists newest first.
	AfterID *int64 `json:"afterId,omitempty"`
	SinceMs int64  `json:"sinceMs,omitempty"`
	UntilMs int64  `json:"untilMs,omitempty"`
	// Search matches a substring of the name or the IP.
	Search  string `json:"search,omitempty"`
	Verdict string `json:"verdict,omitempty"`
	// List keeps only connections that matched this list: a client id, or
	// "" for the Any VPN list. Nil applies no filter.
	List *string `json:"list,omitempty"`
	// VPN keeps only connections that left through the managed tunnel with
	// this exact client name. Empty applies no filter.
	VPN string `json:"vpn,omitempty"`
	// Limit caps the entries returned: 500 by default, at most 5000.
	Limit int `json:"limit,omitempty"`
	// WaitMs holds an AfterID query until a matching entry exists or this
	// many milliseconds pass (at most 20000).
	WaitMs int `json:"waitMs,omitempty"`
}

// Result is the answer to a Query.
type Result struct {
	Entries []Entry `json:"entries"`
	// LatestID is the id to pass as AfterID next time to continue without a
	// gap or a repeat.
	LatestID int64 `json:"latestId"`
}

// ErrInvalidQuery marks a Query the caller must correct.
var ErrInvalidQuery = errors.New("invalid history query")

// normalize checks q and applies defaults and bounds.
func (q Query) normalize() (Query, time.Duration, error) {
	switch q.Verdict {
	case "", VerdictVPN, VerdictDirect, VerdictOther:
	default:
		return q, 0, fmt.Errorf("%w: verdict must be vpn, direct or other, got %q", ErrInvalidQuery, q.Verdict)
	}
	if q.Limit <= 0 {
		q.Limit = DefaultLimit
	}
	q.Limit = min(q.Limit, MaxLimit)
	var wait time.Duration
	if q.AfterID != nil && q.WaitMs > 0 {
		wait = min(time.Duration(q.WaitMs)*time.Millisecond, MaxWait)
	}
	return q, wait, nil
}

// Store records access entries in the shared database. Records are queued and
// written in batches by one goroutine; reads go straight to the database. Its
// locks are leaves: nothing is called out to while holding them.
type Store struct {
	// db is the shared file's history handle; the caller owns and closes it.
	db     *sql.DB
	logger *slog.Logger
	now    func() time.Time
	// queryTimeout bounds one read, so a text search that scans the table
	// cannot pile up connections behind it.
	queryTimeout time.Duration

	retentionDays atomic.Int64
	closed        atomic.Bool
	stop          chan struct{}
	writer        *batchwriter.Writer[Entry]

	// notifyMu guards notify, closed and replaced whenever rows are written.
	notifyMu sync.Mutex
	notify   chan struct{}
}

// Open starts recording into the access table of db, the history handle of the
// shared database (configdb.DB.LogDB). Writes that find the file damaged stop
// recording until the helper restarts; the file itself is never rebuilt here.
func Open(db *sql.DB, retentionDays int, logger *slog.Logger) (*Store, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Store{
		db:           db,
		logger:       logger,
		now:          time.Now,
		queryTimeout: defaultQueryTimeout,
		stop:         make(chan struct{}),
		notify:       make(chan struct{}),
	}
	s.retentionDays.Store(int64(retentionDays))

	var latest int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM access`).Scan(&latest); err != nil {
		return nil, fmt.Errorf("read access history: %w", err)
	}
	if err := s.Purge(); err != nil {
		logger.Warn("could not purge old history", "error", err)
	}
	s.writer = batchwriter.New(batchwriter.Config[Entry]{
		Name:          "access history",
		Logger:        logger,
		QueueSize:     queueSize,
		BatchSize:     flushBatch,
		FlushInterval: flushInterval,
		Write:         s.insert,
		Written:       s.broadcast,
		Periodic:      s.Purge,
		PeriodicEvery: purgeInterval,
	})
	return s, nil
}

// Healthy reports whether the writer still records. It is false once a write
// found the database damaged.
func (s *Store) Healthy() bool { return s.writer.Healthy() }

// Dropped counts the records a full queue turned away.
func (s *Store) Dropped() uint64 { return s.writer.Dropped() }

// Record queues an entry for writing. It never blocks: a full queue drops the
// entry, so a burst of connections cannot slow packet capture.
func (s *Store) Record(e Entry) { s.writer.Add(e) }

// Flush writes every queued entry and returns once they are committed.
func (s *Store) Flush() { s.writer.Flush() }

// Close writes what is queued and stops the writer. The database handle stays
// open for its owner to close.
func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(s.stop)
	s.writer.Close()
	s.broadcast() // release long-polls
	return nil
}

// insert writes entries in one transaction.
func (s *Store) insert(batch []Entry) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	stmt, err := tx.Prepare(`INSERT INTO access (ts, name, ip, port, proto, iface, vpn, verdict, list, rule) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range batch {
		if _, err := stmt.Exec(e.Time.UnixMilli(), nullable(e.Name), e.IP, e.Port, e.Proto, e.Interface, nullable(e.VPN), e.Verdict, nullableList(e.List), nullable(e.Rule)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableList stores a nil list as NULL and the Any VPN list as ”.
func nullableList(list *string) any {
	if list == nil {
		return nil
	}
	return *list
}

// notifyChan returns a channel closed by the next write.
func (s *Store) notifyChan() <-chan struct{} {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	return s.notify
}

func (s *Store) broadcast() {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	close(s.notify)
	s.notify = make(chan struct{})
}

// SetRetention changes how many days of history are kept and purges at once.
func (s *Store) SetRetention(days int) error {
	s.retentionDays.Store(int64(days))
	return s.Purge()
}

// Purge deletes entries older than the retention and hands the freed pages
// back to the file system.
func (s *Store) Purge() error {
	cutoff := s.now().Add(-time.Duration(s.retentionDays.Load()) * 24 * time.Hour).UnixMilli()
	res, err := s.db.Exec(`DELETE FROM access WHERE ts < ?`, cutoff)
	if err != nil {
		return err
	}
	return s.reclaim(res)
}

// reclaim shrinks the file after a delete that removed rows.
func (s *Store) reclaim(res sql.Result) error {
	if n, _ := res.RowsAffected(); n > 0 {
		return configdb.ReclaimSpace(s.db, reclaimPages)
	}
	return nil
}

// Clear deletes every entry, including those still queued, and returns how
// many were stored. Ids keep increasing afterwards.
func (s *Store) Clear() (int64, error) {
	s.Flush()
	res, err := s.db.Exec(`DELETE FROM access`)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := s.reclaim(res); err != nil {
		s.logger.Warn("could not shrink the database after clearing access history", "error", err)
	}
	return n, nil
}

// List answers q. With AfterID and WaitMs it holds until a matching entry
// exists, the wait ends, or ctx is done; an empty result then is not an error.
func (s *Store) List(ctx context.Context, q Query) (Result, error) {
	q, wait, err := q.normalize()
	if err != nil {
		return Result{}, err
	}
	var timeout <-chan time.Time
	for {
		// Take the channel before reading so a write between the read and
		// the wait is not missed.
		wake := s.notifyChan()
		res, err := s.query(ctx, q)
		if err != nil || len(res.Entries) > 0 || wait <= 0 {
			return res, err
		}
		if *q.AfterID > res.LatestID {
			// The client is ahead of this database (it was restored from a
			// backup, which holds no history): answer now so it
			// resynchronizes from LatestID.
			return res, nil
		}
		if timeout == nil {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			timeout = timer.C
		}
		select {
		case <-wake:
		case <-timeout:
			return res, nil
		case <-ctx.Done():
			return res, nil
		case <-s.stop:
			return res, nil
		}
	}
}

// defaultQueryTimeout is how long a single read may hold the connection.
const defaultQueryTimeout = 15 * time.Second

// query runs q once, in one read transaction so the entries and LatestID agree.
// The read is cut off after queryTimeout; a long-poll repeats short reads, so
// its wait is not affected.
func (s *Store) query(ctx context.Context, q Query) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, s.queryTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback() //nolint:errcheck // read-only

	var where []string
	var args []any
	if q.AfterID != nil {
		where = append(where, "id > ?")
		args = append(args, *q.AfterID)
	}
	if q.SinceMs > 0 {
		where = append(where, "ts >= ?")
		args = append(args, q.SinceMs)
	}
	if q.UntilMs > 0 {
		where = append(where, "ts <= ?")
		args = append(args, q.UntilMs)
	}
	if q.Search != "" {
		like := "%" + likeEscaper.Replace(q.Search) + "%"
		where = append(where, `(name LIKE ? ESCAPE '\' OR ip LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}
	if q.Verdict != "" {
		where = append(where, "verdict = ?")
		args = append(args, q.Verdict)
	}
	if q.List != nil {
		where = append(where, "list = ?")
		args = append(args, *q.List)
	}
	if q.VPN != "" {
		where = append(where, "vpn = ?")
		args = append(args, q.VPN)
	}
	stmt := `SELECT id, ts, name, ip, port, proto, iface, vpn, verdict, list, rule FROM access`
	if len(where) > 0 {
		stmt += " WHERE " + strings.Join(where, " AND ")
	}
	if q.AfterID != nil {
		stmt += " ORDER BY id ASC"
	} else {
		stmt += " ORDER BY id DESC"
	}
	stmt += " LIMIT ?"
	args = append(args, q.Limit)

	rows, err := tx.QueryContext(ctx, stmt, args...)
	if err != nil {
		return Result{}, err
	}
	entries := []Entry{}
	for rows.Next() {
		var e Entry
		var ts int64
		var name, vpn, list, rule sql.NullString
		if err := rows.Scan(&e.ID, &ts, &name, &e.IP, &e.Port, &e.Proto, &e.Interface, &vpn, &e.Verdict, &list, &rule); err != nil {
			rows.Close()
			return Result{}, err
		}
		e.Time, e.Name, e.VPN, e.Rule = time.UnixMilli(ts).UTC(), name.String, vpn.String, rule.String
		if list.Valid {
			e.List = &list.String
		}
		entries = append(entries, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Result{}, err
	}

	var latest int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM access`).Scan(&latest); err != nil {
		return Result{}, err
	}
	res := Result{Entries: entries, LatestID: latest}
	// A truncated oldest-first page continues after its last entry, so
	// following never skips the entries the limit cut off.
	if q.AfterID != nil && len(entries) == q.Limit {
		res.LatestID = entries[len(entries)-1].ID
	}
	return res, nil
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
