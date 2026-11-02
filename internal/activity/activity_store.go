package activity

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/quocln/routewise/internal/batchwriter"
	"github.com/quocln/routewise/internal/configdb"
)

// Tuning of the writer and of reads.
const (
	flushInterval = time.Second
	flushBatch    = 500
	// queueSize is how many events may wait for the writer; beyond it new
	// events are dropped rather than slowing the route manager.
	queueSize     = 8192
	purgeInterval = time.Hour
	// reclaimPages bounds how much freed space one purge hands back.
	reclaimPages = 5000
	// MaxStoredList caps how many events one read from the database returns,
	// so a client that asks for everything gets the newest page, not the
	// whole retention.
	MaxStoredList = 5000
)

// Store persists activity events in the activity table of the shared database.
// The Log stays the live view; the Store is what lets events, and their
// sequence numbers, survive a restart.
type Store struct {
	// db is the shared file's history handle; the caller owns and closes it.
	db     *sql.DB
	logger *slog.Logger
	now    func() time.Time

	retentionDays atomic.Int64
	writer        *batchwriter.Writer[Event]
}

// OpenStore starts persisting into db, the history handle of the shared
// database (configdb.DB.LogDB). Writes that find the file damaged stop
// recording until the helper restarts.
func OpenStore(db *sql.DB, retentionDays int, logger *slog.Logger) (*Store, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Store{db: db, logger: logger, now: time.Now}
	s.retentionDays.Store(int64(retentionDays))

	if _, err := s.LatestSeq(); err != nil {
		return nil, err
	}
	if err := s.Purge(); err != nil {
		logger.Warn("could not purge old activity", "error", err)
	}
	s.writer = batchwriter.New(batchwriter.Config[Event]{
		Name:          "activity",
		Logger:        logger,
		QueueSize:     queueSize,
		BatchSize:     flushBatch,
		FlushInterval: flushInterval,
		Write:         s.insert,
		Periodic:      s.Purge,
		PeriodicEvery: purgeInterval,
	})
	return s, nil
}

// LatestSeq returns the highest stored sequence number, or 0 when there is none.
// The Log resumes from it, so sequence numbers keep rising across restarts.
func (s *Store) LatestSeq() (uint64, error) {
	var latest int64
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(sequence), 0) FROM activity`).Scan(&latest); err != nil {
		return 0, fmt.Errorf("read activity: %w", err)
	}
	return uint64(latest), nil
}

// Healthy reports whether the writer still records. It is false once a write
// found the database damaged.
func (s *Store) Healthy() bool { return s.writer.Healthy() }

// Record queues an event, already stamped by the Log, for writing. It never
// blocks.
func (s *Store) Record(e Event) { s.writer.Add(e) }

// Close writes what is queued and stops the writer. The database handle stays
// open for its owner to close.
func (s *Store) Close() { s.writer.Close() }

// insert writes events in one transaction. An event whose sequence number is
// somehow already stored is skipped rather than failing the batch.
func (s *Store) insert(batch []Event) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO activity (sequence, time, kind, name, addresses, interface, detail, list, rule, vpn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range batch {
		addresses, err := json.Marshal(append([]Address{}, e.Addresses...))
		if err != nil {
			return err
		}
		// An empty rule or vpn is stored as NULL; a nil list is NULL and "" is
		// the Any VPN list, which is why list is not normalized.
		var list any
		if e.List != nil {
			list = *e.List
		}
		if _, err := stmt.Exec(int64(e.Seq), e.Time.UnixNano(), string(e.Kind), e.Name, string(addresses), e.Interface, e.Detail,
			list, nullIfEmpty(e.Rule), nullIfEmpty(e.VPN)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// List returns, oldest first, the newest events with a sequence number above
// since, after writing what is queued so none is missed. A limit of zero or less,
// or above MaxStoredList, means MaxStoredList; as with Log.List, when more
// events are newer than since the newest limit are returned.
func (s *Store) List(since uint64, limit int) ([]Event, error) {
	if limit <= 0 || limit > MaxStoredList {
		limit = MaxStoredList
	}
	s.writer.Flush()
	rows, err := s.db.Query(`SELECT sequence, time, kind, name, addresses, interface, detail, list, rule, vpn FROM activity
		WHERE sequence > ? ORDER BY sequence DESC LIMIT ?`, int64(since), limit)
	if err != nil {
		return nil, fmt.Errorf("read activity: %w", err)
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var e Event
		var seq, ns int64
		var kind, addresses string
		var list, rule, vpn sql.NullString
		if err := rows.Scan(&seq, &ns, &kind, &e.Name, &addresses, &e.Interface, &e.Detail, &list, &rule, &vpn); err != nil {
			return nil, fmt.Errorf("read activity: %w", err)
		}
		if list.Valid {
			e.List = &list.String
		}
		e.Rule, e.VPN = rule.String, vpn.String
		e.Seq, e.Time, e.Kind = uint64(seq), time.Unix(0, ns).UTC(), Kind(kind)
		if err := json.Unmarshal([]byte(addresses), &e.Addresses); err != nil {
			return nil, fmt.Errorf("read activity %d addresses: %w", seq, err)
		}
		if len(e.Addresses) == 0 {
			e.Addresses = nil
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read activity: %w", err)
	}
	// Newest first came from the query so the limit keeps the newest.
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events, nil
}

// SetRetention changes how many days of activity are kept and purges at once.
func (s *Store) SetRetention(days int) error {
	s.retentionDays.Store(int64(days))
	return s.Purge()
}

// Purge deletes events older than the retention and hands the freed pages back
// to the file system.
func (s *Store) Purge() error {
	cutoff := s.now().Add(-time.Duration(s.retentionDays.Load()) * 24 * time.Hour).UnixNano()
	res, err := s.db.Exec(`DELETE FROM activity WHERE time < ?`, cutoff)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return configdb.ReclaimSpace(s.db, reclaimPages)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
