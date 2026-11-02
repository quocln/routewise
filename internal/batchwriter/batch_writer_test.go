package batchwriter

import (
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/configdb"

	_ "modernc.org/sqlite"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// recorder is a Write that remembers its batches.
type recorder struct {
	mu      sync.Mutex
	batches [][]int
	err     error
}

func (r *recorder) write(batch []int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.batches = append(r.batches, append([]int(nil), batch...))
	return nil
}

func (r *recorder) total() (n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.batches {
		n += len(b)
	}
	return n
}

func newWriter(r *recorder, queue, batch int) *Writer[int] {
	return New(Config[int]{Name: "test", Logger: quiet, QueueSize: queue, BatchSize: batch,
		FlushInterval: 20 * time.Millisecond, Write: r.write})
}

func TestWriterBatchesAndFlushOnDemand(t *testing.T) {
	r := &recorder{}
	w := newWriter(r, 100, 1000)
	defer w.Close()
	for i := range 5 {
		w.Add(i)
	}
	w.Flush()
	if r.total() != 5 {
		t.Fatalf("flushed %d, want 5", r.total())
	}
}

func TestWriterWritesAtBatchSizeWithoutWaiting(t *testing.T) {
	r := &recorder{}
	w := New(Config[int]{Name: "test", Logger: quiet, QueueSize: 100, BatchSize: 3,
		FlushInterval: time.Hour, Write: r.write})
	defer w.Close()
	for i := range 3 {
		w.Add(i)
	}
	deadline := time.Now().Add(2 * time.Second)
	for r.total() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if r.total() != 3 {
		t.Fatalf("written %d, want a full batch written at once", r.total())
	}
}

func TestWriterCloseWritesWhatIsQueuedAndLaterAddsAreIgnored(t *testing.T) {
	r := &recorder{}
	w := New(Config[int]{Name: "test", Logger: quiet, QueueSize: 100, BatchSize: 1000,
		FlushInterval: time.Hour, Write: r.write})
	w.Add(1)
	w.Add(2)
	w.Close()
	w.Add(3) // must neither panic nor block
	w.Close()
	w.Flush()
	if r.total() != 2 {
		t.Fatalf("written %d, want the 2 queued before Close", r.total())
	}
}

func TestWriterDropsRatherThanBlocking(t *testing.T) {
	block := make(chan struct{})
	w := New(Config[int]{Name: "test", Logger: quiet, QueueSize: 2, BatchSize: 1,
		FlushInterval: time.Hour, Write: func([]int) error { <-block; return nil }})
	defer func() { close(block); w.Close() }()

	done := make(chan struct{})
	go func() {
		for i := range 50 {
			w.Add(i)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Add blocked on a full queue")
	}
	if w.Dropped() == 0 {
		t.Error("a full queue must count its drops")
	}
}

func TestWriterKeepsRecordingAfterAnOrdinaryWriteFailure(t *testing.T) {
	r := &recorder{err: errors.New("disk is busy")}
	w := newWriter(r, 100, 1000)
	defer w.Close()
	w.Add(1)
	w.Flush()
	if !w.Healthy() {
		t.Fatal("a transient failure must not stop recording")
	}
	r.mu.Lock()
	r.err = nil
	r.mu.Unlock()
	w.Add(2)
	w.Flush()
	if r.total() != 1 {
		t.Errorf("written %d, want only the record after the failure", r.total())
	}
}

// corruptError returns the error SQLite gives for a damaged file.
func corruptError(t *testing.T) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "damaged.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	for range 200 {
		if _, err := db.Exec(`INSERT INTO t (v) VALUES (?)`, strings.Repeat("x", 200)); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 4096; i < len(data); i++ { // keep page 1, with the schema
		data[i] = 0xAB
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	damaged, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer damaged.Close()
	_, err = damaged.Exec(`INSERT INTO t (v) VALUES ('y')`)
	if err == nil || !configdb.IsCorrupt(err) {
		t.Fatalf("expected a corruption error from the damaged file, got %v", err)
	}
	return err
}

func TestWriterStopsForGoodWhenTheDatabaseIsDamaged(t *testing.T) {
	var calls atomic.Int32
	damage := corruptError(t)
	w := New(Config[int]{Name: "test", Logger: quiet, QueueSize: 100, BatchSize: 1000,
		FlushInterval: time.Hour, Write: func([]int) error { calls.Add(1); return damage }})
	defer w.Close()

	w.Add(1)
	w.Flush()
	if w.Healthy() {
		t.Fatal("damage must stop the writer")
	}
	w.Add(2)
	w.Flush()
	if got := calls.Load(); got != 1 {
		t.Errorf("Write called %d times, want once: a stopped writer must not touch the file again", got)
	}
}

func TestWriterStopsWhenPeriodicUpkeepFindsDamage(t *testing.T) {
	damage := corruptError(t)
	w := New(Config[int]{Name: "test", Logger: quiet, QueueSize: 100, BatchSize: 1000,
		FlushInterval: time.Hour, Write: func([]int) error { return nil },
		Periodic: func() error { return damage }, PeriodicEvery: 10 * time.Millisecond})
	defer w.Close()
	deadline := time.Now().Add(2 * time.Second)
	for w.Healthy() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if w.Healthy() {
		t.Fatal("damage found by upkeep must stop the writer")
	}
}

func TestWrittenRunsAfterEachCommittedBatchOnly(t *testing.T) {
	var written atomic.Int32
	r := &recorder{}
	w := New(Config[int]{Name: "test", Logger: quiet, QueueSize: 100, BatchSize: 1000,
		FlushInterval: time.Hour, Write: r.write, Written: func() { written.Add(1) }})
	defer w.Close()
	w.Add(1)
	w.Flush()
	r.mu.Lock()
	r.err = errors.New("fail")
	r.mu.Unlock()
	w.Add(2)
	w.Flush()
	if got := written.Load(); got != 1 {
		t.Errorf("Written ran %d times, want once", got)
	}
}
