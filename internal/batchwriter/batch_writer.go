// Package batchwriter queues records and commits them in batches from one
// goroutine. The access history and the activity log share it: both record from
// hot paths (packet capture, route changes) that must never wait on the
// database, and both live in the one SQLite file that also holds the
// configuration.
package batchwriter

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quocln/routewise/internal/configdb"
)

// Config tunes a Writer.
type Config[T any] struct {
	// Name labels log lines, such as "access history".
	Name   string
	Logger *slog.Logger
	// QueueSize is how many records may wait for the writer; beyond it new
	// records are dropped rather than slowing the caller.
	QueueSize int
	// BatchSize is how many queued records trigger a write at once.
	BatchSize int
	// FlushInterval is the longest a record waits for its write.
	FlushInterval time.Duration
	// Write commits one batch. It is never called concurrently, and the slice is
	// reused afterwards.
	Write func(batch []T) error
	// Written runs after each committed batch, for example to wake long-polls.
	Written func()
	// Periodic, when set, runs every PeriodicEvery after the queued records are
	// written, for upkeep such as a retention purge.
	Periodic      func() error
	PeriodicEvery time.Duration
}

// Writer is a bounded queue drained by one goroutine. Its locks and channels
// are leaves: nothing is called out to while holding one.
type Writer[T any] struct {
	cfg Config[T]

	in       chan T
	flushReq chan chan struct{}
	stop     chan struct{}
	wg       sync.WaitGroup

	closed  atomic.Bool
	stopped atomic.Bool
	dropped atomic.Uint64
}

// New starts a Writer.
func New[T any](cfg Config[T]) *Writer[T] {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	w := &Writer[T]{
		cfg:      cfg,
		in:       make(chan T, cfg.QueueSize),
		flushReq: make(chan chan struct{}),
		stop:     make(chan struct{}),
	}
	w.wg.Add(1)
	go w.run()
	return w
}

// Add queues a record. It never blocks: a full queue, or a writer that stopped
// after finding the database damaged, drops the record.
func (w *Writer[T]) Add(v T) {
	if w.closed.Load() || w.stopped.Load() {
		return
	}
	select {
	case w.in <- v:
	default:
		if n := w.dropped.Add(1); n == 1 || n%1000 == 0 {
			w.cfg.Logger.Warn("queue is full; dropping "+w.cfg.Name+" records", "dropped", n)
		}
	}
}

// Dropped counts the records a full queue turned away.
func (w *Writer[T]) Dropped() uint64 { return w.dropped.Load() }

// Healthy reports whether the writer still records. It turns false for good
// when a write finds the database damaged: the shared file is not rebuilt while
// the helper runs, so recording stays off until the next start.
func (w *Writer[T]) Healthy() bool { return !w.stopped.Load() }

// Flush writes every queued record and returns once they are committed.
func (w *Writer[T]) Flush() {
	if w.closed.Load() {
		return
	}
	done := make(chan struct{})
	select {
	case w.flushReq <- done:
		<-done
	case <-w.stop:
	}
}

// Close writes what is queued and stops the goroutine.
func (w *Writer[T]) Close() {
	if !w.closed.CompareAndSwap(false, true) {
		return
	}
	close(w.stop)
	w.wg.Wait()
}

func (w *Writer[T]) run() {
	defer w.wg.Done()
	flush := time.NewTicker(w.cfg.FlushInterval)
	defer flush.Stop()
	var periodic <-chan time.Time
	if w.cfg.Periodic != nil {
		t := time.NewTicker(w.cfg.PeriodicEvery)
		defer t.Stop()
		periodic = t.C
	}

	batch := make([]T, 0, w.cfg.BatchSize)
	write := func() {
		if len(batch) > 0 {
			w.writeBatch(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case v := <-w.in:
			batch = append(batch, v)
			if len(batch) >= w.cfg.BatchSize {
				write()
			}
		case <-flush.C:
			write()
		case done := <-w.flushReq:
			w.drain(&batch)
			write()
			close(done)
		case <-periodic:
			write()
			if w.stopped.Load() {
				continue
			}
			if err := w.cfg.Periodic(); err != nil {
				w.failed("could not maintain "+w.cfg.Name, err, 0)
			}
		case <-w.stop:
			w.drain(&batch)
			write()
			return
		}
	}
}

// drain moves everything queued into batch.
func (w *Writer[T]) drain(batch *[]T) {
	for {
		select {
		case v := <-w.in:
			*batch = append(*batch, v)
		default:
			return
		}
	}
}

// writeBatch commits batch. A batch that cannot be written is lost; damage
// found while writing stops the writer.
func (w *Writer[T]) writeBatch(batch []T) {
	if w.stopped.Load() {
		return
	}
	if err := w.cfg.Write(batch); err != nil {
		w.failed("could not write "+w.cfg.Name, err, len(batch))
		return
	}
	if w.cfg.Written != nil {
		w.cfg.Written()
	}
}

func (w *Writer[T]) failed(msg string, err error, lost int) {
	if configdb.IsCorrupt(err) {
		w.stopped.Store(true)
		w.cfg.Logger.Error(msg+": the database is damaged; "+w.cfg.Name+" recording is off until the helper restarts",
			"error", err, "lost", lost)
		return
	}
	w.cfg.Logger.Warn(msg, "error", err, "lost", lost)
}
