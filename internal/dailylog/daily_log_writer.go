// Package dailylog writes a log to one file per local day. launchd keeps the
// descriptor of its own stdout/stderr file open, so a rotated file would keep
// receiving writes; the helper therefore rotates the file it writes itself.
package dailylog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// dateLayout is the date in a file name: routewise-2026-10-28.log.
	dateLayout = "2006-01-02"
	// reopenBackoff is how long a failed open is left alone before the next
	// write tries again, so a full disk does not cost a syscall per line.
	reopenBackoff = 30 * time.Second
)

// Writer is an io.Writer that appends to <dir>/<base>-YYYY-MM-DD<ext>, where
// dir, base and ext come from a template path such as /var/log/routewise.log.
// It switches files at local midnight (checked on every write) and deletes
// dated files that fall outside the retention window. It is safe for
// concurrent use.
type Writer struct {
	dir, base, ext string
	keepDays       int
	now            func() time.Time
	fallback       io.Writer

	mu        sync.Mutex
	file      *os.File
	day       string // date of file
	retryAt   time.Time
	lastError error
}

// Option customizes a Writer.
type Option func(*Writer)

// WithClock replaces the time source; tests use it to cross midnight.
func WithClock(now func() time.Time) Option { return func(w *Writer) { w.now = now } }

// WithFallback sets where lines go while the dated file cannot be opened.
// The default is os.Stderr, which launchd captures.
func WithFallback(fallback io.Writer) Option { return func(w *Writer) { w.fallback = fallback } }

// DatedPath returns the path of the log for day, derived from the template
// path: /var/log/routewise.log becomes /var/log/routewise-2026-10-28.log.
func DatedPath(template string, day time.Time) string {
	dir, base, ext := split(template)
	return filepath.Join(dir, base+"-"+day.Format(dateLayout)+ext)
}

func split(template string) (dir, base, ext string) {
	dir = filepath.Dir(template)
	file := filepath.Base(template)
	ext = filepath.Ext(file)
	return dir, strings.TrimSuffix(file, ext), ext
}

// New opens today's file, creating it (0644) when needed, and deletes dated
// files older than keepDays. An error means today's file cannot be opened.
func New(template string, keepDays int, opts ...Option) (*Writer, error) {
	if keepDays < 1 {
		return nil, fmt.Errorf("keepDays must be at least 1, got %d", keepDays)
	}
	w := &Writer{keepDays: keepDays, now: time.Now, fallback: os.Stderr}
	w.dir, w.base, w.ext = split(template)
	for _, opt := range opts {
		opt(w)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.rotateLocked(w.now()); err != nil {
		return nil, err
	}
	return w, nil
}

// Write appends p to the file of the current local day.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := w.now()
	if w.file == nil || now.Format(dateLayout) != w.day {
		if w.file != nil || !now.Before(w.retryAt) {
			if err := w.rotateLocked(now); err != nil {
				w.lastError = err
				w.retryAt = now.Add(reopenBackoff)
			}
		}
	}
	if w.file == nil {
		// Do not lose the line: the fallback is launchd's crash log.
		return w.fallback.Write(p)
	}
	return w.file.Write(p)
}

// Close closes the current file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// rotateLocked opens the file for now's date and prunes old ones. On failure
// the previous file (if any) is closed and the writer has no file.
func (w *Writer) rotateLocked(now time.Time) error {
	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
	path := filepath.Join(w.dir, w.base+"-"+now.Format(dateLayout)+w.ext)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	// The process umask must not make the log unreadable to the console user.
	_ = f.Chmod(0o644)
	w.file, w.day = f, now.Format(dateLayout)
	w.prune(now)
	return nil
}

// prune deletes dated files outside the retention window: it keeps the last
// keepDays dates including today. Only files named exactly
// <base>-YYYY-MM-DD<ext> are touched, so the undated launchd file and
// anything else in the directory is left alone. Failures are not fatal.
func (w *Writer) prune(now time.Time) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	loc := now.Location()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	oldestKept := today.AddDate(0, 0, -(w.keepDays - 1))
	prefix := w.base + "-"
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, w.ext) {
			continue
		}
		stamp := strings.TrimSuffix(strings.TrimPrefix(name, prefix), w.ext)
		day, err := time.ParseInLocation(dateLayout, stamp, loc)
		if err != nil || !day.Before(oldestKept) {
			continue
		}
		_ = os.Remove(filepath.Join(w.dir, name))
	}
}
