// Package ledger keeps small records that must survive a crash of this process:
// what RouteWise put in the routing table, so the next start can take it out. Each
// record is replaced atomically, so a reader finds the old one or the new one, never
// part of either, and only root can read it.
package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	dirMode  os.FileMode = 0700
	fileMode os.FileMode = 0600
	// defaultMaxBytes bounds what a corrupt or hostile file can make the caller read.
	defaultMaxBytes = 1 << 20
)

// ErrNotUsable means a record exists but cannot be trusted: it is not a regular file,
// is too large, or does not parse. Callers report it and leave the file for a person.
var ErrNotUsable = errors.New("ledger record is not usable")

// WriteOptions adjusts WriteAtomic. The zero value suits a record that only has to
// outlive a crashed process, which the page cache does.
type WriteOptions struct {
	// Durable forces the data to disk before the rename, and SyncDir, when set, runs
	// after it. Use it for state that must survive a power loss. It costs tens of
	// milliseconds, so it does not belong on a hot path.
	Durable bool
	SyncDir func(dir string) error
	// BeforeSync, BeforeRename and BeforeDirSync let a test fail at each step.
	BeforeSync, BeforeRename, BeforeDirSync func() error
}

// WriteAtomic replaces the file at path with data, by way of a private temporary file
// in the same directory. A failure leaves whatever was there before.
func WriteAtomic(path string, data []byte, opts WriteOptions) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	tmp, err := os.CreateTemp(dir, "."+base+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(fileMode); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := run(opts.BeforeSync); err != nil {
		return err
	}
	if opts.Durable {
		if err := tmp.Sync(); err != nil {
			return fmt.Errorf("sync: %w", err)
		}
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := run(opts.BeforeRename); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace: %w", err)
	}
	if err := run(opts.BeforeDirSync); err != nil {
		return err
	}
	if opts.Durable && opts.SyncDir != nil {
		return opts.SyncDir(dir)
	}
	return nil
}

func run(step func() error) error {
	if step == nil {
		return nil
	}
	return step()
}

// Ledger is one JSON record of type T. Its methods are safe to call concurrently.
type Ledger[T any] struct {
	// path is read at each use: where a record lives may be settled after the ledger
	// is built.
	path func() string

	mu sync.Mutex
	// written is the text last saved, so writing the same state again touches nothing.
	written []byte
}

// New returns a ledger for the record at path.
func New[T any](path func() string) *Ledger[T] {
	return &Ledger[T]{path: path}
}

// Save replaces the record. Saving what is already there does nothing.
func (l *Ledger[T]) Save(record T) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.written != nil && string(data) == string(l.written) {
		return nil
	}
	if err := WriteAtomic(l.path(), data, WriteOptions{}); err != nil {
		return err
	}
	l.written = data
	return nil
}

// Load reads the record. found is false when there is none.
func (l *Ledger[T]) Load() (record T, found bool, err error) {
	path := l.path()
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return record, false, nil
	}
	if err != nil {
		return record, false, fmt.Errorf("%w: %w", ErrNotUsable, err)
	}
	if !info.Mode().IsRegular() {
		return record, false, fmt.Errorf("%w: not a regular file", ErrNotUsable)
	}
	file, err := os.Open(path)
	if err != nil {
		return record, false, fmt.Errorf("%w: %w", ErrNotUsable, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, defaultMaxBytes+1))
	if err != nil {
		return record, false, fmt.Errorf("%w: %w", ErrNotUsable, err)
	}
	if len(data) > defaultMaxBytes {
		return record, false, fmt.Errorf("%w: larger than %d bytes", ErrNotUsable, defaultMaxBytes)
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, false, fmt.Errorf("%w: %w", ErrNotUsable, err)
	}
	return record, true, nil
}

// Remove deletes the record. One that is already gone is not an error.
func (l *Ledger[T]) Remove() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.written = nil
	if err := os.Remove(l.path()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
