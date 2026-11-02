package dailylog

import (
	"bytes"
	"github.com/quocln/routewise/internal/testenv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDatedPathInsertsTheDateBeforeTheExtension(t *testing.T) {
	day := time.Date(2026, 10, 28, 15, 0, 0, 0, time.Local)
	cases := map[string]string{
		"/var/log/routewise.log": "/var/log/routewise-2026-10-28.log",
		"/tmp/x/daemon.out.log":  "/tmp/x/daemon.out-2026-10-28.log",
		"/var/log/routewise":     "/var/log/routewise-2026-10-28",
	}
	for in, want := range cases {
		if got := DatedPath(in, day); got != filepath.FromSlash(want) {
			t.Errorf("DatedPath(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWriterSwitchesFilesAtLocalMidnight(t *testing.T) {
	dir := t.TempDir()
	template := filepath.Join(dir, "routewise.log")
	clock := &fakeClock{t: time.Date(2026, 10, 28, 23, 59, 59, 0, time.Local)}
	w, err := New(template, 14, WithClock(clock.now))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	w.Write([]byte("before\n"))
	clock.set(time.Date(2026, 10, 29, 0, 0, 1, 0, time.Local))
	w.Write([]byte("after\n"))

	if got := read(t, filepath.Join(dir, "routewise-2026-10-28.log")); got != "before\n" {
		t.Errorf("first day = %q", got)
	}
	if got := read(t, filepath.Join(dir, "routewise-2026-10-29.log")); got != "after\n" {
		t.Errorf("second day = %q", got)
	}
	info, _ := os.Stat(filepath.Join(dir, "routewise-2026-10-29.log"))
	if !testenv.HasPerm(info, 0o644) {
		t.Errorf("mode = %v, want 0644", info.Mode().Perm())
	}
}

func TestWriterAppendsToTodaysExistingFile(t *testing.T) {
	dir := t.TempDir()
	template := filepath.Join(dir, "routewise.log")
	clock := &fakeClock{t: time.Date(2026, 10, 28, 9, 0, 0, 0, time.Local)}
	for _, line := range []string{"one\n", "two\n"} {
		w, err := New(template, 14, WithClock(clock.now))
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(line))
		w.Close()
	}
	if got := read(t, filepath.Join(dir, "routewise-2026-10-28.log")); got != "one\ntwo\n" {
		t.Errorf("file = %q, want both lines appended", got)
	}
}

func TestWriterKeepsFourteenDaysAndOnlyItsOwnFiles(t *testing.T) {
	dir := t.TempDir()
	touch := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Today is 2026-10-28: the 14 kept dates run 10-15 .. 10-28.
	for _, name := range []string{
		"routewise-2026-10-14.log", // 15 days old: deleted
		"routewise-2026-09-01.log", // deleted
		"routewise-2026-10-15.log", // 14th day: kept
		"routewise-2026-10-27.log", // kept
		"routewise.log",            // launchd's undated file: kept
		"routewise-notes.log",      // not a date: kept
		"other-2026-01-01.log",     // another program's file: kept
		"routewise-2026-01-01.txt", // another extension: kept
	} {
		touch(name)
	}
	clock := &fakeClock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.Local)}
	w, err := New(filepath.Join(dir, "routewise.log"), 14, WithClock(clock.now))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	exists := func(name string) bool { _, err := os.Stat(filepath.Join(dir, name)); return err == nil }
	for _, gone := range []string{"routewise-2026-10-14.log", "routewise-2026-09-01.log"} {
		if exists(gone) {
			t.Errorf("%s should have been deleted", gone)
		}
	}
	for _, kept := range []string{"routewise-2026-10-15.log", "routewise-2026-10-27.log", "routewise.log",
		"routewise-notes.log", "other-2026-01-01.log", "routewise-2026-01-01.txt", "routewise-2026-10-28.log"} {
		if !exists(kept) {
			t.Errorf("%s should have been kept", kept)
		}
	}

	// A day switch prunes again.
	touch("routewise-2026-10-16.log")
	touch("routewise-2026-10-17.log")
	clock.set(time.Date(2026, 10, 30, 0, 0, 1, 0, time.Local)) // keeps 10-17 .. 10-30
	w.Write([]byte("x"))
	if exists("routewise-2026-10-16.log") || exists("routewise-2026-10-15.log") {
		t.Error("the switch to a new day must delete files that fell out of the window")
	}
	if !exists("routewise-2026-10-17.log") {
		t.Error("10-17 is still inside the window")
	}
}

func TestWriterFallsBackWhenTheFileCannotBeOpened(t *testing.T) {
	dir := t.TempDir()
	clock := &fakeClock{t: time.Date(2026, 10, 28, 9, 0, 0, 0, time.Local)}
	var fallback bytes.Buffer
	w, err := New(filepath.Join(dir, "routewise.log"), 14, WithClock(clock.now), WithFallback(&fallback))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// The next day's file cannot be created: its name is taken by a directory.
	if err := os.Mkdir(filepath.Join(dir, "routewise-2026-10-29.log"), 0o755); err != nil {
		t.Fatal(err)
	}
	clock.set(time.Date(2026, 10, 29, 0, 0, 1, 0, time.Local))
	if _, err := w.Write([]byte("kept\n")); err != nil {
		t.Fatal(err)
	}
	if fallback.String() != "kept\n" {
		t.Errorf("fallback = %q, the line must not be lost", fallback.String())
	}
}

func TestNewRejectsAnUnopenableDirectory(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "missing", "routewise.log"), 14); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
	if _, err := New("/tmp/x.log", 0); err == nil {
		t.Fatal("expected an error for keepDays < 1")
	}
}

func TestWriterIsSafeForConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	clock := &fakeClock{t: time.Date(2026, 10, 28, 23, 59, 59, 0, time.Local)}
	w, err := New(filepath.Join(dir, "routewise.log"), 14, WithClock(clock.now))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 50 {
				if j == 25 && i == 0 {
					clock.set(time.Date(2026, 10, 29, 0, 0, 1, 0, time.Local))
				}
				w.Write([]byte("line\n"))
			}
		}()
	}
	wg.Wait()
	total := 0
	for _, day := range []string{"28", "29"} {
		total += strings.Count(read(t, filepath.Join(dir, "routewise-2026-10-"+day+".log")), "line\n")
	}
	if total != 400 {
		t.Errorf("lines = %d, want 400", total)
	}
}
