package ledger

import (
	"errors"
	"github.com/quocln/routewise/internal/testenv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type record struct {
	Name string `json:"name"`
}

func newLedger(t *testing.T) (*Ledger[record], string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "record.json")
	return New[record](func() string { return path }), path
}

func TestARecordRoundTrips(t *testing.T) {
	l, path := newLedger(t)
	if _, found, err := l.Load(); err != nil || found {
		t.Fatalf("empty ledger: found=%v err=%v", found, err)
	}
	if err := l.Save(record{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	got, found, err := l.Load()
	if err != nil || !found || got.Name != "a" {
		t.Fatalf("got %+v found=%v err=%v", got, found, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !testenv.HasPerm(info, 0o600) {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if !testenv.HasPerm(dir, 0o700) {
		t.Errorf("directory mode = %v, want 0700", dir.Mode().Perm())
	}
}

func TestSavingTheSameStateDoesNotWriteAgain(t *testing.T) {
	l, path := newLedger(t)
	if err := l.Save(record{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	// Taken away behind the ledger's back: a write would bring it back.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := l.Save(record{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an unchanged record was written again: %v", err)
	}
	if err := l.Save(record{Name: "b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("a changed record was not written: %v", err)
	}
}

func TestSavingAgainAfterRemoveWrites(t *testing.T) {
	l, path := newLedger(t)
	for range 2 {
		if err := l.Save(record{Name: "a"}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("not written: %v", err)
		}
		if err := l.Remove(); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Remove(); err != nil {
		t.Errorf("removing what is gone: %v", err)
	}
}

func TestARecordThatCannotBeTrustedIsReported(t *testing.T) {
	for name, write := range map[string]func(path string) error{
		"malformed": func(path string) error { return os.WriteFile(path, []byte("not json"), 0o600) },
		"too large": func(path string) error {
			return os.WriteFile(path, []byte(strings.Repeat("x", defaultMaxBytes+1)), 0o600)
		},
		"directory": func(path string) error { return os.Mkdir(path, 0o700) },
		"symlink":   func(path string) error { return os.Symlink("/etc/hosts", path) },
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "record.json")
			if err := write(path); err != nil {
				t.Skipf("cannot set up: %v", err)
			}
			_, found, err := New[record](func() string { return path }).Load()
			if !errors.Is(err, ErrNotUsable) || found {
				t.Errorf("found=%v err=%v, want ErrNotUsable", found, err)
			}
		})
	}
}

func TestAFailedWriteLeavesTheOldRecordAndNoLitter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	if err := WriteAtomic(path, []byte("old"), WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	for name, opts := range map[string]WriteOptions{
		"before sync":   {BeforeSync: func() error { return boom }},
		"before rename": {BeforeRename: func() error { return boom }},
	} {
		if err := WriteAtomic(path, []byte("new"), opts); !errors.Is(err, boom) {
			t.Fatalf("%s: err = %v", name, err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "old" {
			t.Errorf("%s: record = %q, %v, want the old one", name, got, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("left behind %v", entries)
	}
}

func TestADurableWriteSyncsTheDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	synced := ""
	err := WriteAtomic(path, []byte("x"), WriteOptions{Durable: true, SyncDir: func(dir string) error {
		synced = dir
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if synced != filepath.Dir(path) {
		t.Errorf("synced %q", synced)
	}
}
