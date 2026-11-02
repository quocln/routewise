//go:build linux

package ipc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListenCreatesAWorldConnectableSocketAndReplacesAStaleOne(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rw-ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen over a stale file: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Errorf("%s is not a socket: %v", path, info.Mode())
	}
	if perm := info.Mode().Perm(); perm != 0o666 {
		t.Errorf("socket mode = %o, want 666", perm)
	}

	l.Close()
	Remove(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Remove left the socket behind: %v", err)
	}
}
