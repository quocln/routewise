// Package testenv holds what tests need to run the same assertions on every OS:
// executable paths the config accepts, permission checks that mean something on
// the host, and a local listener the real client can dial.
package testenv

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Exe returns path as an absolute executable path on this OS. Config validation
// refuses a client path that is not absolute, and on Windows a path without a
// drive is not.
func Exe(path string) string {
	if runtime.GOOS == "windows" {
		return "C:" + path
	}
	return path
}

// HasPerm reports whether info carries the permission bits want. Windows has no
// such bits (Go reports 0666 for every writable file); the access list decides
// there, and internal/platform and its callers test that directly.
func HasPerm(info os.FileInfo, want os.FileMode) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm() == want
}

// ListenLocal starts a listener the real client transport can dial, closed with
// the test, and returns its address.
func ListenLocal(t *testing.T) (net.Listener, string) {
	t.Helper()
	l, address, err := listenLocal(t)
	if err != nil {
		t.Fatalf("listen for the test client: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, address
}

// shortTempSocket is a Unix socket path short enough to bind. t.TempDir() embeds
// the test name, which for a table of subtests exceeds macOS's 104-byte limit.
func shortTempSocket(t *testing.T) (string, error) {
	dir, err := os.MkdirTemp("", "rwsock")
	if err != nil {
		return "", err
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "h.sock"), nil
}
