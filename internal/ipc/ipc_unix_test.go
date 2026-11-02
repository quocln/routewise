//go:build unix

package ipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func listenTemp(t *testing.T) (net.Listener, string) {
	t.Helper()
	// Unix socket paths are short; t.TempDir() can exceed the limit.
	dir, err := os.MkdirTemp("/tmp", "rw-ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func TestDialReachesAListeningEndpoint(t *testing.T) {
	l, path := listenTemp(t)
	accepted := make(chan struct{})
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
		close(accepted)
	}()

	conn, err := Dial(context.Background(), path, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
	<-accepted
}

func TestDialFailsWhenNothingListens(t *testing.T) {
	if _, err := Dial(context.Background(), filepath.Join(t.TempDir(), "absent.sock"), time.Second); err == nil {
		t.Fatal("Dial to a missing endpoint must fail")
	}
}
