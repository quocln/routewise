package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/api"
)

func TestConsoleUserAuthorizer(t *testing.T) {
	const consoleUID = uint32(501)

	tests := []struct {
		name       string
		peer       api.Peer
		consoleErr error
		allow      bool
	}{
		{
			name:  "console user allowed",
			peer:  api.Peer{UID: consoleUID, Verified: true},
			allow: true,
		},
		{
			name:  "root allowed",
			peer:  api.Peer{UID: 0, Verified: true},
			allow: true,
		},
		{
			name: "other local account denied",
			peer: api.Peer{UID: 502, Verified: true},
		},
		{
			// Socket group membership alone must not grant control: an
			// unverifiable peer stays read-only.
			name: "unverified peer denied",
			peer: api.Peer{UID: consoleUID},
		},
		{
			// With nobody logged in at the display there is no one to compare
			// against, so a non-root caller cannot be admitted.
			name:       "unknown console owner denies non-root",
			peer:       api.Peer{UID: consoleUID, Verified: true},
			consoleErr: errors.New("no console device"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &ConsoleUserAuthorizer{
				consoleUID: func() (uint32, error) {
					if tt.consoleErr != nil {
						return 0, tt.consoleErr
					}
					return consoleUID, nil
				},
			}

			err := auth.AllowMutation(tt.peer)

			if tt.allow {
				if err != nil {
					t.Fatalf("expected the peer to be allowed, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected the peer to be denied")
			}
			if !errors.Is(err, api.ErrUnauthorized) {
				t.Errorf("denial must wrap ErrUnauthorized so the RPC layer can map it, got %v", err)
			}
			// The denial travels back to an unprivileged caller, so it must not
			// disclose who is logged in at the machine.
			if strings.Contains(err.Error(), strconv.Itoa(int(consoleUID))) {
				t.Errorf("denial leaked the console user's uid: %v", err)
			}
		})
	}
}

func TestConsoleUserAuthorizerRootBypassesConsoleLookup(t *testing.T) {
	called := false
	auth := &ConsoleUserAuthorizer{
		consoleUID: func() (uint32, error) {
			called = true
			return 0, errors.New("console device unavailable")
		},
	}

	if err := auth.AllowMutation(api.Peer{UID: 0, Verified: true}); err != nil {
		t.Fatalf("root must stay authorized regardless of console state, got %v", err)
	}
	if called {
		t.Error("root authorization must not depend on the console device")
	}
}

func TestShutdownDoesNotWaitOnIdleClients(t *testing.T) {
	// A GUI keeps its connection open between polls, so at any moment a handler
	// is likely parked in a read that will not return for seconds. Shutdown must
	// not inherit that latency: the installer stops the daemon and immediately
	// bootstraps its replacement, and launchd rejects the new job while the old
	// one is still being torn down.
	server := &SocketServer{
		logger: slog.New(slog.DiscardHandler),
		conns:  make(map[net.Conn]struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.ctx = ctx

	client, serverSide := net.Pipe()
	defer client.Close()

	if !server.trackConn(serverSide) {
		t.Fatal("a connection accepted before shutdown must be tracked")
	}
	server.wg.Add(1)
	go server.handleConnection(serverSide)

	// Wait for the handler to actually block in its read, so the test exercises
	// the idle case rather than a race with goroutine startup.
	readBlocked := make(chan struct{})
	go func() {
		defer close(readBlocked)
		client.SetWriteDeadline(time.Now().Add(2 * time.Second))
		client.Write([]byte(" ")) // whitespace: the decoder consumes it and reads on
	}()
	select {
	case <-readBlocked:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never started reading")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		cancel()
		server.closeConns()
		server.wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown blocked on an idle client connection")
	}

	// The client sees the close rather than a connection left dangling.
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("expected the client side to observe the closed connection")
	} else if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
		t.Logf("client read returned %v", err)
	}
}

func TestConnectionsAcceptedDuringShutdownAreRejected(t *testing.T) {
	server := &SocketServer{
		logger: slog.New(slog.DiscardHandler),
		conns:  make(map[net.Conn]struct{}),
	}
	server.closeConns()

	client, serverSide := net.Pipe()
	defer client.Close()
	defer serverSide.Close()

	if server.trackConn(serverSide) {
		t.Error("a connection accepted after shutdown began must not be tracked, or Stop would never return")
	}
}

func TestMutatingMethodsCoverEveryStateChangingRPC(t *testing.T) {
	// Any RPC that changes routing must produce an audit record. Reads must not,
	// so that routine status polling does not accumulate a log of who is watching.
	stateChanging := []string{
		"domains.add",
		"domains.remove",
		"domains.set",
		"settings.set",
		"vpn.setAllowed",
		"access.clear",
		"dns.clearCache",
		"dns.clean",
	}
	for _, method := range stateChanging {
		if !api.IsMutating(method) {
			t.Errorf("%s changes routing but is not audited", method)
		}
	}

	for _, method := range []string{"status.get", "domains.list", "routes.list", "settings.get", "access.list"} {
		if api.IsMutating(method) {
			t.Errorf("%s is read-only and must not be audited with peer identity", method)
		}
	}
}

// The app keeps one connection open and polls on it for hours, so the size cap
// must apply to each request, not to everything a connection ever sends.
func TestALongLivedConnectionOutlastsTheRequestSizeCap(t *testing.T) {
	d, _, _, _ := newDNSTestDaemonWith(t, nil, "api.rw-test.invalid")
	handler := api.NewHandler(d, nil)
	server := &SocketServer{
		handler: handler,
		logger:  slog.New(slog.DiscardHandler),
		conns:   make(map[net.Conn]struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.ctx = ctx

	client, serverSide := net.Pipe()
	defer client.Close()
	server.trackConn(serverSide)
	server.wg.Add(1)
	go server.handleConnection(serverSide)

	// Each request is padded to ~4 KB; 400 of them send ~1.6 MB in total.
	padding := strings.Repeat(" ", 4096)
	request := []byte(`{"jsonrpc":"2.0","method":"status.get","id":1}` + padding + "\n")
	decoder := json.NewDecoder(client)
	// net.Pipe is synchronous, so writes run beside the reads: the server only
	// drains a request's trailing padding while reading the next one.
	writeErr := make(chan error, 1)
	go func() {
		for range 400 {
			if _, err := client.Write(request); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()
	for i := range 400 {
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		var resp api.Response
		if err := decoder.Decode(&resp); err != nil {
			t.Fatalf("request %d: read: %v (the connection was cut)", i, err)
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
}

// failingListener fails every Accept until closed, as a process out of file
// descriptors would.
type failingListener struct {
	accepts atomic.Int32
	err     error
	closed  chan struct{}
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
		return nil, l.err
	}
}
func (l *failingListener) Close() error   { close(l.closed); return nil }
func (l *failingListener) Addr() net.Addr { return &net.UnixAddr{Name: "test", Net: "unix"} }

func TestAcceptLoopBacksOffOnAPersistentError(t *testing.T) {
	l := &failingListener{err: syscall.EMFILE, closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	server := &SocketServer{logger: slog.New(slog.DiscardHandler), listener: l, ctx: ctx, cancel: cancel}
	server.wg.Add(1)
	go server.acceptLoop()

	time.Sleep(300 * time.Millisecond)
	// A spin would have called Accept hundreds of thousands of times. With the
	// pause doubling from 5 ms, 300 ms allows about seven.
	if n := l.accepts.Load(); n > 12 {
		t.Fatalf("Accept was called %d times in 300 ms; the loop is not backing off", n)
	}
	cancel()
	done := make(chan struct{})
	go func() { server.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the accept loop did not stop with its context during a backoff")
	}
}

func TestAcceptLoopEndsWhenTheListenerIsClosed(t *testing.T) {
	l := &failingListener{err: syscall.EMFILE, closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &SocketServer{logger: slog.New(slog.DiscardHandler), listener: l, ctx: ctx, cancel: cancel}
	server.wg.Add(1)
	go server.acceptLoop()

	l.Close()
	done := make(chan struct{})
	go func() { server.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the accept loop kept retrying on a closed listener")
	}
}
