package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/ipc"
	"github.com/quocln/routewise/internal/telemetry"
)

// requestLimiter caps the bytes one request may take. The connection
// handler refills remaining after every decoded request.
type requestLimiter struct {
	r         io.Reader
	remaining int64
}

func (l *requestLimiter) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

// maxRequestSize limits the size of a single JSON-RPC request (1 MB).
const maxRequestSize = 1 << 20

// SocketPath is the address of the helper's IPC endpoint (a Unix socket path on
// macOS).
const SocketPath = ipc.DefaultAddress

// SocketServer handles local IPC communication for GUI apps.
type SocketServer struct {
	listener net.Listener
	handler  *api.Handler
	logger   *slog.Logger
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// Open client connections, so shutdown can close them instead of waiting
	// for each handler's blocking read to time out. A GUI that holds an idle
	// connection between polls would otherwise stall the daemon for seconds,
	// long enough for launchd to still consider the job alive when the
	// installer bootstraps its replacement.
	connMu  sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool
}

// NewSocketServer creates a new socket server.
func NewSocketServer(handler *api.Handler, logger *slog.Logger) *SocketServer {
	return &SocketServer{
		handler: handler,
		logger:  logger,
	}
}

// Start begins accepting connections on the Unix socket.
func (s *SocketServer) Start(ctx context.Context) error {
	var err error
	s.listener, err = ipc.Listen(SocketPath)
	if err != nil {
		return err
	}

	s.ctx, s.cancel = context.WithCancel(ctx)

	s.connMu.Lock()
	s.conns = make(map[net.Conn]struct{})
	s.closing = false
	s.connMu.Unlock()

	s.wg.Add(1)
	go s.acceptLoop()

	s.logger.Info("socket server started", "path", SocketPath)
	return nil
}

// Stop gracefully shuts down the socket server.
func (s *SocketServer) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}

	// Closing each connection unblocks its handler's read immediately. Without
	// this the wait below lasts until a client happens to send something or its
	// read deadline expires.
	s.closeConns()

	s.wg.Wait()

	// Remove socket file
	ipc.Remove(SocketPath)
	s.logger.Info("socket server stopped")
}

// trackConn registers an accepted connection. It reports false if shutdown has
// already begun, in which case the caller must close the connection itself.
func (s *SocketServer) trackConn(conn net.Conn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closing {
		return false
	}
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.conns[conn] = struct{}{}
	return true
}

// untrackConn forgets a connection its handler is about to close.
func (s *SocketServer) untrackConn(conn net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	delete(s.conns, conn)
}

// closeConns closes every open client connection and refuses further tracking.
func (s *SocketServer) closeConns() {
	s.connMu.Lock()
	s.closing = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.conns = nil
	s.connMu.Unlock()

	for _, conn := range conns {
		conn.Close()
	}
}

// auditMutation records the outcome of an attempt to change routing: accepted,
// denied, or failed for another reason, such as a malformed request.
// This is the one place peer identity is written down, and only for mutations
// (the methods api.IsMutating names): read-only traffic is logged without peer
// identity so routine status polling does not accumulate a log of who is
// watching.
func (s *SocketServer) auditMutation(req *api.Request, resp *api.Response, peer api.Peer) {
	if !api.IsMutating(req.Method) {
		return
	}
	if resp.Error != nil && resp.Error.Code == api.ErrCodeUnauthorized {
		s.logger.Warn("routing change denied",
			append([]any{"method", req.Method, "peer_verified", peer.Verified}, peerAttrs(peer)...)...)
		return
	}
	if resp.Error != nil {
		s.logger.Warn("routing change failed",
			append([]any{"method", req.Method, "code", resp.Error.Code}, peerAttrs(peer)...)...)
		return
	}
	s.logger.Info("routing change accepted",
		append([]any{"method", req.Method}, peerAttrs(peer)...)...)
}

// peerAttrs names a peer for the audit log: a Unix peer by uid, a Windows peer
// by its SID, session and admin status. Its uid is 0 there, which in a log
// would read as root.
func peerAttrs(peer api.Peer) []any {
	if peer.SID == "" {
		return []any{"peer_uid", peer.UID}
	}
	return []any{"peer_sid", peer.SID, "peer_session", peer.Session, "peer_admin", peer.Admin}
}

// Bounds of the pause after a failed accept. A persistent failure (the process
// out of file descriptors, for one) otherwise repeats at once, filling the log
// and holding a core; the pause doubles from the first to the second and resets
// on the next accepted connection.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

// acceptLoop accepts incoming connections.
func (s *SocketServer) acceptLoop() {
	defer s.wg.Done()
	defer telemetry.RepanicAfterCapture()

	var backoff time.Duration
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				// The listener is gone for good; retrying cannot succeed.
				s.logger.Warn("socket listener closed", "error", err)
				return
			}
			backoff = min(max(backoff*2, acceptBackoffMin), acceptBackoffMax)
			s.logger.Warn("accept error", "error", err, "retry_in", backoff)
			timer := time.NewTimer(backoff)
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		backoff = 0

		if !s.trackConn(conn) {
			conn.Close()
			return
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection processes requests from a single client.
func (s *SocketServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer telemetry.RepanicAfterCapture()
	defer conn.Close()
	defer s.untrackConn(conn)

	// Ask the kernel once, at accept time, who is on the other end. Doing it here
	// rather than per request means the identity cannot change under us mid-connection.
	peer := peerFromConn(conn)

	// The size cap applies to each request, not to the connection: the app
	// keeps one connection open and polls on it for hours.
	limiter := &requestLimiter{r: conn, remaining: maxRequestSize}
	decoder := json.NewDecoder(limiter)
	encoder := json.NewEncoder(conn)

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		var req api.Request
		if err := decoder.Decode(&req); err != nil {
			// Connection closed or timeout
			return
		}

		// Reset deadline and size budget for the next request
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		limiter.remaining = maxRequestSize

		// Process request
		resp := s.handleTraced(&req, peer)
		s.auditMutation(&req, resp, peer)

		// Send response
		if err := encoder.Encode(resp); err != nil {
			// A client that hung up before its answer, as the app does when it
			// cancels a long poll on a tab change or a closed window, is routine.
			if isClientGone(err) {
				s.logger.Debug("client left before its response", "method", req.Method)
			} else {
				s.logger.Warn("encode error", "error", err)
			}
			return
		}
	}
}

// handleTraced runs a request, recording a transaction for each mutating
// method. The transaction is named for the method only: no parameter, peer or
// result is attached.
func (s *SocketServer) handleTraced(req *api.Request, peer api.Peer) *api.Response {
	if !api.IsMutating(req.Method) {
		return s.handler.Handle(req, peer)
	}
	_, txn := telemetry.StartTransaction(s.ctx, "rpc", req.Method)
	resp := s.handler.Handle(req, peer)
	txn.Finish(resp.Error != nil)
	return resp
}
