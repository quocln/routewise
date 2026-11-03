package proxyclient

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.getoutline.org/sdk/transport"
)

const (
	// CheckTimeout bounds one health check.
	CheckTimeout = 10 * time.Second
	// checkTarget is what a health check asks the proxy to reach. It is Cloudflare's
	// secondary resolver on HTTPS, a port proxies rarely block, which DNS's often is.
	checkTarget = "1.0.0.1:443"
)

// ErrAuthRequired means the proxy wants a username and password and has none.
var ErrAuthRequired = errors.New("the proxy requires a username and password")

// ErrAuthRefused means the proxy turned the username and password down.
var ErrAuthRefused = errors.New("the proxy refused the username or password")

// ErrUDPUnsupported means the proxy does not relay UDP, which many do not.
var ErrUDPUnsupported = errors.New("the proxy does not support UDP")

// IsRefusal reports that the proxy answered and turned the profile down. Asking again
// changes nothing until the profile or the proxy does, so unlike silence it needs no
// repeat before a person is told.
func IsRefusal(err error) bool {
	return errors.Is(err, ErrAuthRequired) || errors.Is(err, ErrAuthRefused) || errors.Is(err, ErrConnectUnsupported)
}

// streamDialer opens a stream through a proxy.
type streamDialer interface {
	DialStream(ctx context.Context, addr string) (transport.StreamConn, error)
}

// check proves a proxy answers and accepts the credentials, by asking it to reach
// checkTarget. isAboutTarget picks out the answers that speak of the target and not of
// the proxy. A company proxy may reach only company addresses, and a tunnel marked down
// for that would send its list direct, around the proxy. So this cannot tell a proxy
// that reaches nothing at all, whose traffic then fails rather than leaks.
func check(ctx context.Context, d streamDialer, isAboutTarget func(error) bool) error {
	ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	conn, err := d.DialStream(ctx, checkTarget)
	if err == nil {
		return conn.Close()
	}
	if isAboutTarget(err) {
		return nil
	}
	var answered ConnectStatusError
	if IsRefusal(err) || errors.As(err, &answered) {
		return err
	}
	return fmt.Errorf("the proxy did not answer: %w", err)
}

// handshakeKey carries a handshake to the endpoint that opens its connection.
type handshakeKey struct{}

// handshake holds a connection to the proxy to its context until the request is done.
type handshake struct {
	mu       sync.Mutex
	conn     transport.StreamConn
	stop     func() bool
	finished bool
}

// watch applies ctx to conn, through the deadline that interrupts a blocked read.
func (h *handshake) watch(ctx context.Context, conn transport.StreamConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conn = conn
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	h.stop = context.AfterFunc(ctx, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if !h.finished {
			_ = conn.SetDeadline(time.Now())
		}
	})
}

// finish frees the connection from the context, whatever it did in the meantime.
func (h *handshake) finish() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.finished = true
	if h.conn != nil {
		h.stop()
		_ = h.conn.SetDeadline(time.Time{})
	}
}
