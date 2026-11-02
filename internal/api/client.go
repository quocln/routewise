package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/quocln/routewise/internal/ipc"
)

// clientTimeout bounds a single request/response exchange with the helper.
// A long-poll request, which the helper holds on purpose, gets its wait on top
// (see exchangeTimeout).
const clientTimeout = 10 * time.Second

// RPCError is a JSON-RPC error the helper answered with. Error() is the
// helper's message alone, so callers that print it show what they always did.
type RPCError struct {
	Code    int
	Message string
}

func (e *RPCError) Error() string { return e.Message }

// ConnectError reports that the helper's socket could not be reached: nothing
// is listening, or the socket does not exist. Callers use IsUnavailable to
// tell that apart from a helper that answered with an error.
type ConnectError struct{ Err error }

func (e *ConnectError) Error() string { return "connect to helper: " + e.Err.Error() }
func (e *ConnectError) Unwrap() error { return e.Err }

// IsUnavailable reports whether err means no helper is accepting connections.
func IsUnavailable(err error) bool {
	var ce *ConnectError
	return errors.As(err, &ce)
}

// Client speaks JSON-RPC 2.0 to a running helper over its local IPC endpoint. It exists
// so that callers outside the daemon mutate configuration through the daemon
// rather than by writing the config file themselves, which would race with the
// daemon's own writes.
type Client struct {
	socketPath string
	// timeout bounds one exchange; zero means clientTimeout.
	timeout time.Duration
}

// NewClient returns a client for the helper listening at socketPath.
func NewClient(socketPath string) *Client {
	return &Client{socketPath: socketPath}
}

// Available reports whether a helper is currently accepting connections.
func (c *Client) Available() bool {
	conn, err := ipc.Dial(context.Background(), c.socketPath, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// exchangeTimeout is how long one exchange may take: the base timeout, plus
// the wait a long-poll request asks the helper to hold it for. Without the
// wait, a follow request that is idle on purpose would hit the base deadline.
func (c *Client) exchangeTimeout(params json.RawMessage) time.Duration {
	base := c.timeout
	if base == 0 {
		base = clientTimeout
	}
	var p struct {
		WaitMs int `json:"waitMs"`
	}
	if len(params) > 0 && json.Unmarshal(params, &p) == nil && p.WaitMs > 0 {
		base += time.Duration(p.WaitMs) * time.Millisecond
	}
	return base
}

// Call sends one request and decodes the result into out. A JSON-RPC error is
// returned as an *RPCError carrying the helper's message.
func (c *Client) Call(method string, params interface{}, out interface{}) error {
	return c.CallContext(context.Background(), method, params, out)
}

// CallContext is Call that also stops when ctx is cancelled. The exchange
// deadline covers the wait of a long-poll request (params with waitMs), and
// never extends past ctx's own deadline.
func (c *Client) CallContext(ctx context.Context, method string, params interface{}, out interface{}) error {
	req := Request{JSONRPC: "2.0", Method: method, ID: 1}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("encode params: %w", err)
		}
		req.Params = raw
	}
	timeout := c.exchangeTimeout(req.Params)

	conn, err := ipc.Dial(ctx, c.socketPath, min(timeout, clientTimeout))
	if err != nil {
		return &ConnectError{Err: err}
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	// Closing the connection unblocks a read that is waiting on the helper.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return c.ioError(ctx, "send request", err)
	}

	// Decode into json.RawMessage first so a caller that does not care about the
	// result can pass nil, and so an error response is reported as an error.
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *Error          `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return c.ioError(ctx, "read response", err)
	}
	if resp.Error != nil {
		return &RPCError{Code: resp.Error.Code, Message: resp.Error.Message}
	}
	if out == nil || len(resp.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(resp.Result, out); err != nil {
		return fmt.Errorf("decode result: %w", err)
	}
	return nil
}

// Prefs returns the calling user's app preferences. The helper picks the user
// from the socket's credentials.
func (c *Client) Prefs() (map[string]json.RawMessage, error) {
	var out PrefsResult
	if err := c.Call(MethodPrefsGet, nil, &out); err != nil {
		return nil, err
	}
	if out.Prefs == nil {
		out.Prefs = map[string]json.RawMessage{}
	}
	return out.Prefs, nil
}

// SetPref stores value (any JSON) under key for the calling user; a JSON null
// deletes the key.
func (c *Client) SetPref(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode preference: %w", err)
	}
	return c.Call(MethodPrefsSet, PrefsSetParams{Key: key, Value: raw}, nil)
}

// ioError wraps a socket failure, reporting cancellation as the context's
// error rather than as the "use of closed connection" it caused.
func (c *Client) ioError(ctx context.Context, what string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	// The socket deadline can fire a moment before the context notices its own.
	if d, ok := ctx.Deadline(); ok && errors.Is(err, os.ErrDeadlineExceeded) && !time.Now().Before(d) {
		return context.DeadlineExceeded
	}
	return fmt.Errorf("%s: %w", what, err)
}
