//go:build windows

package ipc

import (
	"context"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// Dial connects to the helper's named pipe at address, giving up after timeout
// or when ctx ends, and refuses a server that is not the helper. The pipe is opened with PipeClientAccess, which is all its
// DACL grants an unprivileged user.
func Dial(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := winio.DialPipeAccess(ctx, address, PipeClientAccess)
	if err != nil {
		if ctx.Err() != nil {
			// go-winio reports its own timeout error; give callers the context's.
			return nil, ctx.Err()
		}
		return nil, err
	}
	// Nothing is sent before the server is known to be the helper: the pipe
	// name can be claimed by any user while the helper is not running.
	if err := verifyPipeServer(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
