//go:build unix

package ipc

import (
	"context"
	"net"
	"time"
)

// Dial connects to the helper at address, giving up after timeout or when ctx
// ends.
func Dial(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "unix", address)
}
