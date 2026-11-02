//go:build !unix && !windows

package ipc

import (
	"context"
	"net"
	"time"

	"github.com/quocln/routewise/internal/platform"
)

// Dial reports that the client transport is not implemented here.
func Dial(context.Context, string, time.Duration) (net.Conn, error) {
	return nil, platform.Unsupported("helper IPC client")
}
