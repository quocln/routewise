//go:build !windows

package dnsproxy

import "syscall"

// shareListener is nil off Windows: no shared bind is attempted.
var shareListener func(network, address string, c syscall.RawConn) error
