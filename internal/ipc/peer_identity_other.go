//go:build !darwin && !linux && !windows

package ipc

import "net"

// Identify has no implementation on this platform and reports false, which the
// helper treats as an unverified peer: read-only, never allowed to change
// routing.
func Identify(net.Conn) (Peer, bool) { return Peer{}, false }
