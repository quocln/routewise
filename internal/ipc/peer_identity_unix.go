//go:build darwin || linux

package ipc

import "net"

// Identify reports who is on the other end of conn from the kernel's socket
// credentials. It reports false when the identity cannot be read.
func Identify(conn net.Conn) (Peer, bool) {
	uid, ok := PeerUID(conn)
	if !ok {
		return Peer{}, false
	}
	return Peer{UID: uid}, true
}
