//go:build linux

package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID asks the kernel who is on the other end of a Unix socket
// (SO_PEERCRED). The identity is never taken from the request body, so a client
// cannot claim to be someone else. It reports false when the identity cannot be
// read.
func PeerUID(conn net.Conn) (uid uint32, ok bool) {
	unixConn, isUnix := conn.(*net.UnixConn)
	if !isUnix {
		return 0, false
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, false
	}

	var ucred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || sockErr != nil || ucred == nil {
		return 0, false
	}
	return ucred.Uid, true
}
