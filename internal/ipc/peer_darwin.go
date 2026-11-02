//go:build darwin

package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID asks the kernel who is on the other end of a Unix socket. The
// identity is never taken from the request body, so a client cannot claim to be
// someone else. It reports false when the identity cannot be read.
func PeerUID(conn net.Conn) (uid uint32, ok bool) {
	unixConn, isUnix := conn.(*net.UnixConn)
	if !isUnix {
		return 0, false
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, false
	}

	var xucred *unix.Xucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		xucred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil || sockErr != nil || xucred == nil {
		return 0, false
	}
	return xucred.Uid, true
}
