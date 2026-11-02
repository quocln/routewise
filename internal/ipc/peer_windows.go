//go:build windows

package ipc

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Identify asks Windows who is on the other end of a named pipe connection: the
// pipe reports its client's process id (GetNamedPipeClientProcessId), and the
// identity is read from that process's token, never from the request body. It
// reports false when any step is refused, so an unreadable client stays
// read-only.
//
// The pid is looked up after the connection is made, so a client that exits and
// whose pid is reused in that window would be misidentified; closing the window
// would need impersonation, which a client may withhold (go-winio and Rust
// clients open the pipe at the anonymous impersonation level). The helper reads
// the token at once on accept, which keeps the window to microseconds.
func Identify(conn net.Conn) (Peer, bool) {
	handle, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return Peer{}, false
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(handle.Fd()), &pid); err != nil || pid == 0 {
		return Peer{}, false
	}
	return identifyProcess(pid)
}

// identifyProcess reads the user, session and admin status from the token of
// process pid. Opening a process of another user needs SYSTEM or administrator
// rights, which the service has.
func identifyProcess(pid uint32) (Peer, bool) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Peer{}, false
	}
	defer windows.CloseHandle(process)

	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return Peer{}, false
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return Peer{}, false
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return Peer{}, false
	}
	var session uint32
	var returned uint32
	if err := windows.GetTokenInformation(token, windows.TokenSessionId,
		(*byte)(unsafe.Pointer(&session)), uint32(unsafe.Sizeof(session)), &returned); err != nil {
		return Peer{}, false
	}

	userSID := user.User.Sid.String()
	var list []tokenGroup
	for _, g := range groups.AllGroups() {
		if g.Sid != nil {
			list = append(list, tokenGroup{SID: g.Sid.String(), Attributes: g.Attributes})
		}
	}
	return Peer{SID: userSID, Session: session, Admin: tokenIsAdmin(userSID, list)}, true
}
