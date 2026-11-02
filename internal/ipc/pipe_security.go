package ipc

// ServiceName is the name of the helper's Windows service.
const ServiceName = "RouteWise"

// PipeAddress is the helper's named pipe on Windows.
const PipeAddress = `\\.\pipe\routewise`

// PipeSecurityDescriptor is the DACL of the helper's pipe, in SDDL.
//
//	D:P                protected: nothing is inherited
//	(A;;GA;;;SY)       SYSTEM: full control (the service)
//	(A;;GA;;;BA)       Administrators: full control (a foreground helper)
//	(A;;0x12018b;;;AU) authenticated users: connect and talk
//
// 0x12018b is FILE_GENERIC_READ (0x120089) | FILE_WRITE_DATA (0x2) |
// FILE_WRITE_ATTRIBUTES (0x100). It leaves out FILE_CREATE_PIPE_INSTANCE (the
// pipe's name for FILE_APPEND_DATA, 0x4), which is what lets a process create
// another server instance of the pipe and receive clients' requests: an
// unprivileged user must not be able to do that. The consequence is that a
// client has to open the pipe with PipeClientAccess, not GENERIC_WRITE.
// Remote clients are refused separately (PIPE_REJECT_REMOTE_CLIENTS).
const PipeSecurityDescriptor = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12018b;;;AU)"

// PipeClientAccess is the access mask a client opens the pipe with:
// GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES. It is within what
// PipeSecurityDescriptor grants to authenticated users.
const PipeClientAccess uint32 = 0x80000000 | 0x2 | 0x100

// pipeServerTrusted decides whether the process behind a connected pipe is the
// helper. Any user may create the pipe name while no helper holds it, so a
// client checks before it sends a request or a secret: the server is the
// service's own process, or else a process whose token is readable and is
// SYSTEM or an elevated administrator (a foreground helper). A standard user
// cannot read a SYSTEM token, which is why the service's process id, which
// anyone may query, is the main proof; an unreadable server is not trusted.
func pipeServerTrusted(serverPID, servicePID uint32, server Peer, serverKnown bool) bool {
	if serverPID == 0 {
		return false
	}
	if servicePID != 0 && serverPID == servicePID {
		return true
	}
	return serverKnown && server.Admin
}
