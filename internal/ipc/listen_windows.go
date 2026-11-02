//go:build windows

package ipc

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// DefaultAddress is the helper's named pipe.
const DefaultAddress = PipeAddress

// pipeBufferSize is the pipe's in and out buffer. Requests are bounded at 1 MB
// by the daemon; the buffer only has to keep small replies from blocking.
const pipeBufferSize = 64 << 10

// Listen creates the helper's named pipe at address. The DACL
// (PipeSecurityDescriptor) lets any authenticated local user connect, SYSTEM and
// Administrators have full control, and go-winio creates the pipe with
// PIPE_REJECT_REMOTE_CLIENTS so nothing off the machine can reach it. Who may
// change routing is the daemon's peer authorizer's decision, fed by the
// client's token. Creating the first instance fails when the name is already
// taken, so a second helper or a squatter cannot share it.
func Listen(address string) (net.Listener, error) {
	return winio.ListenPipe(address, &winio.PipeConfig{
		SecurityDescriptor: PipeSecurityDescriptor,
		InputBufferSize:    pipeBufferSize,
		OutputBufferSize:   pipeBufferSize,
	})
}

// Remove does nothing: a named pipe disappears with its last handle.
func Remove(string) {}
