package daemon

import (
	"net"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/ipc"
)

// peerFromConn asks the kernel who is on the other end of a connection. A
// connection whose identity cannot be read comes back unverified, which the
// authorizer treats as read-only, so a platform without kernel-reported peer
// identity can never authorize a routing change.
func peerFromConn(conn net.Conn) api.Peer {
	id, ok := ipc.Identify(conn)
	if !ok {
		return api.Peer{}
	}
	return api.Peer{UID: id.UID, SID: id.SID, Session: id.Session, Admin: id.Admin, Verified: true}
}
