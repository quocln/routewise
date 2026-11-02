package ipc

// Peer is who is on the other end of a connection, as the kernel reports it.
// Unix peers carry a uid. Windows peers carry the token's user SID, its logon
// session and whether the token is an enabled administrator; a Windows peer is
// recognised by a non-empty SID, because a uid of 0 means root only on Unix.
type Peer struct {
	UID uint32

	// SID is the Windows user SID in string form ("S-1-5-21-..."); empty on Unix.
	SID string
	// Session is the Windows session id the peer's process runs in.
	Session uint32
	// Admin is set for a Windows peer whose token is SYSTEM or has the
	// Administrators group enabled (an elevated administrator). A UAC-filtered
	// administrator token has the group only for deny, so it is not Admin.
	Admin bool
}

// tokenGroup is a token group reduced to what the admin test reads.
type tokenGroup struct {
	SID        string
	Attributes uint32
}

const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"

	// Group attributes (winnt.h).
	groupEnabled  = 0x00000004
	groupDenyOnly = 0x00000010
)

// tokenIsAdmin reports whether a token with the given user and groups acts as
// an administrator: it is SYSTEM, or the Administrators group is enabled and
// not deny-only. A filtered (non-elevated) administrator token lists the group
// as deny-only and so is not an administrator for this purpose.
func tokenIsAdmin(userSID string, groups []tokenGroup) bool {
	if userSID == sidSystem {
		return true
	}
	for _, g := range groups {
		if g.SID == sidAdministrators && g.Attributes&groupEnabled != 0 && g.Attributes&groupDenyOnly == 0 {
			return true
		}
	}
	return false
}
