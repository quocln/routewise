package daemon

import (
	"fmt"

	"github.com/quocln/routewise/internal/api"
)

// ConsoleUserAuthorizer allows routing changes from root and from the user
// currently logged in at the console, and denies everyone else. On Windows
// "root" is an enabled administrator (or SYSTEM) and "the console user" is any
// process in the session attached to the physical console.
type ConsoleUserAuthorizer struct {
	// consoleUID and consoleSession are fields so a test can supply a console
	// owner without needing a real login session on the build machine.
	consoleUID     func() (uint32, error)
	consoleSession func() (uint32, error)
}

// NewConsoleUserAuthorizer builds an authorizer backed by the real console.
func NewConsoleUserAuthorizer() *ConsoleUserAuthorizer {
	return &ConsoleUserAuthorizer{consoleUID: consoleOwnerUID, consoleSession: consoleSessionID}
}

// AllowMutation reports whether peer may change routing state.
func (a *ConsoleUserAuthorizer) AllowMutation(peer api.Peer) error {
	// An unverifiable peer is read-only. Failing closed here is what makes group
	// access to the socket a status grant rather than a control grant.
	if !peer.Verified {
		return fmt.Errorf("%w: peer identity could not be verified", api.ErrUnauthorized)
	}

	if peer.SID != "" {
		return a.allowWindowsPeer(peer)
	}

	// Root already owns the helper and everything it manages.
	if peer.UID == 0 {
		return nil
	}

	uid, err := a.consoleUID()
	if err != nil {
		return fmt.Errorf("%w: console user could not be determined", api.ErrUnauthorized)
	}
	if peer.UID != uid {
		return fmt.Errorf("%w: only the console user may change routing", api.ErrUnauthorized)
	}
	return nil
}

// allowWindowsPeer decides for a peer identified by a Windows token. An
// administrator owns the machine, like root. Anyone else must be in the session
// of the physical console: that is the user sitting at the machine, and a
// process another account runs in the background (or a remote desktop session)
// is not.
func (a *ConsoleUserAuthorizer) allowWindowsPeer(peer api.Peer) error {
	if peer.Admin {
		return nil
	}
	if a.consoleSession == nil {
		return fmt.Errorf("%w: console session could not be determined", api.ErrUnauthorized)
	}
	session, err := a.consoleSession()
	if err != nil {
		return fmt.Errorf("%w: console session could not be determined", api.ErrUnauthorized)
	}
	if peer.Session != session {
		return fmt.Errorf("%w: only the console user may change routing", api.ErrUnauthorized)
	}
	return nil
}

// noConsoleSession is what WTSGetActiveConsoleSessionId returns while no
// session is attached to the console (a session switch is in progress).
const noConsoleSession = 0xFFFFFFFF

// validConsoleSession turns the raw console session id into a usable one. No
// session, or session 0 (where services run, never a person at the console on
// supported Windows), leaves only administrators allowed to change routing.
func validConsoleSession(id uint32) (uint32, error) {
	if id == noConsoleSession || id == 0 {
		return 0, fmt.Errorf("no user session is attached to the console")
	}
	return id, nil
}
