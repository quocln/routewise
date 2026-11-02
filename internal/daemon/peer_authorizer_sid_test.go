package daemon

import (
	"errors"
	"testing"

	"github.com/quocln/routewise/internal/api"
)

func TestConsoleUserAuthorizerWindowsPeers(t *testing.T) {
	const console = uint32(2)
	const user = "S-1-5-21-1-2-3-1001"
	session := func(id uint32, err error) func() (uint32, error) {
		return func() (uint32, error) { return id, err }
	}

	tests := []struct {
		name    string
		peer    api.Peer
		session func() (uint32, error)
		allow   bool
	}{
		{"elevated administrator is root", api.Peer{SID: user, Session: 5, Admin: true, Verified: true}, session(console, nil), true},
		{"administrator needs no console", api.Peer{SID: user, Admin: true, Verified: true}, session(0, errors.New("none")), true},
		{"user in the console session", api.Peer{SID: user, Session: console, Verified: true}, session(console, nil), true},
		{"user in another session", api.Peer{SID: user, Session: 3, Verified: true}, session(console, nil), false},
		{"service session is not the console", api.Peer{SID: user, Session: 0, Verified: true}, session(console, nil), false},
		{"no console session", api.Peer{SID: user, Session: console, Verified: true}, session(0, errors.New("none")), false},
		{"unverified", api.Peer{SID: user, Session: console, Admin: true}, session(console, nil), false},
		// UID 0 means root only on Unix; a Windows peer's zero UID is nothing.
		{"zero uid on windows is not root", api.Peer{SID: user, UID: 0, Session: 3, Verified: true}, session(console, nil), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &ConsoleUserAuthorizer{
				consoleUID:     func() (uint32, error) { return 0, errors.New("windows has no console uid") },
				consoleSession: tt.session,
			}
			err := auth.AllowMutation(tt.peer)
			if tt.allow && err != nil {
				t.Fatalf("expected allowed, got %v", err)
			}
			if !tt.allow && !errors.Is(err, api.ErrUnauthorized) {
				t.Fatalf("expected ErrUnauthorized, got %v", err)
			}
		})
	}

	// An authorizer with no session source fails closed for a non-admin.
	noSource := &ConsoleUserAuthorizer{}
	if err := noSource.AllowMutation(api.Peer{SID: user, Session: console, Verified: true}); !errors.Is(err, api.ErrUnauthorized) {
		t.Errorf("no session source: got %v, want ErrUnauthorized", err)
	}
}

func TestValidConsoleSession(t *testing.T) {
	for id, ok := range map[uint32]bool{1: true, 2: true, 7: true, 0: false, noConsoleSession: false} {
		if _, err := validConsoleSession(id); (err == nil) != ok {
			t.Errorf("validConsoleSession(%#x) error = %v, want ok=%v", id, err, ok)
		}
	}
}
