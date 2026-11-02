package daemon

import (
	"slices"
	"testing"

	"github.com/quocln/routewise/internal/api"
)

func TestPeerAttrsNameAWindowsPeerBySIDNotByUID(t *testing.T) {
	if got := peerAttrs(api.Peer{UID: 501}); !slices.Equal(got, []any{"peer_uid", uint32(501)}) {
		t.Errorf("Unix peer attrs = %v", got)
	}
	got := peerAttrs(api.Peer{SID: "S-1-5-21-1-2-3-1001", Session: 2, Admin: true})
	for _, a := range got {
		if a == "peer_uid" {
			t.Fatalf("a Windows peer's uid 0 must not be logged: %v", got)
		}
	}
	if !slices.Contains(got, any("peer_sid")) || !slices.Contains(got, any("S-1-5-21-1-2-3-1001")) {
		t.Errorf("Windows peer attrs = %v", got)
	}
}
