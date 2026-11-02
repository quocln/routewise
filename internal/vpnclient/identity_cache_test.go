package vpnclient

import (
	"testing"

	"github.com/quocln/routewise/internal/winnet"
)

func TestCachedIdentityHoldsUntilTheAdapterChanges(t *testing.T) {
	a := winnet.Adapter{LUID: 9001, Index: 14, Alias: "work", Up: true}
	want := Client{ID: `c:\program files\wireguard\wireguard.exe`, Name: "WireGuard"}
	rememberIdentity(a, want)

	if got, ok := cachedIdentity(a); !ok || got != want {
		t.Fatalf("cachedIdentity = %+v, %v; want the remembered client", got, ok)
	}
	for name, changed := range map[string]winnet.Adapter{
		"new interface index": {LUID: 9001, Index: 15, Alias: "work", Up: true},
		"renamed":             {LUID: 9001, Index: 14, Alias: "other", Up: true},
		"down":                {LUID: 9001, Index: 14, Alias: "work", Up: false},
	} {
		rememberIdentity(a, want)
		if _, ok := cachedIdentity(changed); ok {
			t.Errorf("%s: a changed adapter must be identified again", name)
		}
	}
}
