//go:build linux

package vpnclient

import (
	"context"
	"os"
	"testing"
)

// TestIdentifyLiveInterface identifies the owner of the interface named by
// ROUTEWISE_LIVE_IDENTIFY_IFACE and compares it with
// ROUTEWISE_LIVE_IDENTIFY_NAME. It needs root to read other processes'
// descriptors and a simulated VPN (run it inside its network namespace); it is
// skipped otherwise.
func TestIdentifyLiveInterface(t *testing.T) {
	iface := os.Getenv("ROUTEWISE_LIVE_IDENTIFY_IFACE")
	if iface == "" || os.Geteuid() != 0 {
		t.Skip("needs root and ROUTEWISE_LIVE_IDENTIFY_IFACE")
	}
	client, err := Identify(context.Background(), iface)
	if err != nil {
		t.Fatalf("Identify(%q): %v", iface, err)
	}
	t.Logf("%s owner: %+v", iface, client)
	if want := os.Getenv("ROUTEWISE_LIVE_IDENTIFY_NAME"); want != "" && client.Name != want {
		t.Fatalf("Identify(%q).Name = %q, want %q", iface, client.Name, want)
	}
}

func TestIdentifyUnknownInterfaceFails(t *testing.T) {
	if _, err := Identify(context.Background(), "rw-no-such-iface"); err == nil {
		t.Fatal("an interface that does not exist must not be identified")
	}
}
