package wgtunnel

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func randomKeyPair(t *testing.T) (priv, pub Key) {
	t.Helper()
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	raw, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pub[:], raw)
	return priv, pub
}

// TestTunnelLifecycleAsRoot creates a real utun, so it needs root and an
// explicit opt-in; it is skipped in ordinary test runs.
func TestTunnelLifecycleAsRoot(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("ROUTEWISE_WG_ROOT_TEST") != "1" {
		t.Skip("needs root and ROUTEWISE_WG_ROOT_TEST=1")
	}
	priv, _ := randomKeyPair(t)
	_, peerPub := randomKeyPair(t)
	cfg := Config{
		PrivateKey: priv,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.255.254.2/32")},
		Peers: []Peer{{
			PublicKey:  peerPub,
			Endpoint:   Endpoint{Host: "192.0.2.1", Port: 51820}, // TEST-NET-1, never answers
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.254.1/32")},
		}},
	}
	tn, err := Start(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Stop()

	if _, err := net.InterfaceByName(tn.Name()); err != nil {
		t.Fatalf("interface %s missing after Start: %v", tn.Name(), err)
	}
	st, err := tn.Stats()
	if err != nil || len(st.Peers) != 1 || st.Peers[0].PublicKey != peerPub {
		t.Fatalf("stats = %+v, err = %v", st, err)
	}
	if eps := tn.PeerEndpoints(); len(eps) != 1 || eps[0] != netip.MustParseAddrPort("192.0.2.1:51820") {
		t.Fatalf("endpoints = %v", eps)
	}

	tn.Stop()
	tn.Stop() // idempotent
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := net.InterfaceByName(tn.Name()); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("interface %s still present after Stop", tn.Name())
		}
		time.Sleep(50 * time.Millisecond)
	}
}
