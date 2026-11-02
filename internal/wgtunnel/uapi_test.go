package wgtunnel

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestUAPIExactText(t *testing.T) {
	cfg := Config{
		PrivateKey: Key{1},
		ListenPort: 51821,
		Peers: []Peer{
			{
				PublicKey:           Key{2},
				PresharedKey:        Key{3},
				Endpoint:            Endpoint{Host: "vpn.example.com", Port: 51820},
				AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24"), netip.MustParsePrefix("192.168.50.0/24")},
				PersistentKeepalive: 25,
			},
			{PublicKey: Key{4}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.5/32")}},
		},
	}
	got, err := cfg.UAPI(map[Key]netip.AddrPort{Key{2}: netip.MustParseAddrPort("203.0.113.9:51820")})
	if err != nil {
		t.Fatal(err)
	}
	h := func(b byte) string { return Key{b}.hex() }
	want := "private_key=" + h(1) + "\n" +
		"listen_port=51821\n" +
		"replace_peers=true\n" +
		"public_key=" + h(2) + "\n" +
		"preshared_key=" + h(3) + "\n" +
		"endpoint=203.0.113.9:51820\n" +
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=10.8.0.0/24\n" +
		"allowed_ip=192.168.50.0/24\n" +
		"public_key=" + h(4) + "\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=10.9.0.5/32\n"
	if got != want {
		t.Fatalf("UAPI mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestUAPIUnresolvedEndpointIsError(t *testing.T) {
	cfg := Config{Peers: []Peer{{PublicKey: Key{2}, Endpoint: Endpoint{Host: "h.example", Port: 1}}}}
	if _, err := cfg.UAPI(nil); err == nil || !strings.Contains(err.Error(), "no resolved address") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveEndpoints(t *testing.T) {
	cfg := Config{Peers: []Peer{
		{PublicKey: Key{1}, Endpoint: Endpoint{Host: "dual.example", Port: 1000}},
		{PublicKey: Key{2}, Endpoint: Endpoint{Host: "v6only.example", Port: 2000}},
		{PublicKey: Key{3}, Endpoint: Endpoint{Host: "192.0.2.7", Port: 3000}}, // literal: never resolved
		{PublicKey: Key{4}}, // no endpoint
	}}
	var asked []string
	resolver := func(_ context.Context, host string) ([]netip.Addr, error) {
		asked = append(asked, host)
		switch host {
		case "dual.example":
			return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("198.51.100.1")}, nil
		case "v6only.example":
			return []netip.Addr{netip.MustParseAddr("2001:db8::2")}, nil
		}
		return nil, errors.New("unexpected host")
	}
	got, err := cfg.ResolveEndpoints(context.Background(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	want := map[Key]netip.AddrPort{
		{1}: netip.MustParseAddrPort("198.51.100.1:1000"),
		{2}: netip.MustParseAddrPort("[2001:db8::2]:2000"),
		{3}: netip.MustParseAddrPort("192.0.2.7:3000"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("peer %v = %v, want %v", k[0], got[k], v)
		}
	}
	if len(asked) != 2 {
		t.Fatalf("resolver asked %v", asked)
	}

	failing := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nxdomain") }
	if _, err := cfg.ResolveEndpoints(context.Background(), failing); err == nil {
		t.Fatal("expected resolver error")
	}
	empty := func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	if _, err := cfg.ResolveEndpoints(context.Background(), empty); err == nil {
		t.Fatal("expected error for empty answer")
	}
}

func TestEnsureKeepaliveForcesAnIntervalOnlyWhereItIsMissing(t *testing.T) {
	k := func(b byte) Key { return Key{b} }
	cfg := Config{Peers: []Peer{
		{PublicKey: k(1), Endpoint: Endpoint{Host: "vpn.example.com", Port: 51820}},
		{PublicKey: k(2), Endpoint: Endpoint{Host: "vpn2.example.com", Port: 51820}, PersistentKeepalive: 60},
		{PublicKey: k(3)}, // no endpoint: waits for the remote side
	}}
	got := EnsureKeepalive(cfg)
	if got.Peers[0].PersistentKeepalive != HealthKeepalive || HealthKeepalive != 25 {
		t.Errorf("peer without keepalive = %d, want 25", got.Peers[0].PersistentKeepalive)
	}
	if got.Peers[1].PersistentKeepalive != 60 {
		t.Errorf("an explicit keepalive must be kept, got %d", got.Peers[1].PersistentKeepalive)
	}
	if got.Peers[2].PersistentKeepalive != 0 {
		t.Errorf("a peer with no endpoint gets no keepalive, got %d", got.Peers[2].PersistentKeepalive)
	}
	if cfg.Peers[0].PersistentKeepalive != 0 {
		t.Error("the caller's config must not be modified")
	}

	resolved := map[Key]netip.AddrPort{k(1): netip.MustParseAddrPort("203.0.113.1:51820"), k(2): netip.MustParseAddrPort("203.0.113.2:51820")}
	text, err := got.UAPI(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "persistent_keepalive_interval=25\n") || !strings.Contains(text, "persistent_keepalive_interval=60\n") {
		t.Errorf("the device must be told both intervals:\n%s", text)
	}
}
