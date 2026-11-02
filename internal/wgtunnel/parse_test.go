package wgtunnel

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// RFC 7748 section 6.1 Alice key pair: WireGuard keys are X25519 keys, so the
// vector pins PublicKey derivation.
const (
	rfcPrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfcPubHex  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)

func b64FromHex(t *testing.T, h string) string {
	t.Helper()
	raw, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// b64Fill returns a base64 key whose bytes are all b.
func b64Fill(b byte) string {
	k := Key{}
	for i := range k {
		k[i] = b
	}
	return k.Base64()
}

func sampleConf(t *testing.T) string {
	return fmt.Sprintf(`# comment
[Interface]
PrivateKey = %s
Address = 10.8.0.2/24, fd00::2/64
DNS = 10.8.0.1, corp.example, 1.1.1.1
MTU = 1380
ListenPort = 51821
Table = off
PostUp = /bin/touch /tmp/pwned
SaveConfig = true

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = vpn.example.com:51820
AllowedIPs = 10.8.0.0/24, 192.168.50.0/24
PersistentKeepalive = 25

[Peer]
PublicKey = %s
Endpoint = [2001:db8::1]:443
AllowedIPs = 10.9.0.5
`, b64FromHex(t, rfcPrivHex), b64Fill(2), b64Fill(3), b64Fill(4))
}

func TestParseValid(t *testing.T) {
	cfg, err := Parse(sampleConf(t))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MTU != 1380 || cfg.ListenPort != 51821 {
		t.Fatalf("mtu/port = %d/%d", cfg.MTU, cfg.ListenPort)
	}
	if len(cfg.Addresses) != 2 || len(cfg.IPv4Addresses()) != 1 ||
		cfg.IPv4Addresses()[0] != netip.MustParsePrefix("10.8.0.2/24") {
		t.Fatalf("addresses = %v", cfg.Addresses)
	}
	if len(cfg.DNS) != 2 || cfg.DNS[0] != netip.MustParseAddr("10.8.0.1") ||
		len(cfg.DNSSearch) != 1 || cfg.DNSSearch[0] != "corp.example" {
		t.Fatalf("dns = %v search = %v", cfg.DNS, cfg.DNSSearch)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("peers = %d", len(cfg.Peers))
	}
	p := cfg.Peers[0]
	if p.Endpoint != (Endpoint{Host: "vpn.example.com", Port: 51820}) || p.PersistentKeepalive != 25 ||
		len(p.AllowedIPs) != 2 || p.PresharedKey.IsZero() {
		t.Fatalf("peer0 = %+v", p)
	}
	p1 := cfg.Peers[1]
	if p1.Endpoint.String() != "[2001:db8::1]:443" || p1.AllowedIPs[0] != netip.MustParsePrefix("10.9.0.5/32") {
		t.Fatalf("peer1 = %+v", p1)
	}
}

func TestParseIgnoresHooksWithWarnings(t *testing.T) {
	cfg, err := Parse(sampleConf(t))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"table", "postup", "saveconfig"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings %q lack %s", joined, want)
		}
	}
	if strings.Contains(joined, "pwned") {
		t.Error("warning leaked the hook command")
	}
}

func TestParseErrors(t *testing.T) {
	priv, pub := b64Fill(1), b64Fill(2)
	iface := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.0.0.2/32\n"
	peer := "[Peer]\nPublicKey = " + pub + "\nAllowedIPs = 0.0.0.0/0\n"
	cases := map[string]struct{ text, want string }{
		"no peer":         {iface, "at least one [Peer]"},
		"no interface":    {peer, "exactly one [Interface]"},
		"two interfaces":  {iface + iface + peer, "line 4: more than one"},
		"bad private key": {"[Interface]\nPrivateKey = not-a-key\nAddress = 10.0.0.2/32\n" + peer, "line 2: PrivateKey"},
		"short key":       {iface + "[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString([]byte("short")) + "\n", "line 5: PublicKey"},
		"no ipv4":         {"[Interface]\nPrivateKey = " + priv + "\nAddress = fd00::2/64\n" + peer, "IPv4 Address"},
		"bad port high":   {iface + peer + "Endpoint = h.example:70000\n", "port"},
		"bad port zero":   {iface + peer + "Endpoint = h.example:0\n", "port"},
		"endpoint no":     {iface + peer + "Endpoint = nocolon\n", "host:port"},
		"missing pubkey":  {iface + "[Peer]\nAllowedIPs = 10.0.0.0/8\n", "missing PublicKey"},
		"missing private": {"[Interface]\nAddress = 10.0.0.2/32\n" + peer, "missing PrivateKey"},
		"bad cidr":        {iface + peer + "AllowedIPs = 10.0.0.0/99\n", "line 7"},
		"bad mtu":         {iface + "MTU = 12\n" + peer, "MTU"},
		"no equals":       {iface + "garbage\n" + peer, "line 4"},
		"unknown section": {"[Bogus]\n", "unknown section"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(tc.text)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q lacks %q", err, tc.want)
			}
			for _, secret := range []string{priv, pub, "not-a-key"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks key material: %v", err)
				}
			}
		})
	}
}

func TestRedacted(t *testing.T) {
	cfg, err := Parse(sampleConf(t))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Redacted()
	if !r.PrivateKey.IsZero() || !r.Peers[0].PresharedKey.IsZero() {
		t.Fatal("secrets not blanked")
	}
	if r.Peers[0].PublicKey != cfg.Peers[0].PublicKey {
		t.Fatal("public key must survive redaction")
	}
	if cfg.PrivateKey.IsZero() || cfg.Peers[0].PresharedKey.IsZero() {
		t.Fatal("Redacted mutated the original")
	}
	r.Peers[0].AllowedIPs[0] = netip.MustParsePrefix("1.1.1.1/32")
	if cfg.Peers[0].AllowedIPs[0] == r.Peers[0].AllowedIPs[0] {
		t.Fatal("Redacted shares slices with the original")
	}
	if s := fmt.Sprintf("%v %+v %#v", cfg.PrivateKey, cfg, cfg.PrivateKey); strings.Contains(s, b64FromHex(t, rfcPrivHex)) {
		t.Fatal("formatting leaks the key")
	}
}

func TestPublicKeyDerivation(t *testing.T) {
	cfg, err := Parse(sampleConf(t))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := cfg.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if got := pub.hex(); got != rfcPubHex {
		t.Fatalf("public key = %s, want %s", got, rfcPubHex)
	}
	if _, err := (Config{}).PublicKey(); err == nil {
		t.Fatal("expected error for unset private key")
	}
}
