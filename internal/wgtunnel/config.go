// Package wgtunnel runs WireGuard tunnels inside the helper process using the
// embedded wireguard-go library. It is cgo-free: the utun device, the Noise
// engine and the UDP bind are all pure Go on darwin.
//
// The package deliberately owns no routing policy. It creates the interface,
// assigns its addresses and configures peers; which destinations are sent into
// the tunnel is decided by the caller.
package wgtunnel

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"

	"golang.org/x/crypto/curve25519"
)

// KeyLen is the size in bytes of every WireGuard key.
const KeyLen = 32

// Key is a 32-byte WireGuard key (private, public or preshared).
//
// Its String and GoString methods never print the key bytes, so a Key that is
// accidentally formatted into a log line or an error leaks nothing. Use
// Base64 or hex deliberately when the material is truly needed.
type Key [KeyLen]byte

// IsZero reports whether the key is unset.
func (k Key) IsZero() bool { return k == Key{} }

// String returns a fixed placeholder instead of the key material.
func (k Key) String() string {
	if k.IsZero() {
		return ""
	}
	return "[redacted]"
}

// GoString keeps %#v from printing key bytes.
func (k Key) GoString() string { return "wgtunnel.Key(" + k.String() + ")" }

// Base64 returns the wg-quick text form of the key.
func (k Key) Base64() string { return base64.StdEncoding.EncodeToString(k[:]) }

// hex returns the lowercase hex form that the UAPI protocol expects.
func (k Key) hex() string { return hex.EncodeToString(k[:]) }

// parseKey decodes a base64 key. The error never contains the input.
func parseKey(s string) (Key, error) {
	var k Key
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != KeyLen {
		return k, fmt.Errorf("not a base64-encoded %d-byte key", KeyLen)
	}
	copy(k[:], raw)
	return k, nil
}

// parseHexKey decodes a UAPI hex key. The error never contains the input.
func parseHexKey(s string) (Key, error) {
	var k Key
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != KeyLen {
		return k, fmt.Errorf("not a hex-encoded %d-byte key", KeyLen)
	}
	copy(k[:], raw)
	return k, nil
}

// Endpoint is a peer's remote address. Host may be a DNS name that the caller
// resolves before configuring the device, so the tunnel's own transport is
// never looked up through the tunnel being built.
type Endpoint struct {
	Host string
	Port uint16
}

// IsZero reports whether the peer has no endpoint (it then waits for the
// remote side to initiate).
func (e Endpoint) IsZero() bool { return e.Host == "" }

// String renders host:port, bracketing IPv6 literals.
func (e Endpoint) String() string {
	if e.IsZero() {
		return ""
	}
	if a, err := netip.ParseAddr(e.Host); err == nil {
		return netip.AddrPortFrom(a, e.Port).String()
	}
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

// Peer is one [Peer] section.
type Peer struct {
	PublicKey           Key
	PresharedKey        Key // zero when absent
	Endpoint            Endpoint
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int // seconds, 0 = off
}

// Config is a parsed wg-quick profile.
type Config struct {
	PrivateKey Key
	// Addresses are the [Interface] Address entries exactly as written (host
	// bits preserved). IPv4 entries are assigned to the interface; IPv6 entries
	// are kept so callers can inspect them but Start does not assign them.
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	DNSSearch  []string
	MTU        int // 0 = use DefaultMTU
	ListenPort int // 0 = let the kernel pick
	Peers      []Peer

	// Warnings records wg-quick-only keys (Table, hooks, SaveConfig) and unknown
	// keys that were ignored. Hooks are never executed.
	Warnings []string
}

// IPv4Addresses returns only the IPv4 interface addresses.
func (c Config) IPv4Addresses() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range c.Addresses {
		if p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out
}

// HealthKeepalive is the PersistentKeepalive, in seconds, the tunnel forces on
// every peer with an endpoint that configures none. Without traffic WireGuard
// never handshakes, so a tunnel nothing has used yet could not be told from a
// dead one. A keepalive makes the device handshake at once and again on every
// rekey, which keeps the peer's last-handshake time fresh while the path works.
const HealthKeepalive = 25

// EnsureKeepalive returns a copy of c in which every peer that has an endpoint
// and no PersistentKeepalive gets HealthKeepalive. A peer with no endpoint waits
// for the remote side and is left alone, as is one that sets its own interval.
func EnsureKeepalive(c Config) Config {
	out := c
	out.Peers = make([]Peer, len(c.Peers))
	copy(out.Peers, c.Peers)
	for i := range out.Peers {
		if p := &out.Peers[i]; !p.Endpoint.IsZero() && p.PersistentKeepalive == 0 {
			p.PersistentKeepalive = HealthKeepalive
		}
	}
	return out
}

// Redacted returns a deep copy with the private key and every preshared key
// blanked, safe for logs and RPC responses.
func (c Config) Redacted() Config {
	out := c
	out.PrivateKey = Key{}
	out.Addresses = append([]netip.Prefix(nil), c.Addresses...)
	out.DNS = append([]netip.Addr(nil), c.DNS...)
	out.DNSSearch = append([]string(nil), c.DNSSearch...)
	out.Warnings = append([]string(nil), c.Warnings...)
	out.Peers = make([]Peer, len(c.Peers))
	for i, p := range c.Peers {
		p.PresharedKey = Key{}
		p.AllowedIPs = append([]netip.Prefix(nil), p.AllowedIPs...)
		out.Peers[i] = p
	}
	return out
}

// PublicKey derives the interface public key from the private key.
func (c Config) PublicKey() (Key, error) {
	var pub Key
	if c.PrivateKey.IsZero() {
		return pub, fmt.Errorf("private key is not set")
	}
	raw, err := curve25519.X25519(c.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return pub, fmt.Errorf("derive public key: %w", err)
	}
	copy(pub[:], raw)
	return pub, nil
}
