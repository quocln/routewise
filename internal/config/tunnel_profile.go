package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Kinds of built-in VPN client the helper runs itself.
const (
	ProfileKindWireGuard = "wireguard"
	ProfileKindOutline   = "outline"
	ProfileKindSOCKS5    = "socks5"
	ProfileKindHTTP      = "http"
)

// profileKinds lists every kind a profile may have.
var profileKinds = []string{ProfileKindWireGuard, ProfileKindOutline, ProfileKindSOCKS5, ProfileKindHTTP}

// ProfileKinds returns the known profile kinds. Code that keeps a table per kind
// can check its keys against this list.
func ProfileKinds() []string { return slices.Clone(profileKinds) }

// Bounds on what a profile may hold.
const (
	MaxProfiles       = 32
	MaxProfileNameLen = 64
	MaxProfileDNS     = 8
	profileIDBytes    = 4
)

var profileIDRegex = regexp.MustCompile(`^[0-9a-f]{4,32}$`)

// TunnelProfile is the metadata of one built-in VPN: a WireGuard tunnel, an
// Outline (Shadowsocks) tunnel or a tunnel through a SOCKS5 or HTTP proxy, which the
// helper runs itself. It never holds secrets; the WireGuard .conf text, the Outline access
// key and the proxy address live in their own table of the config database and are
// read only by the tunnel manager.
type TunnelProfile struct {
	// ID is short random hex, stable for the life of the profile.
	ID string `yaml:"id" mapstructure:"id" json:"id"`
	// Kind is one of profileKinds.
	Kind string `yaml:"kind" mapstructure:"kind" json:"kind"`
	// Name is what the user calls the profile; it is also the VPN client name
	// shown for the tunnel.
	Name string `yaml:"name" mapstructure:"name" json:"name"`
	// AutoConnect connects the profile when the helper starts.
	AutoConnect bool `yaml:"auto_connect,omitempty" mapstructure:"auto_connect" json:"autoConnect"`
	// DNS are the IPv4 servers routed into the tunnel and bound to its session
	// as the VPN's DNS.
	DNS []string `yaml:"dns,omitempty" mapstructure:"dns" json:"dns"`
}

// ProfileClientID is the VPN client ID of a built-in profile. It sits in the
// allowlist beside executable paths.
func ProfileClientID(kind, id string) string {
	return "routewise-" + kind + ":" + id
}

// ClientID is the VPN client ID of p.
func (p TunnelProfile) ClientID() string { return ProfileClientID(p.Kind, p.ID) }

// ParseProfileClientID splits a built-in client ID into its kind and profile
// ID, and reports whether client has that shape.
func ParseProfileClientID(client string) (kind, id string, ok bool) {
	rest, found := strings.CutPrefix(client, "routewise-")
	if !found {
		return "", "", false
	}
	kind, id, found = strings.Cut(rest, ":")
	if !found || !validProfileKind(kind) || !profileIDRegex.MatchString(id) {
		return "", "", false
	}
	return kind, id, true
}

// IsBuiltinClient reports whether client names a built-in profile rather than
// an executable path.
func IsBuiltinClient(client string) bool {
	_, _, ok := ParseProfileClientID(client)
	return ok
}

func validProfileKind(kind string) bool { return slices.Contains(profileKinds, kind) }

// NewProfileID returns a fresh random profile ID.
func NewProfileID() (string, error) {
	b := make([]byte, profileIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate profile id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ValidateProfileName checks a profile name: not blank, bounded, no control
// characters.
func ValidateProfileName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("profile name is empty")
	}
	if len([]rune(name)) > MaxProfileNameLen {
		return fmt.Errorf("profile name is longer than %d characters", MaxProfileNameLen)
	}
	if strings.ContainsFunc(name, unicode.IsControl) {
		return fmt.Errorf("profile name contains control characters")
	}
	return nil
}

// NormalizeProfileDNS parses a DNS server list: IPv4 addresses only, in
// canonical form, without duplicates.
func NormalizeProfileDNS(servers []string) ([]string, error) {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("profile DNS server %q is not an IPv4 address", s)
		}
		if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() {
			return nil, fmt.Errorf("profile DNS server %q is not a usable unicast address", s)
		}
		if text := addr.String(); !slices.Contains(out, text) {
			out = append(out, text)
		}
	}
	if len(out) > MaxProfileDNS {
		return nil, fmt.Errorf("at most %d DNS servers are allowed", MaxProfileDNS)
	}
	return out, nil
}

// validateProfiles checks every profile and that IDs and names are unique.
func validateProfiles(profiles []TunnelProfile) error {
	if len(profiles) > MaxProfiles {
		return fmt.Errorf("too many profiles: %d (max %d)", len(profiles), MaxProfiles)
	}
	ids := make(map[string]bool, len(profiles))
	names := make(map[string]bool, len(profiles))
	for i, p := range profiles {
		if !profileIDRegex.MatchString(p.ID) {
			return fmt.Errorf("profiles[%d]: invalid id %q", i, p.ID)
		}
		if !validProfileKind(p.Kind) {
			return fmt.Errorf("profiles[%d]: kind must be one of %s, got %q", i, strings.Join(profileKinds, ", "), p.Kind)
		}
		if err := ValidateProfileName(p.Name); err != nil {
			return fmt.Errorf("profiles[%d]: %w", i, err)
		}
		if _, err := NormalizeProfileDNS(p.DNS); err != nil {
			return fmt.Errorf("profiles[%d]: %w", i, err)
		}
		if ids[p.ID] {
			return fmt.Errorf("profiles[%d]: id %q listed twice", i, p.ID)
		}
		key := strings.ToLower(strings.TrimSpace(p.Name))
		if names[key] {
			return fmt.Errorf("profiles[%d]: name %q is already used by another profile", i, p.Name)
		}
		ids[p.ID], names[key] = true, true
	}
	return nil
}

// Profile returns the profile with the given ID.
func (c *Config) Profile(id string) (TunnelProfile, bool) {
	for _, p := range c.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return TunnelProfile{}, false
}

// EnsureProfileVPNs gives every profile its VPN client entry, last in priority
// when it has none yet, so each built-in VPN can hold a domain list.
func (c *Config) EnsureProfileVPNs() {
	for _, p := range c.Profiles {
		if !slices.Contains(c.AllowedClients(), p.ClientID()) {
			c.VPNs = append(c.VPNs, VPNRoute{Client: p.ClientID()})
		}
	}
}

// validateProfileClients checks that built-in client entries and profiles pair
// up one to one: an entry without a profile would name a tunnel that cannot
// exist, and a profile without an entry could never route anything.
func (c *Config) validateProfileClients() error {
	for i, v := range c.VPNs {
		if !IsBuiltinClient(v.Client) {
			continue
		}
		kind, id, _ := ParseProfileClientID(v.Client)
		if p, ok := c.Profile(id); !ok || p.Kind != kind {
			return fmt.Errorf("vpns[%d]: built-in client %q has no matching profile", i, v.Client)
		}
	}
	for _, p := range c.Profiles {
		if !slices.Contains(c.AllowedClients(), p.ClientID()) {
			return fmt.Errorf("profile %q has no VPN client entry", p.Name)
		}
	}
	return nil
}
