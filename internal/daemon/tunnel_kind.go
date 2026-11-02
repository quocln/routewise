package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
)

// tunnelKind is everything the daemon knows that differs between kinds of
// built-in VPN (WireGuard, Outline). Code that used to branch on the kind asks
// the kind from tunnelKinds instead, so a new kind is one type and one registry
// entry; config.ProfileKinds lists the kinds a profile may have, and a test
// keeps the registry in step with it.
type tunnelKind interface {
	// displayName is the name a profile of this kind gets when its secret
	// suggests none.
	displayName() string
	// pickSecret takes this kind's secret out of the two fields of a profile
	// request and rejects the field of another kind. It may return "" when the
	// request carries no secret.
	pickSecret(wireguardConfig, accessKey string) (string, error)
	// validateSecret parses a secret as a tunnel of this kind would use it,
	// without starting anything, and returns the metadata it implies: the DNS
	// servers it names and a label for the profile. The error never contains
	// the secret.
	validateSecret(secret string) (dns []string, label string, err error)
	// redactionTokens lists the parts of a secret, besides the whole of it, that
	// must never appear in output.
	redactionTokens(secret string) []string
	// healthPolicy is how often a tunnel of this kind is checked and how many
	// failed checks in a row make it unhealthy.
	healthPolicy() healthPolicy
	// start brings a tunnel of this kind up.
	start(ctx context.Context, req tunnelStartRequest, logger *slog.Logger) (builtinTunnel, error)
	// needsSyntheticAddress reports whether the helper must give the tunnel's
	// interface an address of its own (req.Address) because the secret names none.
	needsSyntheticAddress() bool
	// reservedAddrs lists the interface addresses a profile of this kind takes
	// on this machine, read from its secret. load fetches the secret; a kind that
	// takes no address must not call it.
	reservedAddrs(load func() (string, error)) []netip.Addr
	// checkUnique rejects secret when another profile of this kind already uses
	// something that must be unique to one tunnel. others lists those profiles
	// with their stored secrets and is read only when the kind needs it.
	checkUnique(secret string, others func() []profileSecret) error
}

// profileSecret is a stored profile secret with the profile's name.
type profileSecret struct {
	name   string
	secret string
}

// tunnelKinds is the registry, keyed by config's profile kind.
var tunnelKinds = map[string]tunnelKind{
	config.ProfileKindWireGuard: wireguardKind{},
	config.ProfileKindOutline:   outlineKind{},
}

// kindOf returns the registered kind, and false for one nothing implements.
func kindOf(kind string) (tunnelKind, bool) {
	k, ok := tunnelKinds[kind]
	return k, ok
}

// errUnknownKind is returned for a kind the registry lacks.
func errUnknownKind(kind string) error { return fmt.Errorf("unknown profile kind %q", kind) }

func startBuiltinTunnel(ctx context.Context, req tunnelStartRequest, logger *slog.Logger) (builtinTunnel, error) {
	k, ok := kindOf(req.Profile.Kind)
	if !ok {
		return nil, errUnknownKind(req.Profile.Kind)
	}
	return k.start(ctx, req, logger)
}

// healthPolicyFor is the health policy of a kind. A kind the registry lacks gets
// the shortest one, so a stale profile is never left unwatched.
func healthPolicyFor(kind string) healthPolicy {
	if k, ok := kindOf(kind); ok {
		return k.healthPolicy()
	}
	return wireguardKind{}.healthPolicy()
}

// defaultProfileName names a profile whose request gave no name: the secret's
// own label when it is usable, else the kind's name.
func defaultProfileName(kind, label string) string {
	if label = strings.TrimSpace(label); label != "" && config.ValidateProfileName(label) == nil {
		return label
	}
	if k, ok := kindOf(kind); ok {
		return k.displayName()
	}
	return "VPN"
}

// secretForKind picks the secret out of a request and checks it is the one
// the profile kind uses.
func secretForKind(kind, wireguardConfig, accessKey string) (string, error) {
	k, ok := kindOf(kind)
	if !ok {
		return "", fmt.Errorf("%w: kind must be %q or %q", api.ErrRejected, config.ProfileKindWireGuard, config.ProfileKindOutline)
	}
	return k.pickSecret(wireguardConfig, accessKey)
}

// validateSecret parses a secret as the given kind of profile would use it,
// without starting anything, and returns the metadata it implies: the DNS
// servers a WireGuard .conf names, or the tag of an Outline key. The error
// never contains the secret.
func validateSecret(kind, secret string) (dns []string, label string, err error) {
	k, ok := kindOf(kind)
	if !ok {
		return nil, "", errUnknownKind(kind)
	}
	return k.validateSecret(secret)
}

// redact removes the secret and its sensitive parts from an error text before
// it can reach an RPC response, a log line, or the activity log. The tunnel
// packages already keep secrets out of their errors; this is the second wall.
func redact(text, kind, secret string) string {
	for _, tok := range secretTokens(kind, secret) {
		text = strings.ReplaceAll(text, tok, "[redacted]")
	}
	return text
}

// secretTokens lists the strings that must never appear in output: the whole
// secret and the kind's sensitive parts of it (a WireGuard key line's value, an
// Outline key's password).
func secretTokens(kind, secret string) []string {
	var out []string
	add := func(s string) {
		if s = strings.TrimSpace(s); len(s) >= 6 {
			out = append(out, s)
		}
	}
	add(secret)
	if k, ok := kindOf(kind); ok {
		for _, tok := range k.redactionTokens(secret) {
			add(tok)
		}
	}
	return out
}

// checkProfileUnique rejects a secret that another profile of the same kind
// already uses where the kind requires uniqueness. selfID is the profile being
// updated, which may keep its own values. The error names the other profile and
// never the secret. Stored secrets are read only to compare them; an unreadable
// one is skipped.
func (d *Daemon) checkProfileUnique(selfID, kind, secret string) error {
	k, ok := kindOf(kind)
	if !ok || d.secrets == nil {
		return nil
	}
	return k.checkUnique(secret, func() []profileSecret {
		var out []profileSecret
		for _, other := range d.store.Profiles() {
			if other.ID == selfID || other.Kind != kind {
				continue
			}
			stored, err := d.secrets.ProfileSecret(other.ID)
			if err != nil {
				continue
			}
			out = append(out, profileSecret{name: other.Name, secret: stored})
		}
		return out
	})
}

// reservedAddrCollides builds the test the synthetic-address allocator uses: an
// address is taken when it lies on a directly connected network or is the
// interface address of a profile whose kind reserves one. Stored secrets are
// read only to compare them; an unreadable or unparseable one is skipped.
func (d *Daemon) reservedAddrCollides() func(netip.Addr) bool {
	prefixes := d.hooks.localPrefixes()
	reserved := make(map[netip.Addr]bool)
	if d.secrets != nil {
		for _, p := range d.store.Profiles() {
			k, ok := kindOf(p.Kind)
			if !ok {
				continue
			}
			for _, a := range k.reservedAddrs(func() (string, error) { return d.secrets.ProfileSecret(p.ID) }) {
				reserved[a] = true
			}
		}
	}
	return func(a netip.Addr) bool {
		if reserved[a] {
			return true
		}
		for _, p := range prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
}
