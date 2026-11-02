package resolverfiles

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// nrptBackend is the Windows side of the NRPT configurator: the registry and
// the DNS client service. nrpt_backend_windows.go implements it; tests supply
// their own.
type nrptBackend interface {
	// OwnedRules lists the keys of the rules RouteWise wrote.
	OwnedRules() ([]string, error)
	// WriteRule creates the rule's key if it is missing and sets its values.
	WriteRule(key string, values []regValue) error
	// DeleteRule removes the rule's key. A key that is already gone is not an
	// error.
	DeleteRule(key string) error
	// PolicyManaged reports whether Group Policy defines NRPT rules, in which
	// case Windows ignores every local rule.
	PolicyManaged() (bool, error)
	// Reload makes the DNS client read its rules again and drops cached answers.
	Reload() error
}

// ErrPolicyManaged is returned by Apply when Group Policy owns the NRPT. The
// DNS client then ignores local rules, so no split DNS is in effect.
var ErrPolicyManaged = errors.New("Group Policy defines Name Resolution Policy Table rules, so Windows ignores local ones")

var _ Configurator = (*NRPT)(nil)

// NRPT is the Windows implementation of Configurator. It writes one rule per
// forwarded domain that sends the domain (and everything under it) to the
// local forwarder, and leaves every other name on the system's normal path.
// Windows takes no port in a rule, so the forwarder must listen on port 53.
//
// Every Apply writes the full state again. The DNS client loses rules when it
// reconfigures during network changes, and the daemon applies on every sync,
// so a lost rule comes back at the next one.
type NRPT struct {
	backend nrptBackend
	server  netip.Addr
	// cfgErr is why Apply cannot work, from a forwarder address NRPT cannot
	// express. RemoveAll still works.
	cfgErr error
	logger *slog.Logger

	mu     sync.Mutex
	active []string // domains whose rules the DNS client has loaded
	loaded []string // the domains of the last successful Reload; nil when unknown
}

func newNRPT(backend nrptBackend, nameserver string, port int) *NRPT {
	n := &NRPT{backend: backend, logger: slog.Default()}
	addr, err := netip.ParseAddr(nameserver)
	switch {
	case err != nil:
		n.cfgErr = fmt.Errorf("forwarder address %q: %w", nameserver, err)
	case port != 53:
		n.cfgErr = fmt.Errorf("the Name Resolution Policy Table cannot name port %d: the forwarder must listen on port 53", port)
	default:
		n.server = addr
	}
	return n
}

// Active returns the domains the DNS client sends to the forwarder.
func (n *NRPT) Active() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.active)
}

// Apply makes the forwarded domains equal to domains. An empty set removes
// every rule. The NRPT takes any domain, so nothing is skipped. When Group
// Policy owns the table, RouteWise's rules are removed and ErrPolicyManaged is
// returned.
func (n *NRPT) Apply(domains []string) (skipped []string, err error) {
	if n.cfgErr != nil {
		return nil, n.cfgErr
	}
	want := make(map[string]bool, len(domains))
	for _, d := range domains {
		d = strings.ToLower(d)
		if !domainRegex.MatchString(d) {
			return nil, fmt.Errorf("resolver domain %q is not a valid domain name", d)
		}
		want[d] = true
	}
	sorted := sortedKeys(want)

	n.mu.Lock()
	defer n.mu.Unlock()
	if len(sorted) == 0 {
		return nil, n.removeLocked()
	}

	managed, err := n.backend.PolicyManaged()
	if err != nil {
		// Unknown is treated as not managed: the rules are harmless if
		// ignored, and refusing would disable split DNS on a read failure.
		n.logger.Warn("could not check Group Policy for NRPT rules", "error", err)
	} else if managed {
		if err := n.removeLocked(); err != nil {
			return nil, err
		}
		return nil, ErrPolicyManaged
	}
	return nil, n.writeLocked(sorted)
}

// RemoveAll deletes every rule RouteWise owns, including ones a previous
// process left behind.
func (n *NRPT) RemoveAll() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.removeLocked()
}

// writeLocked brings the registry to exactly one rule per domain and reloads
// the DNS client when what it loaded differs from that.
func (n *NRPT) writeLocked(domains []string) error {
	owned, err := n.backend.OwnedRules()
	if err != nil {
		return fmt.Errorf("list NRPT rules: %w", err)
	}
	wantKeys := make(map[string]string, len(domains)) // key -> domain
	for _, d := range domains {
		wantKeys[nrptRuleKey(d)] = d
	}

	var errs []error
	changed := n.loaded == nil || !slices.Equal(n.loaded, domains)
	for _, key := range owned {
		if _, keep := wantKeys[key]; !keep {
			changed = true
			if err := n.backend.DeleteRule(key); err != nil {
				errs = append(errs, err)
			}
		}
	}
	var written []string
	for _, d := range domains {
		key := nrptRuleKey(d)
		if !slices.Contains(owned, key) {
			changed = true // a rule the DNS client may never have read
		}
		if err := n.backend.WriteRule(key, nrptRule{domain: d, server: n.server}.values()); err != nil {
			errs = append(errs, fmt.Errorf("write NRPT rule for %s: %w", d, err))
			changed = true
			continue
		}
		written = append(written, d)
	}
	if len(errs) > 0 {
		n.loaded = nil
	}
	if changed || len(errs) > 0 {
		if err := n.backend.Reload(); err != nil {
			n.loaded, n.active = nil, nil
			return fmt.Errorf("reload the DNS client: %w", errors.Join(append(errs, err)...))
		}
		if len(errs) == 0 {
			n.loaded = slices.Clone(domains)
		}
	}
	n.active = written
	if len(errs) > 0 {
		return fmt.Errorf("apply NRPT rules: %w", errors.Join(errs...))
	}
	return nil
}

func (n *NRPT) removeLocked() error {
	n.active, n.loaded = nil, nil
	owned, err := n.backend.OwnedRules()
	if err != nil {
		return fmt.Errorf("list NRPT rules: %w", err)
	}
	if len(owned) == 0 {
		return nil
	}
	var errs []error
	for _, key := range owned {
		if err := n.backend.DeleteRule(key); err != nil {
			errs = append(errs, err)
		}
	}
	// Reload even after a failed delete: the rules that did go must leave the
	// DNS client too.
	if err := n.backend.Reload(); err != nil {
		errs = append(errs, fmt.Errorf("reload the DNS client: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("remove NRPT rules: %w", errors.Join(errs...))
	}
	return nil
}
