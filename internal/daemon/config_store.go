package daemon

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
)

// ErrPersistFailed marks a mutation that was validated and accepted but could not
// be written to disk. It is a helper-side fault, not a bad request, and the
// in-memory config is left untouched when it occurs.
var ErrPersistFailed = errors.New("could not persist configuration")

// ErrStaleRevision reports that a caller's expected revision no longer matches
// the store, meaning another mutation landed first.
type ErrStaleRevision struct {
	Expected uint64
	Actual   uint64
}

func (e *ErrStaleRevision) Error() string {
	return fmt.Sprintf("config changed since revision %d (now %d)", e.Expected, e.Actual)
}

// ConfigStore is the single owner of daemon configuration. It hands out only
// immutable deep copies, serializes every mutation, and persists each accepted
// change before it becomes visible. No other component may hold a *config.Config
// that the store also writes to.
//
// Readers never take mu: every commit publishes a compiled routingPolicy, and
// the read methods answer from it. mu therefore serializes writers only, so a
// slow save (SQLite and its backup copy) never stalls a DNS query or a captured
// flow.
type ConfigStore struct {
	mu      sync.Mutex
	cfg     *config.Config
	persist config.Persister
	// revision increases on every accepted mutation so callers can detect that
	// the snapshot they reasoned about is no longer current.
	revision uint64
	// policy is the compiled view of cfg at revision, replaced after each commit.
	policy atomic.Pointer[routingPolicy]
	// onCommit, when set, is told of every committed configuration while mu is
	// held, so it must return quickly. It is set once before the store is shared.
	onCommit func(*config.Config)
}

// OnCommit registers fn to be called with each configuration the store commits.
// Call it before the store is used concurrently.
func (s *ConfigStore) OnCommit(fn func(*config.Config)) { s.onCommit = fn }

// NewConfigStore takes ownership of cfg. persist saves every accepted change;
// nil keeps the config in memory only.
func NewConfigStore(cfg *config.Config, persist config.Persister) *ConfigStore {
	owned := cfg.Clone()
	owned.ApplyDefaults()
	owned.Domains = config.NormalizeDomains(owned.Domains)
	for i := range owned.VPNs {
		owned.VPNs[i].Domains = config.NormalizeDomains(owned.VPNs[i].Domains)
	}
	// Revisions start at 1 so zero can mean "caller stated no expectation".
	s := &ConfigStore{cfg: owned, persist: persist, revision: 1}
	s.policy.Store(newRoutingPolicy(owned, s.revision, nil))
	return s
}

// Policy returns the compiled routing policy of the current configuration. The
// result is immutable and may be read without any lock.
func (s *ConfigStore) Policy() *routingPolicy { return s.policy.Load() }

// Snapshot returns an immutable copy of the current config and its revision.
func (s *ConfigStore) Snapshot() (*config.Config, uint64) {
	p := s.policy.Load()
	return p.cfg.Clone(), p.revision
}

// Revision returns the current revision without copying the config.
func (s *ConfigStore) Revision() uint64 { return s.policy.Load().revision }

// Domains returns a copy of the Any VPN domain patterns.
func (s *ConfigStore) Domains() []string {
	list, _ := s.DomainList(config.AnyVPN)
	return list
}

// AllPatterns returns every configured pattern across every list.
func (s *ConfigStore) AllPatterns() []string {
	return slices.Clone(s.policy.Load().patterns)
}

// DomainList returns a copy of one list's patterns: a VPN client's, or the
// Any VPN list for config.AnyVPN.
func (s *ConfigStore) DomainList(client string) ([]string, error) {
	l, ok := s.policy.Load().list(client)
	if !ok {
		return nil, fmt.Errorf("VPN client %q is not allowed", client)
	}
	return slices.Clone(l.patterns), nil
}

// AddDomain appends a pattern to a list if it is not already present.
func (s *ConfigStore) AddDomain(client, pattern string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	rules, ok := next.DomainList(client)
	if !ok {
		return s.revision, fmt.Errorf("VPN client %q is not allowed", client)
	}
	before := len(rules)
	next.SetDomainList(client, append(slices.Clone(rules), config.DomainRule{Pattern: pattern}))
	if after, _ := next.DomainList(client); len(after) == before {
		return s.revision, fmt.Errorf("domain %q already exists", pattern)
	}
	if err := s.commitLocked(next); err != nil {
		return s.revision, err
	}
	return s.revision, nil
}

// RemoveDomain drops a pattern from a list. Removing the last pattern of the
// whole configuration is rejected, because an empty configuration is invalid.
func (s *ConfigStore) RemoveDomain(client, pattern string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	normalized := config.NormalizeDomains([]config.DomainRule{{Pattern: pattern}})
	if len(normalized) == 0 {
		return s.revision, fmt.Errorf("domain pattern is empty")
	}
	target := normalized[0].Pattern

	next := s.cfg.Clone()
	rules, ok := next.DomainList(client)
	if !ok {
		return s.revision, fmt.Errorf("VPN client %q is not allowed", client)
	}
	kept := slices.DeleteFunc(slices.Clone(rules), func(d config.DomainRule) bool { return d.Pattern == target })
	if len(kept) == len(rules) {
		return s.revision, fmt.Errorf("domain %q not found", pattern)
	}
	next.SetDomainList(client, kept)
	if err := s.commitLocked(next); err != nil {
		return s.revision, err
	}
	return s.revision, nil
}

// SetDomains replaces one list in one mutation. A non-zero expectedRevision
// makes the write conditional, so a client that edited a stale snapshot is
// rejected instead of silently discarding a concurrent change.
func (s *ConfigStore) SetDomains(client string, patterns []string, expectedRevision uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if expectedRevision != 0 && expectedRevision != s.revision {
		return s.revision, &ErrStaleRevision{Expected: expectedRevision, Actual: s.revision}
	}

	rules := make([]config.DomainRule, 0, len(patterns))
	for _, p := range patterns {
		rules = append(rules, config.DomainRule{Pattern: p})
	}
	next := s.cfg.Clone()
	if !next.SetDomainList(client, rules) {
		return s.revision, fmt.Errorf("VPN client %q is not allowed", client)
	}
	if err := s.commitLocked(next); err != nil {
		return s.revision, err
	}
	return s.revision, nil
}

// update applies change to a copy of the configuration and commits it. change reports
// whether anything changed: a no-op must not bump the revision, or it would invalidate
// a client's pending conditional domains.set. An error from change commits nothing.
func (s *ConfigStore) update(change func(next *config.Config) (changed bool, err error)) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	changed, err := change(next)
	if err != nil || !changed {
		return s.revision, err
	}
	if err := s.commitLocked(next); err != nil {
		return s.revision, err
	}
	return s.revision, nil
}

// setField is update for one comparable field.
func setField[T comparable](s *ConfigStore, field func(*config.Config) *T, value T) (uint64, error) {
	return s.update(func(next *config.Config) (bool, error) {
		target := field(next)
		if *target == value {
			return false, nil
		}
		*target = value
		return true, nil
	})
}

// SetUseVPNDNS saves dns.use_vpn_dns.
func (s *ConfigStore) SetUseVPNDNS(enabled bool) (uint64, error) {
	return setField(s, func(c *config.Config) *bool { return &c.DNS.UseVPNDNS }, enabled)
}

// SetAllowIPv6 saves routing.allow_ipv6.
func (s *ConfigStore) SetAllowIPv6(allowed bool) (uint64, error) {
	return setField(s, func(c *config.Config) *bool { return &c.Routing.AllowIPv6 }, allowed)
}

// SetDefaultVPN saves routing.default_vpn and routing.default_vpn_fallback.
func (s *ConfigStore) SetDefaultVPN(client, fallback string) (uint64, error) {
	return s.update(func(next *config.Config) (bool, error) {
		if next.Routing.DefaultVPN == client && next.Routing.DefaultVPNFallback == fallback {
			return false, nil
		}
		next.Routing.DefaultVPN, next.Routing.DefaultVPNFallback = client, fallback
		return true, nil
	})
}

// SetDefaultVPNExcept saves routing.default_vpn_except, normalized the way a domain
// list is. A list that changes nothing does not bump the revision.
func (s *ConfigStore) SetDefaultVPNExcept(patterns []string) (uint64, error) {
	rules := make([]config.DomainRule, 0, len(patterns))
	for _, p := range patterns {
		rules = append(rules, config.DomainRule{Pattern: p})
	}
	normalized := make([]string, 0, len(patterns))
	for _, r := range config.NormalizeDomains(rules) {
		normalized = append(normalized, r.Pattern)
	}
	return s.update(func(next *config.Config) (bool, error) {
		if slices.Equal(next.Routing.DefaultVPNExcept, normalized) {
			return false, nil
		}
		next.Routing.DefaultVPNExcept = normalized
		return true, nil
	})
}

// SetHistory saves history.enabled and history.retention_days; a nil argument
// keeps the stored value. A request that changes nothing does not bump the
// revision.
func (s *ConfigStore) SetHistory(enabled *bool, retentionDays *int) (uint64, error) {
	return s.update(func(next *config.Config) (bool, error) {
		before := next.History
		if enabled != nil {
			next.History.Enabled = *enabled
		}
		if retentionDays != nil {
			if err := config.ValidateHistoryRetention(*retentionDays); err != nil {
				return false, err
			}
			next.History.RetentionDays = *retentionDays
		}
		return next.History != before, nil
	})
}

// Telemetry returns the error-reporting settings.
func (s *ConfigStore) Telemetry() config.TelemetryConfig {
	return s.policy.Load().cfg.Telemetry
}

// SetTelemetry applies the settings p names and keeps the rest. A request that
// changes nothing does not bump the revision. An invalid value is rejected as a
// whole, without echoing the DSN.
func (s *ConfigStore) SetTelemetry(p api.SetTelemetryParams) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	t := &next.Telemetry
	if p.DSN != nil {
		t.DSN = *p.DSN
	}
	if p.Errors != nil {
		t.Errors = *p.Errors
	}
	if p.Sessions != nil {
		t.Sessions = *p.Sessions
	}
	if p.Logs != nil {
		t.Logs = *p.Logs
	}
	if p.Traces != nil {
		t.Traces = *p.Traces
	}
	if p.TracesSampleRate != nil {
		t.TracesSampleRate = *p.TracesSampleRate
	}
	if *t == s.cfg.Telemetry {
		return s.revision, nil
	}
	if err := s.commitLocked(next); err != nil {
		return s.revision, err
	}
	return s.revision, nil
}

// AllowedVPNClients returns the executable paths of the VPN clients RouteWise
// may manage, in priority order.
func (s *ConfigStore) AllowedVPNClients() []string {
	return slices.Clone(s.policy.Load().allowed)
}

// SetVPNClientAllowed adds a VPN client to the allowlist, last in priority, or
// removes it together with its domain list.
func (s *ConfigStore) SetVPNClientAllowed(id string, allowed bool) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id == "" {
		return s.revision, fmt.Errorf("VPN client id is empty")
	}
	present := slices.Contains(s.cfg.AllowedClients(), id)
	if present == allowed {
		return s.revision, nil
	}
	// A built-in VPN is allowed while its profile exists and no longer once it
	// is removed, so the allowlist cannot disagree with the profile list.
	if config.IsBuiltinClient(id) {
		return s.revision, fmt.Errorf("built-in VPN %q is allowed by its profile and cannot be allowed or revoked here", id)
	}
	next := s.cfg.Clone()
	if allowed {
		next.VPNs = append(next.VPNs, config.VPNRoute{Client: id})
	} else {
		next.VPNs = slices.DeleteFunc(next.VPNs, func(v config.VPNRoute) bool { return v.Client == id })
	}
	if err := s.commitLocked(next); err != nil {
		return s.revision, err
	}
	return s.revision, nil
}

// Profiles returns a copy of the built-in VPN profiles.
func (s *ConfigStore) Profiles() []config.TunnelProfile {
	p := s.policy.Load()
	out := make([]config.TunnelProfile, len(p.profiles))
	for i, pr := range p.profiles {
		pr.DNS = slices.Clone(pr.DNS)
		out[i] = pr
	}
	return out
}

// Profile returns one profile.
func (s *ConfigStore) Profile(id string) (config.TunnelProfile, bool) {
	return s.policy.Load().profileByID(id)
}

// AddProfile appends a profile and gives it a VPN client entry, last in
// priority, so it can hold a domain list.
func (s *ConfigStore) AddProfile(p config.TunnelProfile) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	next.Profiles = append(next.Profiles, p)
	next.EnsureProfileVPNs()
	if err := s.commitValidatedLocked(next, next.ValidateAllowingNoDomains); err != nil {
		return s.revision, err
	}
	return s.revision, nil
}

// UpdateProfile applies change to one profile. A change that leaves the
// profile as it was does not bump the revision.
func (s *ConfigStore) UpdateProfile(id string, change func(*config.TunnelProfile) error) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	i := slices.IndexFunc(next.Profiles, func(p config.TunnelProfile) bool { return p.ID == id })
	if i < 0 {
		return s.revision, fmt.Errorf("profile %q does not exist", id)
	}
	before := next.Profiles[i]
	before.DNS = slices.Clone(before.DNS)
	if err := change(&next.Profiles[i]); err != nil {
		return s.revision, err
	}
	after := next.Profiles[i]
	if before.Name == after.Name && before.AutoConnect == after.AutoConnect && slices.Equal(before.DNS, after.DNS) {
		return s.revision, nil
	}
	if err := s.commitValidatedLocked(next, next.ValidateAllowingNoDomains); err != nil {
		return s.revision, err
	}
	return s.revision, nil
}

// RemoveProfile deletes a profile together with its VPN client entry and
// that entry's domain list.
func (s *ConfigStore) RemoveProfile(id string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	p, ok := next.Profile(id)
	if !ok {
		return s.revision, fmt.Errorf("profile %q does not exist", id)
	}
	next.Profiles = slices.DeleteFunc(next.Profiles, func(q config.TunnelProfile) bool { return q.ID == id })
	next.VPNs = slices.DeleteFunc(next.VPNs, func(v config.VPNRoute) bool { return v.Client == p.ClientID() })
	if err := s.commitValidatedLocked(next, next.ValidateAllowingNoDomains); err != nil {
		return s.revision, err
	}
	return s.revision, nil
}

// Replace swaps in an imported routing configuration: domain lists, allowed
// VPN clients, DNS, and routing mode. The daemon section is machine-specific
// and is kept from the current configuration.
func (s *ConfigStore) Replace(imported *config.Config) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := imported.Clone()
	next.EnsureProfileVPNs()
	next.Daemon = s.cfg.Daemon
	next.Domains = config.NormalizeDomains(next.Domains)
	for i := range next.VPNs {
		next.VPNs[i].Domains = config.NormalizeDomains(next.VPNs[i].Domains)
	}
	if err := s.commitLocked(next); err != nil {
		return s.revision, err
	}
	return s.revision, nil
}

// commitLocked validates, persists, and only then publishes the new config, so a
// rejected or unwritable change leaves the in-memory state untouched.
func (s *ConfigStore) commitLocked(next *config.Config) error {
	return s.commitValidatedLocked(next, next.Validate)
}

// commitValidatedLocked is commitLocked with the validation to apply. Profile
// changes use ValidateAllowingNoDomains: importing the first built-in VPN into
// a store that holds no domain yet is legitimate.
func (s *ConfigStore) commitValidatedLocked(next *config.Config, validate func() error) error {
	next.ApplyDefaults()
	if n := next.PatternCount(); n > config.MaxDomainPatterns {
		return fmt.Errorf("too many domain patterns: %d (max %d)", n, config.MaxDomainPatterns)
	}
	if err := validate(); err != nil {
		return err
	}
	if s.persist != nil {
		if err := s.persist.Save(next); err != nil {
			return fmt.Errorf("%w: %w", ErrPersistFailed, err)
		}
	}
	s.cfg = next
	s.revision++
	s.policy.Store(newRoutingPolicy(next, s.revision, s.policy.Load()))
	if s.onCommit != nil {
		s.onCommit(next)
	}
	return nil
}
