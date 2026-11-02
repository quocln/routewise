package config

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// ExportFormat and ExportVersion identify a RouteWise config export.
const (
	ExportFormat  = "routewise-config"
	ExportVersion = 1
)

// Export is the portable form of the routing configuration: domain lists,
// allowed VPN clients, DNS, routing mode, and history settings. The daemon section (pid file,
// log file, poll interval) is machine-specific and never leaves the machine.
type Export struct {
	Format     string        `json:"format"`
	Version    int           `json:"version"`
	ExportedAt time.Time     `json:"exportedAt"`
	DNS        ExportDNS     `json:"dns"`
	Routing    ExportRouting `json:"routing"`
	// Domains route through the highest-priority connected VPN.
	Domains []string `json:"domains"`
	// VPNs are the allowed VPN clients in priority order, each with domains
	// that go only through it.
	VPNs []ExportVPN `json:"vpns"`
	// History is absent in exports made before access history existed; an
	// import without it means the defaults.
	History *ExportHistory `json:"history,omitempty"`
	// Profiles are the built-in VPNs (metadata only). Secrets are never
	// exported: an imported profile has none until the user adds one.
	Profiles []ExportProfile `json:"profiles,omitempty"`
}

// ExportProfile is the metadata of one built-in VPN profile.
type ExportProfile struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	AutoConnect bool     `json:"autoConnect"`
	DNS         []string `json:"dns"`
}

// ExportHistory is the access history part of an export.
type ExportHistory struct {
	Enabled       bool `json:"enabled"`
	RetentionDays int  `json:"retentionDays"`
}

// ExportDNS is the DNS part of an export.
type ExportDNS struct {
	Servers   []string `json:"servers"`
	CacheTTL  int      `json:"cacheTtl"`
	UseVPNDNS bool     `json:"useVpnDns"`
}

// ExportRouting is the routing part of an export.
type ExportRouting struct {
	Mode      RoutingMode `json:"mode"`
	AllowIPv6 bool        `json:"allowIpv6"`
	// DefaultVPN and DefaultVPNFallback are client IDs. An import that does not
	// also allow the client drops them.
	DefaultVPN         string `json:"defaultVpn,omitempty"`
	DefaultVPNFallback string `json:"defaultVpnFallback,omitempty"`
}

// ExportVPN is one allowed VPN client and its domains.
type ExportVPN struct {
	// Client is the executable path that identifies the VPN client.
	Client  string   `json:"client"`
	Domains []string `json:"domains"`
}

// NewExport captures cfg for export.
func NewExport(cfg *Config, now time.Time) Export {
	e := Export{
		Format:     ExportFormat,
		Version:    ExportVersion,
		ExportedAt: now.UTC(),
		DNS: ExportDNS{
			Servers:   slices.Clone(cfg.DNS.Servers),
			CacheTTL:  cfg.DNS.CacheTTL,
			UseVPNDNS: cfg.DNS.UseVPNDNS,
		},
		Routing: ExportRouting{
			Mode:               cfg.Routing.Mode,
			AllowIPv6:          cfg.Routing.AllowIPv6,
			DefaultVPN:         cfg.Routing.DefaultVPN,
			DefaultVPNFallback: cfg.Routing.DefaultVPNFallback,
		},
		Domains: rulePatterns(cfg.Domains),
		VPNs:    make([]ExportVPN, 0, len(cfg.VPNs)),
		History: &ExportHistory{Enabled: cfg.History.Enabled, RetentionDays: cfg.History.RetentionDays},
	}
	for _, v := range cfg.VPNs {
		e.VPNs = append(e.VPNs, ExportVPN{Client: v.Client, Domains: rulePatterns(v.Domains)})
	}
	for _, p := range cfg.Profiles {
		e.Profiles = append(e.Profiles, ExportProfile{
			ID: p.ID, Kind: p.Kind, Name: p.Name, AutoConnect: p.AutoConnect, DNS: slices.Clone(p.DNS),
		})
	}
	return e
}

// ParseExport decodes and checks an export file.
func ParseExport(data []byte) (Export, error) {
	var e Export
	if err := json.Unmarshal(data, &e); err != nil {
		return Export{}, fmt.Errorf("not a RouteWise config export: %w", err)
	}
	if e.Format != ExportFormat {
		return Export{}, fmt.Errorf("not a RouteWise config export (format %q)", e.Format)
	}
	if e.Version < 1 || e.Version > ExportVersion {
		return Export{}, fmt.Errorf("config export version %d is not supported (this RouteWise reads up to %d)", e.Version, ExportVersion)
	}
	return e, nil
}

// Apply returns base with the exported routing configuration in place of its
// own, keeping base's daemon section, and validates the result.
func (e Export) Apply(base *Config) (*Config, error) {
	next := base.Clone()
	next.DNS = DNSConfig{Servers: slices.Clone(e.DNS.Servers), CacheTTL: e.DNS.CacheTTL, UseVPNDNS: e.DNS.UseVPNDNS}
	next.Routing.Mode = e.Routing.Mode
	next.Routing.AllowIPv6 = e.Routing.AllowIPv6
	next.Routing.DefaultVPN = e.Routing.DefaultVPN
	next.Routing.DefaultVPNFallback = e.Routing.DefaultVPNFallback
	next.History = DefaultConfig().History
	if e.History != nil {
		next.History = HistoryConfig{Enabled: e.History.Enabled, RetentionDays: e.History.RetentionDays}
	}
	next.Domains = NormalizeDomains(patternRules(e.Domains))
	next.VPNs = make([]VPNRoute, 0, len(e.VPNs))
	for _, v := range e.VPNs {
		next.VPNs = append(next.VPNs, VPNRoute{Client: v.Client, Domains: NormalizeDomains(patternRules(v.Domains))})
	}
	next.Profiles = nil
	for _, p := range e.Profiles {
		dns, err := NormalizeProfileDNS(p.DNS)
		if err != nil {
			return nil, fmt.Errorf("invalid config export: profile %q: %w", p.Name, err)
		}
		next.Profiles = append(next.Profiles, TunnelProfile{
			ID: p.ID, Kind: p.Kind, Name: p.Name, AutoConnect: p.AutoConnect, DNS: dns,
		})
	}
	// An export that lists a profile but not its client entry (a hand-edited
	// file) still gets one, so the profile can hold a list.
	next.EnsureProfileVPNs()
	if n := next.PatternCount(); n > MaxDomainPatterns {
		return nil, fmt.Errorf("too many domain patterns: %d (max %d)", n, MaxDomainPatterns)
	}
	next.ApplyDefaults()
	if err := next.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config export: %w", err)
	}
	return next, nil
}

// NeedsRestart reports whether moving from current to next changes a setting
// the running helper only reads at start: DNS servers, cache TTL, or the
// routing mode.
func NeedsRestart(current, next *Config) bool {
	return !slices.Equal(current.DNS.Servers, next.DNS.Servers) ||
		current.DNS.CacheTTL != next.DNS.CacheTTL ||
		current.Routing.Mode != next.Routing.Mode
}

func rulePatterns(rules []DomainRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Pattern)
	}
	return out
}

func patternRules(patterns []string) []DomainRule {
	out := make([]DomainRule, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, DomainRule{Pattern: p})
	}
	return out
}
