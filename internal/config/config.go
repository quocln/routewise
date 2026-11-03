// Package config handles configuration loading and validation for the VPN routing daemon.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	yaml "go.yaml.in/yaml/v3"

	"github.com/quocln/routewise/internal/platform"
)

// ValidLogLevels defines allowed log level values.
var ValidLogLevels = map[string]bool{
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
}

// domainPatternRegex validates domain patterns. A pattern is either an exact
// name (example.com) or a wildcard whose single '*' sits in the first label
// (*.example.com, qa*.example.com). A wildcard must leave at least two labels
// after it: RouteWise installs a resolver for that suffix, and a suffix such as
// "com" would capture every lookup under a whole top-level domain.
var domainPatternRegex = regexp.MustCompile(
	`^(?:[a-zA-Z0-9-]*\*[a-zA-Z0-9-]*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*)[a-zA-Z]{2,}$`,
)

// RoutingMode defines how RouteWise manages routes relative to other VPN clients.
type RoutingMode string

const (
	// RoutingModeInverted replaces VPN catch-all routes with local gateway,
	// then adds /32 routes only for configured domains. All other traffic goes direct.
	// Use when RouteWise is the only VPN route manager.
	RoutingModeInverted RoutingMode = "inverted"

	// RoutingModeAdditive keeps existing VPN routes intact and only adds /32 routes
	// for configured domains as insurance. Use when coexisting with another VPN client
	// (e.g., AWS Client VPN) that manages its own routing.
	RoutingModeAdditive RoutingMode = "additive"
)

// Config represents the complete daemon configuration.
type Config struct {
	// Domains route through the highest-priority connected VPN ("Any VPN").
	Domains []DomainRule `yaml:"domains" mapstructure:"domains"`
	// VPNs are the VPN clients RouteWise may manage, in priority order, each
	// with domains that route only through that VPN. A full-tunnel VPN from
	// a client not listed here is left alone.
	VPNs []VPNRoute `yaml:"vpns,omitempty" mapstructure:"vpns"`
	// Profiles are the built-in VPNs (WireGuard, Outline) the helper runs
	// itself. Each has a VPN client entry in VPNs under its client ID. Their
	// secrets are never part of the configuration.
	Profiles []TunnelProfile `yaml:"profiles,omitempty" mapstructure:"profiles"`
	DNS      DNSConfig       `yaml:"dns" mapstructure:"dns"`
	Daemon   DaemonConfig    `yaml:"daemon" mapstructure:"daemon"`
	Routing  RoutingConfig   `yaml:"routing" mapstructure:"routing"`
	// History controls the record of outbound connections.
	History HistoryConfig `yaml:"history" mapstructure:"history"`
	// Telemetry controls error reporting. Its DSN is never exported.
	Telemetry TelemetryConfig `yaml:"telemetry" mapstructure:"telemetry"`
}

// Bounds of history.retention_days.
const (
	MinHistoryRetentionDays     = 1
	MaxHistoryRetentionDays     = 90
	DefaultHistoryRetentionDays = 7
)

// HistoryConfig holds the access history settings.
type HistoryConfig struct {
	// Enabled records every new outbound connection. On by default.
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// RetentionDays is how long records are kept: 1 to 90, 7 by default.
	RetentionDays int `yaml:"retention_days" mapstructure:"retention_days"`
}

// ValidateHistoryRetention checks a retention in days.
func ValidateHistoryRetention(days int) error {
	if days < MinHistoryRetentionDays || days > MaxHistoryRetentionDays {
		return fmt.Errorf("history.retention_days must be between %d and %d, got %d",
			MinHistoryRetentionDays, MaxHistoryRetentionDays, days)
	}
	return nil
}

// RoutingConfig holds routing behavior settings.
type RoutingConfig struct {
	// Mode controls how RouteWise interacts with other VPN clients.
	// "inverted" (default): removes VPN catch-all routes, only configured domains go through VPN.
	// "additive": keeps VPN routes intact, adds /32 routes for configured domains alongside.
	Mode RoutingMode `yaml:"mode" mapstructure:"mode"`
	// AllowIPv6 lets IPv6 traffic to listed names leave directly. RouteWise
	// routes IPv4 only, so while it is off (the default) the IPv6 addresses of
	// listed names are made unreachable and apps connect over IPv4.
	AllowIPv6 bool `yaml:"allow_ipv6" mapstructure:"allow_ipv6"`
	// DefaultVPN is the client ID of the allowed VPN that carries traffic no
	// connected VPN's list claims. Empty leaves that traffic direct. It only
	// applies in inverted mode.
	DefaultVPN string `yaml:"default_vpn,omitempty" mapstructure:"default_vpn"`
	// DefaultVPNFallback is the client ID of the allowed VPN that takes over
	// while DefaultVPN is down. Empty sends that traffic direct.
	DefaultVPNFallback string `yaml:"default_vpn_fallback,omitempty" mapstructure:"default_vpn_fallback"`
	// DefaultVPNExcept lists the domains, wildcards, IPs and networks that go
	// direct instead of through the default VPN. A VPN list that claims one
	// still wins while that VPN is connected.
	DefaultVPNExcept []string `yaml:"default_vpn_except,omitempty" mapstructure:"default_vpn_except"`
}

// ExceptRules returns DefaultVPNExcept as list entries.
func (r RoutingConfig) ExceptRules() []DomainRule { return patternRules(r.DefaultVPNExcept) }

// VPNRoute is an allowed VPN client and the domains that go only through it.
// When that VPN is not connected, its domains go direct.
type VPNRoute struct {
	// Client is the client's executable path, as vpnclient identifies it.
	Client  string       `yaml:"client" mapstructure:"client"`
	Domains []DomainRule `yaml:"domains,omitempty" mapstructure:"domains"`
}

// KernelWireGuardClient is the client ID of a kernel WireGuard link on Linux.
// The link has no owning process (wg-quick, NetworkManager or
// systemd-networkd create it and exit), so it has no executable path.
const KernelWireGuardClient = "wireguard:kernel"

// AnyVPN names the domain list that is not tied to one VPN client.
const AnyVPN = ""

// AllowedClients returns the allowed VPN clients in priority order.
func (c *Config) AllowedClients() []string {
	out := make([]string, 0, len(c.VPNs))
	for _, v := range c.VPNs {
		out = append(out, v.Client)
	}
	return out
}

// DomainList returns the domain list for a VPN client, or the Any VPN list
// for AnyVPN, and whether that list exists.
func (c *Config) DomainList(client string) ([]DomainRule, bool) {
	if client == AnyVPN {
		return c.Domains, true
	}
	for _, v := range c.VPNs {
		if v.Client == client {
			return v.Domains, true
		}
	}
	return nil, false
}

// SetDomainList replaces the domain list of a VPN client (or the Any VPN
// list), normalized. It reports false when the client is not allowed.
func (c *Config) SetDomainList(client string, rules []DomainRule) bool {
	rules = NormalizeDomains(rules)
	if client == AnyVPN {
		c.Domains = rules
		return true
	}
	for i := range c.VPNs {
		if c.VPNs[i].Client == client {
			c.VPNs[i].Domains = rules
			return true
		}
	}
	return false
}

// PatternCount counts the patterns across every list.
func (c *Config) PatternCount() int {
	n := len(c.Domains)
	for _, v := range c.VPNs {
		n += len(v.Domains)
	}
	return n
}

// Persister saves a whole configuration.
type Persister interface {
	Save(cfg *Config) error
}

// YAMLFile persists to a YAML file, the format releases before the SQLite
// store used. Tests and the one-time migration use it.
type YAMLFile string

// Save writes cfg to the file.
func (p YAMLFile) Save(cfg *Config) error { return Save(string(p), cfg) }

// DomainRule defines a list entry to route through VPN: a domain pattern, an
// IPv4 address, or an IPv4 CIDR.
// Supports both simple string format and object format for backwards compatibility.
type DomainRule struct {
	Pattern string `yaml:"pattern,omitempty" mapstructure:"pattern"` // e.g., "*.example.com", "10.20.30.40", "10.20.0.0/16"
}

// UnmarshalYAML allows domains to be specified as simple strings or objects.
func (d *DomainRule) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try simple string first
	var pattern string
	if err := unmarshal(&pattern); err == nil {
		d.Pattern = pattern
		return nil
	}

	// Try object format with "pattern" field
	type domainAlias DomainRule
	var alias domainAlias
	if err := unmarshal(&alias); err != nil {
		return err
	}
	d.Pattern = alias.Pattern
	return nil
}

// DNSConfig holds DNS resolver settings.
type DNSConfig struct {
	Servers  []string `yaml:"servers" mapstructure:"servers"`     // DNS servers, e.g., ["8.8.8.8", "1.1.1.1"]
	CacheTTL int      `yaml:"cache_ttl" mapstructure:"cache_ttl"` // Cache TTL in seconds, default 300

	// UseVPNDNS makes RouteWise resolve through the DNS servers the VPN pushes
	// while it is connected, and route those servers through the tunnel so they
	// stay reachable after the inverted split tunnel moves the default route.
	// Servers above remain the fallback. Off by default.
	UseVPNDNS bool `yaml:"use_vpn_dns" mapstructure:"use_vpn_dns"`
}

// DaemonConfig holds daemon runtime settings.
type DaemonConfig struct {
	PollInterval int    `yaml:"poll_interval" mapstructure:"poll_interval"` // VPN check interval in seconds
	PidFile      string `yaml:"pid_file" mapstructure:"pid_file"`           // PID file path
	LogFile      string `yaml:"log_file" mapstructure:"log_file"`           // Log file path
	LogLevel     string `yaml:"log_level" mapstructure:"log_level"`         // Log level: debug, info, warn, error
}

// DefaultConfigPath is the standard location for RouteWise config on this OS.
var DefaultConfigPath = platform.ConfigFile()

// MaxDomainPatterns bounds the configured host list so a client cannot grow the
// config file, DNS refresh work, or route table without limit. This is
// RouteWise's own local bound on this config file's domains list.
const MaxDomainPatterns = 500

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Domains: []DomainRule{},
		DNS: DNSConfig{
			Servers:  []string{"8.8.8.8", "1.1.1.1"},
			CacheTTL: 300, // 5 minutes
		},
		Daemon: DaemonConfig{
			PollInterval: 1,
			PidFile:      platform.PidFile(),
			LogFile:      platform.LogFile(),
			LogLevel:     "info",
		},
		Routing: RoutingConfig{
			Mode: RoutingModeInverted, // backwards-compatible default
		},
		History: HistoryConfig{Enabled: true, RetentionDays: DefaultHistoryRetentionDays},
		// Every kind is on, but with no DSN nothing is sent.
		Telemetry: TelemetryConfig{
			Errors: true, Sessions: true, Logs: true, Traces: true,
			TracesSampleRate: DefaultTracesSampleRate,
		},
	}
}

func validateDomainList(label string, rules []DomainRule) error {
	for i, d := range rules {
		if strings.TrimSpace(d.Pattern) == "" {
			return fmt.Errorf("%s[%d]: empty pattern", label, i)
		}
		if _, err := ParseEntry(d.Pattern); err != nil {
			if ClassifyEntry(d.Pattern) == EntryDomain {
				return fmt.Errorf("%s[%d]: invalid pattern %q", label, i, d.Pattern)
			}
			return fmt.Errorf("%s[%d]: invalid entry %q: %w", label, i, d.Pattern, err)
		}
	}
	return nil
}

// IsAdditiveMode returns true if routing mode is additive (coexist with other VPNs).
func (c *Config) IsAdditiveMode() bool {
	return c.Routing.Mode == RoutingModeAdditive
}

// Clone returns a deep copy so callers can never mutate shared configuration state.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	out := *c
	out.Domains = append([]DomainRule(nil), c.Domains...)
	out.DNS.Servers = append([]string(nil), c.DNS.Servers...)
	out.Routing.DefaultVPNExcept = append([]string(nil), c.Routing.DefaultVPNExcept...)
	out.VPNs = make([]VPNRoute, len(c.VPNs))
	for i, v := range c.VPNs {
		out.VPNs[i] = VPNRoute{Client: v.Client, Domains: append([]DomainRule(nil), v.Domains...)}
	}
	if c.Profiles != nil {
		out.Profiles = make([]TunnelProfile, len(c.Profiles))
		for i, p := range c.Profiles {
			p.DNS = append([]string(nil), p.DNS...)
			out.Profiles[i] = p
		}
	}
	return &out
}

// NormalizeDomains lowercases, trims, and de-duplicates list entries while
// preserving the original ordering of the first occurrence of each. An IP or
// CIDR entry is put in canonical form first (see NormalizeEntry), so
// 10.20.5.1/16 and 10.20.0.0/16 are one entry.
func NormalizeDomains(rules []DomainRule) []DomainRule {
	seen := make(map[string]struct{}, len(rules))
	out := make([]DomainRule, 0, len(rules))
	for _, r := range rules {
		pattern := NormalizeEntry(r.Pattern)
		if pattern == "" {
			continue
		}
		if _, dup := seen[pattern]; dup {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, DomainRule{Pattern: pattern})
	}
	return out
}

// Load reads configuration from the specified file path.
// Falls back to defaults for missing values.
func Load(configPath string) (*Config, error) {
	cfg := DefaultConfig()

	if configPath == "" {
		configPath = DefaultConfigPath
	}

	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// Set defaults
	for _, s := range Settings {
		viper.SetDefault(s.Key, settingValue(s.Field(cfg)))
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("read config: %w", err)
		}
		// Config file not found; use defaults
	}

	if err := viper.Unmarshal(cfg, viper.DecodeHook(stringToDomainRuleHook())); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	// Earlier releases accepted wildcard shapes that are no longer valid, such
	// as "*.com", but never routed any wildcard. Dropping them keeps an old
	// config loadable, so an upgraded helper still starts; the warning reaches
	// the daemon log through launchd's stderr redirection.
	var dropped []string
	cfg.Domains, dropped = dropUnsupportedWildcards(cfg.Domains)
	for _, p := range dropped {
		fmt.Fprintf(os.Stderr, "routewise: ignoring unsupported wildcard pattern %q in %s: "+
			"a '*' may appear once, in the first label, with at least two labels after it\n", p, configPath)
	}

	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// ApplyDefaults fills the values a configuration may leave unset: the routing
// mode (inverted), the history retention (DefaultHistoryRetentionDays) and the
// telemetry trace sample rate (DefaultTracesSampleRate). A
// configuration built or loaded without them gets them here; Validate never
// changes what it checks, so call this first wherever the configuration is
// about to be used or saved.
func (c *Config) ApplyDefaults() {
	if c.Routing.Mode == "" {
		c.Routing.Mode = RoutingModeInverted
	}
	if c.History.RetentionDays == 0 {
		c.History.RetentionDays = DefaultHistoryRetentionDays
	}
	if c.Telemetry.TracesSampleRate == 0 {
		c.Telemetry.TracesSampleRate = DefaultTracesSampleRate
	}
	c.pruneDefaultVPN()
}

// pruneDefaultVPN clears a default or fallback VPN that names a client no longer
// allowed, so revoking a VPN or removing a profile needs no extra step. A
// fallback means nothing without a default, or when it is the default.
func (c *Config) pruneDefaultVPN() {
	allowed := c.AllowedClients()
	if !slices.Contains(allowed, c.Routing.DefaultVPN) {
		c.Routing.DefaultVPN = ""
	}
	if c.Routing.DefaultVPN == "" || c.Routing.DefaultVPNFallback == c.Routing.DefaultVPN ||
		!slices.Contains(allowed, c.Routing.DefaultVPNFallback) {
		c.Routing.DefaultVPNFallback = ""
	}
}

// Validate checks the configuration for errors. It never modifies it: an unset
// routing mode or history retention is valid and means the default (see
// ApplyDefaults).
//
// An empty configuration is valid: with built-in VPN profiles a user may
// import a profile before adding any domain, and a helper with nothing to
// route simply routes nothing.
func (c *Config) Validate() error {
	return c.ValidateAllowingNoDomains()
}

// ValidateAllowingNoDomains checks everything Validate does except that at
// least one domain pattern exists. A freshly seeded store legitimately holds
// none until the first domain is added, but every other value in it must still
// be one the helper may act on as root.
func (c *Config) ValidateAllowingNoDomains() error {
	if err := validateDomainList("domain", c.Domains); err != nil {
		return err
	}
	if err := validateDomainList("routing.default_vpn_except", c.Routing.ExceptRules()); err != nil {
		return err
	}
	if err := validateProfiles(c.Profiles); err != nil {
		return err
	}
	seenClients := make(map[string]bool, len(c.VPNs))
	for i, v := range c.VPNs {
		if !IsBuiltinClient(v.Client) && v.Client != KernelWireGuardClient && !filepath.IsAbs(v.Client) {
			return fmt.Errorf("vpns[%d]: client must be an absolute executable path, kernel WireGuard or a built-in profile, got %q", i, v.Client)
		}
		if seenClients[v.Client] {
			return fmt.Errorf("vpns[%d]: client %q listed twice", i, v.Client)
		}
		seenClients[v.Client] = true
		if err := validateDomainList(fmt.Sprintf("vpns[%d].domain", i), v.Domains); err != nil {
			return err
		}
	}
	if err := c.validateProfileClients(); err != nil {
		return err
	}
	// Validate DNS servers
	if len(c.DNS.Servers) == 0 {
		return fmt.Errorf("dns.servers: at least one DNS server required")
	}
	for i, server := range c.DNS.Servers {
		if net.ParseIP(server) == nil {
			return fmt.Errorf("dns.servers[%d]: invalid IP address %q", i, server)
		}
	}
	if c.DNS.CacheTTL < 0 {
		return fmt.Errorf("dns.cache_ttl must be >= 0")
	}
	if c.Daemon.PollInterval < 1 {
		return fmt.Errorf("daemon.poll_interval must be >= 1")
	}
	// An empty routing mode means inverted.
	if c.Routing.Mode != "" && c.Routing.Mode != RoutingModeInverted && c.Routing.Mode != RoutingModeAdditive {
		return fmt.Errorf("routing.mode: invalid value %q (must be inverted or additive)", c.Routing.Mode)
	}
	// An unset retention (a config built without the history section) means the
	// default; any set value must be in range.
	if c.History.RetentionDays != 0 {
		if err := ValidateHistoryRetention(c.History.RetentionDays); err != nil {
			return err
		}
	}
	if err := c.Telemetry.Validate(); err != nil {
		return err
	}
	// Validate log level
	if c.Daemon.LogLevel != "" && !ValidLogLevels[strings.ToLower(c.Daemon.LogLevel)] {
		return fmt.Errorf("daemon.log_level: invalid value %q (must be debug, info, warn, or error)", c.Daemon.LogLevel)
	}
	// Validate log file path (restrict to safe directories for root daemon)
	if c.Daemon.LogFile != "" {
		if !platform.LogPathAllowed(filepath.Dir(c.Daemon.LogFile)) {
			return fmt.Errorf("daemon.log_file: path must be under %s, got %q", describeRoots(platform.LogRoots()), c.Daemon.LogFile)
		}
	}
	return nil
}

// describeRoots spells directory roots as "/var/log/ or /tmp/" for messages.
func describeRoots(roots []string) string {
	dirs := make([]string, len(roots))
	for i, root := range roots {
		dirs[i] = strings.TrimRight(root, `/\`) + string(filepath.Separator)
	}
	return strings.Join(dirs, " or ")
}

// IsValidDomainPattern reports whether pattern is an exact domain name or a
// supported wildcard (see domainPatternRegex). It is the single validator for
// both the config file and the socket API.
func IsValidDomainPattern(pattern string) bool {
	return pattern != "" && domainPatternRegex.MatchString(pattern)
}

// dropUnsupportedWildcards removes wildcard patterns IsValidDomainPattern
// rejects and returns them. Invalid exact patterns are kept so Validate still
// reports them as errors, as it always has.
func dropUnsupportedWildcards(rules []DomainRule) (kept []DomainRule, dropped []string) {
	kept = make([]DomainRule, 0, len(rules))
	for _, r := range rules {
		pattern := strings.TrimSpace(r.Pattern)
		if IsWildcardPattern(pattern) && !IsValidDomainPattern(strings.ToLower(pattern)) {
			dropped = append(dropped, pattern)
			continue
		}
		kept = append(kept, r)
	}
	return kept, dropped
}

// IsWildcardPattern reports whether pattern contains a wildcard and therefore
// can only be routed by watching DNS answers, not by resolving it up front.
func IsWildcardPattern(pattern string) bool {
	return strings.Contains(pattern, "*")
}

// WildcardSuffix returns the domain a wildcard pattern lives under: everything
// after its first label ("*.corp.example.com" -> "corp.example.com"). It returns
// "" for an exact pattern.
func WildcardSuffix(pattern string) string {
	if !IsWildcardPattern(pattern) {
		return ""
	}
	_, suffix, ok := strings.Cut(pattern, ".")
	if !ok {
		return ""
	}
	return strings.ToLower(suffix)
}

// stringToDomainRuleHook allows domains to be specified as simple strings.
func stringToDomainRuleHook() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if t != reflect.TypeOf(DomainRule{}) {
			return data, nil
		}
		if f.Kind() == reflect.String {
			return DomainRule{Pattern: data.(string)}, nil
		}
		return data, nil
	}
}

// ValidateConfigSecurity checks that the config file has secure ownership and permissions.
// Returns nil if secure, error with fix instructions if insecure.
// Windows checks the file's owner and access list instead of a uid and mode
// bits; other systems without Unix ownership return nil.
func ValidateConfigSecurity(path string) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil // File doesn't exist yet, will be created
	}
	if runtime.GOOS == "windows" {
		return platform.CheckFileSecurity(path)
	}

	// Get file owner
	uid, ok := platform.FileOwnerUID(info)
	if !ok {
		return nil // Can't check on this platform
	}

	// Check owner is root (UID 0)
	if uid != 0 {
		return fmt.Errorf(
			"security: config file %s is owned by UID %d, not root (UID 0)\n"+
				"  This is a security risk when running as root daemon.\n"+
				"  Fix with: sudo chown %s %s",
			path, uid, platform.RootOwner(), path,
		)
	}

	// Check not world-writable (mode & 0002)
	mode := info.Mode()
	if mode&0002 != 0 {
		return fmt.Errorf(
			"security: config file %s is world-writable (mode %o)\n"+
				"  This allows any user to modify daemon behavior.\n"+
				"  Fix with: sudo chmod 644 %s",
			path, mode.Perm(), path,
		)
	}

	return nil
}

// defaultConfigFileMode is used when the config file is created for the first time.
const defaultConfigFileMode os.FileMode = 0600

// Save writes the configuration to the specified file path atomically.
//
// The target is inspected without following symlinks and rejected unless it is a
// regular file that only root or the running user can modify. The new content is
// written to a temporary file in the same directory, flushed, and renamed over
// the target, so a crash at any point leaves either the old or the new config
// intact and never a truncated file.
func Save(configPath string, cfg *Config) error {
	if configPath == "" {
		return fmt.Errorf("config path is empty")
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	mode, err := safeTargetMode(configPath)
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".config-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpPath := tmp.Name()
	// Any failure past this point must not leave the temporary file behind.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("set config permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}

	// Fsync the directory so the rename itself survives a crash. Windows cannot
	// flush a directory handle; its rename is durable through the journal.
	if runtime.GOOS == "windows" {
		return nil
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open config dir: %w", err)
	}
	defer dirFile.Close()
	if err := dirFile.Sync(); err != nil {
		return fmt.Errorf("sync config dir: %w", err)
	}

	return nil
}

// safeTargetMode validates an existing config target and returns the file mode to
// write with. A missing target is created with restrictive permissions; an
// existing target keeps its permissions so an installer-provisioned file is not
// silently locked down.
func safeTargetMode(configPath string) (os.FileMode, error) {
	info, err := os.Lstat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultConfigFileMode, nil
		}
		return 0, fmt.Errorf("inspect config: %w", err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("config %s is a symlink; refusing to write through it", configPath)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("config %s is not a regular file", configPath)
	}
	if runtime.GOOS == "windows" {
		// Mode bits do not describe Windows access; the access list does.
		if err := platform.CheckFileSecurity(configPath); err != nil {
			return 0, fmt.Errorf("refusing to write config: %w", err)
		}
		return defaultConfigFileMode, nil
	}
	if perm := info.Mode().Perm(); perm&0022 != 0 {
		return 0, fmt.Errorf("config %s is group- or world-writable (mode %o); refusing to write", configPath, perm)
	}
	if uid, ok := platform.FileOwnerUID(info); ok {
		if uid != 0 && uint64(uid) != uint64(os.Geteuid()) {
			return 0, fmt.Errorf("config %s is owned by UID %d, not root or the current user", configPath, uid)
		}
	}

	return info.Mode().Perm(), nil
}
