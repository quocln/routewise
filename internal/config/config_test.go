package config

import (
	"github.com/quocln/routewise/internal/platform"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if len(cfg.DNS.Servers) != 2 {
		t.Errorf("expected 2 DNS servers, got %d", len(cfg.DNS.Servers))
	}
	if cfg.DNS.CacheTTL != 300 {
		t.Errorf("expected CacheTTL 300, got %d", cfg.DNS.CacheTTL)
	}
	if cfg.Daemon.PollInterval != 1 {
		t.Errorf("expected PollInterval 1, got %d", cfg.Daemon.PollInterval)
	}
	if cfg.Daemon.LogLevel != "info" {
		t.Errorf("expected LogLevel 'info', got '%s'", cfg.Daemon.LogLevel)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				Domains: []DomainRule{{Pattern: "*.example.com"}},
				DNS:     DNSConfig{Servers: []string{"8.8.8.8"}, CacheTTL: 300},
				Daemon:  DaemonConfig{PollInterval: 1},
			},
			wantErr: false,
		},
		{
			// Valid: built-in VPN profiles can exist before any domain.
			name: "no domains",
			cfg: &Config{
				Domains: []DomainRule{},
				DNS:     DNSConfig{Servers: []string{"8.8.8.8"}, CacheTTL: 300},
				Daemon:  DaemonConfig{PollInterval: 1},
			},
			wantErr: false,
		},
		{
			name: "empty pattern",
			cfg: &Config{
				Domains: []DomainRule{{Pattern: ""}},
				DNS:     DNSConfig{Servers: []string{"8.8.8.8"}, CacheTTL: 300},
				Daemon:  DaemonConfig{PollInterval: 1},
			},
			wantErr: true,
		},
		{
			name: "negative cache TTL",
			cfg: &Config{
				Domains: []DomainRule{{Pattern: "*.example.com"}},
				DNS:     DNSConfig{Servers: []string{"8.8.8.8"}, CacheTTL: -1},
				Daemon:  DaemonConfig{PollInterval: 1},
			},
			wantErr: true,
		},
		{
			name: "zero poll interval",
			cfg: &Config{
				Domains: []DomainRule{{Pattern: "*.example.com"}},
				DNS:     DNSConfig{Servers: []string{"8.8.8.8"}, CacheTTL: 300},
				Daemon:  DaemonConfig{PollInterval: 0},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write test config
	configContent := `
domains:
  - pattern: "gateway.example.com"
  - pattern: "*.example.com"
dns:
  servers:
    - "8.8.8.8"
  cache_ttl: 600
daemon:
  poll_interval: 5
  pid_file: "/tmp/test.pid"
  log_file: '` + filepath.Join(platform.LogDir(), "test.log") + `'
  log_level: "debug"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.Domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(cfg.Domains))
	}
	if cfg.Domains[0].Pattern != "gateway.example.com" {
		t.Errorf("expected first pattern 'gateway.example.com', got '%s'", cfg.Domains[0].Pattern)
	}
	if cfg.DNS.CacheTTL != 600 {
		t.Errorf("expected CacheTTL 600, got %d", cfg.DNS.CacheTTL)
	}
	if cfg.Daemon.PollInterval != 5 {
		t.Errorf("expected PollInterval 5, got %d", cfg.Daemon.PollInterval)
	}
	if cfg.Daemon.LogLevel != "debug" {
		t.Errorf("expected LogLevel 'debug', got '%s'", cfg.Daemon.LogLevel)
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	// Try to load non-existent config (should use defaults but fail validation)
	_, err := Load("/nonexistent/path/config.yaml")
	// This should fail because defaults have no domains
	if err == nil {
		t.Error("expected error for missing config with no domains")
	}
}

func TestSaveConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "subdir", "config.yaml")

	cfg := &Config{
		Domains: []DomainRule{{Pattern: "test.example.com"}},
		DNS:     DNSConfig{Servers: []string{"1.1.1.1"}, CacheTTL: 120},
		Daemon:  DaemonConfig{PollInterval: 2, LogLevel: "warn"},
	}

	if err := Save(configPath, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("config file not created")
	}
}

func TestIsValidDomainPattern(t *testing.T) {
	valid := []string{
		"example.com",
		"api.internal.example.com",
		"*.example.com",
		"*.corp.example.com",
		"qa*.staging.example.com",
		"*-api.example.com",
	}
	invalid := []string{
		"",
		"*.com",             // a suffix this broad would capture a whole TLD
		"*",                 // no suffix at all
		"api.*.example.com", // wildcard outside the first label
		"*a*.example.com",   // more than one wildcard
		"example.com.*",
		"bad space.com",
		"../etc.com",
	}
	for _, p := range valid {
		if !IsValidDomainPattern(p) {
			t.Errorf("IsValidDomainPattern(%q) = false, want true", p)
		}
	}
	for _, p := range invalid {
		if IsValidDomainPattern(p) {
			t.Errorf("IsValidDomainPattern(%q) = true, want false", p)
		}
	}
}

func TestWildcardSuffix(t *testing.T) {
	tests := map[string]string{
		"*.corp.example.com":      "corp.example.com",
		"qa*.Staging.Example.com": "staging.example.com",
		"api.example.com":         "",
	}
	for pattern, want := range tests {
		if got := WildcardSuffix(pattern); got != want {
			t.Errorf("WildcardSuffix(%q) = %q, want %q", pattern, got, want)
		}
	}
}

// A config written by an older release can still carry the removed provider
// and Tailscale keys. They must be ignored, not rejected, so upgrading never
// stops the daemon from starting.
func TestLoadConfigIgnoresRemovedProviderKeys(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := `
domains:
  - pattern: "api.example.com"
routing:
  provider: "tailscale"
  mode: "additive"
  tailscale_policy:
    tailnet: "example.ts.net"
    connector_name: "corp"
    connector_tag: "tag:corp"
dns:
  servers: ["1.1.1.1"]
  use_vpn_dns: true
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.IsAdditiveMode() {
		t.Error("routing.mode must still be read next to the removed keys")
	}
	if !cfg.DNS.UseVPNDNS {
		t.Error("dns.use_vpn_dns: true must be loaded")
	}
}

func TestAllowIPv6DefaultsToOffAndLoadsFromYAML(t *testing.T) {
	if DefaultConfig().Routing.AllowIPv6 {
		t.Error("routing.allow_ipv6 must default to off")
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("routing:\n  allow_ipv6: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Routing.AllowIPv6 {
		t.Error("routing.allow_ipv6: true must be loaded")
	}
}

func TestDefaultConfigLeavesVPNDNSOff(t *testing.T) {
	if DefaultConfig().DNS.UseVPNDNS {
		t.Error("dns.use_vpn_dns must default to off")
	}
}

// Older releases accepted "*.com". Such a pattern never routed anything, so an
// upgraded helper drops it with a warning instead of refusing to start.
func TestLoadDropsWildcardsThatAreNoLongerValid(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := `
domains:
  - pattern: "*.com"
  - pattern: "api.example.com"
dns:
  servers: ["1.1.1.1"]
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v, want the old pattern dropped rather than fatal", err)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0].Pattern != "api.example.com" {
		t.Errorf("domains = %v, want only api.example.com", cfg.Domains)
	}
}

func TestLoadStillRejectsInvalidExactPatterns(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := `
domains:
  - pattern: "bad space.com"
dns:
  servers: ["1.1.1.1"]
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil {
		t.Error("an invalid exact pattern must still fail validation")
	}
}

func TestHistoryDefaultsAndValidation(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.History.Enabled || cfg.History.RetentionDays != 7 {
		t.Fatalf("defaults = %+v, want enabled with 7 days", cfg.History)
	}
	cfg.Domains = []DomainRule{{Pattern: "a.example.com"}}
	for _, days := range []int{1, 7, 90} {
		cfg.History.RetentionDays = days
		if err := cfg.Validate(); err != nil {
			t.Errorf("retention %d: %v", days, err)
		}
	}
	for _, days := range []int{-5, 91, 365} {
		cfg.History.RetentionDays = days
		if err := cfg.Validate(); err == nil {
			t.Errorf("retention %d must be rejected", days)
		}
	}
}
