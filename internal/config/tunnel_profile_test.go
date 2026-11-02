package config

import (
	"encoding/json"
	"github.com/quocln/routewise/internal/testenv"
	"slices"
	"strings"
	"testing"
	"time"
)

func profileConfig() *Config {
	cfg := DefaultConfig()
	cfg.Domains = []DomainRule{{Pattern: "any.example.com"}}
	cfg.Profiles = []TunnelProfile{
		{ID: "0a1b2c3d", Kind: ProfileKindWireGuard, Name: "Office", AutoConnect: true, DNS: []string{"10.8.0.1"}},
		{ID: "4e5f6a7b", Kind: ProfileKindOutline, Name: "Travel", DNS: []string{"1.1.1.1"}},
	}
	cfg.VPNs = []VPNRoute{
		{Client: testenv.Exe("/opt/homebrew/sbin/openvpn")},
		{Client: "routewise-wireguard:0a1b2c3d", Domains: []DomainRule{{Pattern: "10.9.0.0/16"}, {Pattern: "wiki.corp.example.com"}}},
		{Client: "routewise-outline:4e5f6a7b"},
	}
	return cfg
}

func TestProfileClientIDRoundTrip(t *testing.T) {
	id := ProfileClientID(ProfileKindOutline, "4e5f6a7b")
	if id != "routewise-outline:4e5f6a7b" {
		t.Fatalf("client id = %q", id)
	}
	kind, pid, ok := ParseProfileClientID(id)
	if !ok || kind != ProfileKindOutline || pid != "4e5f6a7b" {
		t.Errorf("parse = %q %q %v", kind, pid, ok)
	}
	for _, bad := range []string{"", "/usr/bin/x", "routewise-openvpn:0a1b2c3d", "routewise-wireguard:", "routewise-wireguard:XYZ", "routewise-wireguard:0a1b2c3d/../x"} {
		if IsBuiltinClient(bad) {
			t.Errorf("%q must not be a built-in client", bad)
		}
	}
}

func TestValidateAcceptsBuiltInClientsNextToPaths(t *testing.T) {
	if err := profileConfig().Validate(); err != nil {
		t.Fatalf("valid profile config rejected: %v", err)
	}
}

func TestValidateAcceptsKernelWireGuardAsAClient(t *testing.T) {
	c := profileConfig()
	c.VPNs = append(c.VPNs, VPNRoute{Client: KernelWireGuardClient})
	if err := c.Validate(); err != nil {
		t.Fatalf("kernel WireGuard client rejected: %v", err)
	}
	c.VPNs[len(c.VPNs)-1].Client = "wireguard:other"
	if err := c.Validate(); err == nil {
		t.Fatal("an unknown non-path client must be rejected")
	}
}

func TestValidateRejectsBadProfiles(t *testing.T) {
	mutations := map[string]func(*Config){
		"duplicate id": func(c *Config) { c.Profiles[1].ID = c.Profiles[0].ID },
		"duplicate name (any case)": func(c *Config) {
			c.Profiles[1].Name = "office"
		},
		"unknown kind":           func(c *Config) { c.Profiles[0].Kind = "openvpn" },
		"blank name":             func(c *Config) { c.Profiles[0].Name = "  " },
		"control in name":        func(c *Config) { c.Profiles[0].Name = "a\nb" },
		"long name":              func(c *Config) { c.Profiles[0].Name = strings.Repeat("x", MaxProfileNameLen+1) },
		"ipv6 dns":               func(c *Config) { c.Profiles[0].DNS = []string{"fd00::1"} },
		"hostname dns":           func(c *Config) { c.Profiles[0].DNS = []string{"dns.example.com"} },
		"loopback dns":           func(c *Config) { c.Profiles[0].DNS = []string{"127.0.0.1"} },
		"bad id":                 func(c *Config) { c.Profiles[0].ID = "NOT-HEX" },
		"client without profile": func(c *Config) { c.VPNs = append(c.VPNs, VPNRoute{Client: "routewise-wireguard:99999999"}) },
		"kind mismatch":          func(c *Config) { c.VPNs[1].Client = "routewise-outline:0a1b2c3d" },
		"profile without client": func(c *Config) { c.VPNs = c.VPNs[:2] },
		"relative client":        func(c *Config) { c.VPNs[0].Client = "relative/path" },
	}
	for name, mutate := range mutations {
		cfg := profileConfig()
		mutate(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestCloneCopiesProfilesDeeply(t *testing.T) {
	a := profileConfig()
	b := a.Clone()
	b.Profiles[0].DNS[0] = "9.9.9.9"
	b.Profiles[0].Name = "Changed"
	if a.Profiles[0].DNS[0] != "10.8.0.1" || a.Profiles[0].Name != "Office" {
		t.Error("Clone shares profile state with the original")
	}
}

func TestExportCarriesProfilesAndListsWithoutSecretsAndRoundTrips(t *testing.T) {
	cfg := profileConfig()
	e := NewExport(cfg, time.Now())
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	// An export has no field a secret could sit in.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, p := range generic["profiles"].([]any) {
		for key := range p.(map[string]any) {
			if !slices.Contains([]string{"id", "kind", "name", "autoConnect", "dns"}, key) {
				t.Errorf("unexpected profile export field %q", key)
			}
		}
	}

	parsed, err := ParseExport(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsed.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(got.Profiles) != 2 || got.Profiles[0].Name != "Office" || !got.Profiles[0].AutoConnect ||
		got.Profiles[1].Kind != ProfileKindOutline || got.Profiles[0].DNS[0] != "10.8.0.1" {
		t.Errorf("profiles after the round trip: %+v", got.Profiles)
	}
	if list, ok := got.DomainList("routewise-wireguard:0a1b2c3d"); !ok || len(list) != 2 {
		t.Errorf("the profile's list after the round trip: %v %v", list, ok)
	}
	if !slices.Equal(got.AllowedClients(), cfg.AllowedClients()) {
		t.Errorf("priority order changed: %v", got.AllowedClients())
	}
}

func TestApplyAddsAMissingClientEntryForAnExportedProfile(t *testing.T) {
	e := NewExport(profileConfig(), time.Now())
	e.VPNs = e.VPNs[:1] // a hand-edited export that dropped the profiles' entries
	got, err := e.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !slices.Contains(got.AllowedClients(), "routewise-wireguard:0a1b2c3d") || !slices.Contains(got.AllowedClients(), "routewise-outline:4e5f6a7b") {
		t.Errorf("clients = %v, want an entry per profile", got.AllowedClients())
	}
}

func TestApplyRejectsAClientEntryWithoutAProfile(t *testing.T) {
	e := NewExport(profileConfig(), time.Now())
	e.Profiles = e.Profiles[:1]
	if _, err := e.Apply(DefaultConfig()); err == nil {
		t.Fatal("a built-in client entry whose profile is missing must be rejected")
	}
}

func TestOldExportWithoutProfilesStillApplies(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domains = []DomainRule{{Pattern: "a.example.com"}}
	raw, _ := json.Marshal(NewExport(cfg, time.Now()))
	if strings.Contains(string(raw), "profiles") {
		t.Error("an export without profiles must not carry the field")
	}
	parsed, err := ParseExport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Apply(DefaultConfig()); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeProfileDNS(t *testing.T) {
	got, err := NormalizeProfileDNS([]string{" 10.0.0.1", "10.0.0.1", "1.1.1.1"})
	if err != nil || !slices.Equal(got, []string{"10.0.0.1", "1.1.1.1"}) {
		t.Errorf("got %v, %v", got, err)
	}
	if _, err := NormalizeProfileDNS(make([]string, 0)); err != nil {
		t.Errorf("an empty list is allowed: %v", err)
	}
	many := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9"}
	if _, err := NormalizeProfileDNS(many); err == nil {
		t.Error("too many DNS servers must be rejected")
	}
}
