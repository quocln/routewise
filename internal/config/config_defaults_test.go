package config

import (
	"reflect"
	"slices"
	"testing"
)

func TestValidateDoesNotModifyTheConfig(t *testing.T) {
	cfg := &Config{
		Domains: []DomainRule{{Pattern: "example.com"}},
		DNS:     DNSConfig{Servers: []string{"8.8.8.8"}},
		Daemon:  DaemonConfig{PollInterval: 1},
	}
	before := cfg.Clone()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a config with the defaulted values unset is valid: %v", err)
	}
	if cfg.Routing.Mode != "" || cfg.History.RetentionDays != 0 {
		t.Fatalf("Validate changed the config: mode %q, retention %d", cfg.Routing.Mode, cfg.History.RetentionDays)
	}
	if !reflect.DeepEqual(cfg.Routing, before.Routing) || cfg.History != before.History {
		t.Fatal("Validate changed the config")
	}
}

func TestApplyDefaultsFillsOnlyWhatIsUnset(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyDefaults()
	if cfg.Routing.Mode != RoutingModeInverted || cfg.History.RetentionDays != DefaultHistoryRetentionDays {
		t.Fatalf("defaults = mode %q, retention %d", cfg.Routing.Mode, cfg.History.RetentionDays)
	}

	set := &Config{Routing: RoutingConfig{Mode: RoutingModeAdditive}, History: HistoryConfig{RetentionDays: 30}}
	set.ApplyDefaults()
	if set.Routing.Mode != RoutingModeAdditive || set.History.RetentionDays != 30 {
		t.Fatalf("ApplyDefaults overwrote a set value: %+v %+v", set.Routing, set.History)
	}
}

func TestValidateStillRejectsBadValues(t *testing.T) {
	base := func() *Config {
		return &Config{
			Domains: []DomainRule{{Pattern: "example.com"}},
			DNS:     DNSConfig{Servers: []string{"8.8.8.8"}},
			Daemon:  DaemonConfig{PollInterval: 1},
		}
	}
	bad := base()
	bad.Routing.Mode = "sideways"
	if bad.Validate() == nil {
		t.Error("an unknown routing mode must be rejected")
	}
	bad = base()
	bad.History.RetentionDays = 500
	if bad.Validate() == nil {
		t.Error("an out-of-range retention must be rejected")
	}
	bad = base()
	bad.History.RetentionDays = -1
	if bad.Validate() == nil {
		t.Error("a negative retention must be rejected")
	}
}

func TestProfileKindsAreTheKindsAProfileMayHave(t *testing.T) {
	kinds := ProfileKinds()
	if !slices.Equal(kinds, []string{ProfileKindWireGuard, ProfileKindOutline}) {
		t.Fatalf("ProfileKinds = %v", kinds)
	}
	kinds[0] = "mutated"
	if ProfileKinds()[0] != ProfileKindWireGuard {
		t.Error("ProfileKinds must return a copy")
	}
	for _, kind := range ProfileKinds() {
		if !validProfileKind(kind) {
			t.Errorf("%q is listed but not valid", kind)
		}
	}
	if validProfileKind("future") {
		t.Error("an unknown kind must not be valid")
	}
}
