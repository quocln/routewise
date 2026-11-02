package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/configdb"
)

// useConfigDir points the CLI at a temporary config location.
func useConfigDir(t *testing.T) string {
	t.Helper()
	old := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "config.yaml")
	t.Cleanup(func() { cfgFile = old })
	return cfgFile
}

func TestLoadForUpdateUsesDefaultsOnlyWhenNothingWasEverStored(t *testing.T) {
	useConfigDir(t)
	cfg, err := loadConfigForUpdate()
	if err != nil {
		t.Fatalf("nothing stored yet must start from the defaults: %v", err)
	}
	if cfg.PatternCount() != 0 || len(cfg.DNS.Servers) == 0 {
		t.Errorf("config = %+v, want the defaults", cfg)
	}

	// An empty database with no YAML is the same situation.
	db, err := configdb.Open(configdb.PathFor(cfgFile))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := loadConfigForUpdate(); err != nil {
		t.Fatalf("an empty database must start from the defaults: %v", err)
	}
}

func TestAnOfflineWriteNeverReplacesAStoredConfigAfterAFailedLoad(t *testing.T) {
	path := useConfigDir(t)
	dbPath := configdb.PathFor(path)
	stored := config.DefaultConfig()
	stored.Domains = []config.DomainRule{{Pattern: "keep.example.com"}}
	stored.VPNs = []config.VPNRoute{{Client: "/Applications/WireGuard.app/x", Domains: []config.DomainRule{{Pattern: "wg.example.com"}}}}
	if err := saveConfig(stored); err != nil {
		t.Fatal(err)
	}

	for name, damage := range map[string]func(t *testing.T){
		"a damaged database": func(t *testing.T) {
			if err := os.WriteFile(dbPath, bytes.Repeat([]byte("not a database "), 20), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"an invalid stored config": func(t *testing.T) {
			if err := os.Remove(dbPath); err != nil {
				t.Fatal(err)
			}
			db, err := configdb.Open(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			bad := stored.Clone()
			bad.DNS.Servers = nil
			if err := db.Save(bad); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			damage(t)
			before, err := os.ReadFile(dbPath)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := loadConfigForUpdate(); err == nil {
				t.Fatal("a failed load must stop the update, not fall back to defaults")
			} else if !strings.Contains(err.Error(), "nothing was changed") {
				t.Errorf("error = %v, want it to say nothing was changed", err)
			}
			after, err := os.ReadFile(dbPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Errorf("the database file must be untouched (err=%v)", err)
			}
		})
	}
}
