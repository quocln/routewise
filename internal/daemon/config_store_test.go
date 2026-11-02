package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/quocln/routewise/internal/config"
)

func newTestStore(t *testing.T, patterns ...string) *ConfigStore {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Domains = nil
	for _, p := range patterns {
		cfg.Domains = append(cfg.Domains, config.DomainRule{Pattern: p})
	}
	if len(cfg.Domains) == 0 {
		cfg.Domains = []config.DomainRule{{Pattern: "example.com"}}
	}

	return NewConfigStore(cfg, config.YAMLFile(filepath.Join(t.TempDir(), "config.yaml")))
}

func TestConfigStore_SnapshotIsIsolated(t *testing.T) {
	store := newTestStore(t, "example.com")

	snapshot, rev := store.Snapshot()
	if rev != 1 {
		t.Errorf("initial revision = %d, want 1 so that zero can mean 'no expectation'", rev)
	}

	snapshot.Domains[0].Pattern = "hijacked.example.com"
	snapshot.Routing.Mode = config.RoutingModeAdditive

	if got := store.Domains(); got[0] != "example.com" {
		t.Errorf("mutating a snapshot changed the store: %v", got)
	}
	if fresh, _ := store.Snapshot(); fresh.Routing.Mode != config.RoutingModeInverted {
		t.Error("mutating a snapshot changed the stored routing mode")
	}
}

func TestConfigStore_NewStoreNormalizesDomains(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{
		{Pattern: "  Example.COM "},
		{Pattern: "example.com"},
		{Pattern: "*.Other.com"},
	}
	store := NewConfigStore(cfg, nil)

	got := store.Domains()
	if len(got) != 2 || got[0] != "example.com" || got[1] != "*.other.com" {
		t.Errorf("domains = %v, want normalized and deduplicated", got)
	}
}

func TestConfigStore_AddRemoveDomain(t *testing.T) {
	store := newTestStore(t, "example.com")

	if _, err := store.AddDomain("", "api.example.com"); err != nil {
		t.Fatalf("AddDomain() error = %v", err)
	}
	if got := store.Domains(); len(got) != 2 {
		t.Fatalf("domains = %v, want 2", got)
	}

	if _, err := store.AddDomain("", "API.example.com"); err == nil {
		t.Error("adding a domain that normalizes to an existing one must be rejected")
	}

	if _, err := store.RemoveDomain("", "api.example.com"); err != nil {
		t.Fatalf("RemoveDomain() error = %v", err)
	}
	if got := store.Domains(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("domains = %v, want [example.com]", got)
	}

	if _, err := store.RemoveDomain("", "absent.example.com"); err == nil {
		t.Error("removing an unknown domain must be rejected")
	}
}

// An empty domain list is a valid configuration: with built-in VPN profiles a
// user may have a profile before any domain, and a helper with nothing to route
// simply routes nothing. The emptied list must also be what gets saved.
func TestConfigStore_AllowsAnEmptyDomainList(t *testing.T) {
	store := newTestStore(t, "example.com")

	if _, err := store.RemoveDomain("", "example.com"); err != nil {
		t.Fatalf("removing the last domain: %v", err)
	}
	if got := store.Domains(); len(got) != 0 {
		t.Errorf("domains = %v, want none", got)
	}
	if _, err := store.SetDomains("", nil, 0); err != nil {
		t.Errorf("setting an empty domain list: %v", err)
	}
	if cfg, _ := store.Snapshot(); cfg.PatternCount() != 0 {
		t.Errorf("pattern count = %d, want 0", cfg.PatternCount())
	}
}

func TestConfigStore_SetDomainsRejectsStaleRevision(t *testing.T) {
	store := newTestStore(t, "example.com")

	_, current := store.Snapshot()

	if _, err := store.SetDomains("", []string{"a.example.com"}, current); err != nil {
		t.Fatalf("SetDomains() with current revision error = %v", err)
	}

	_, err := store.SetDomains("", []string{"b.example.com"}, current)
	if err == nil {
		t.Fatal("expected a stale revision to be rejected")
	}
	var stale *ErrStaleRevision
	if !errors.As(err, &stale) {
		t.Fatalf("error = %v, want ErrStaleRevision", err)
	}
	if stale.Expected != current || stale.Actual != current+1 {
		t.Errorf("stale revision reported %d/%d, want %d/%d", stale.Expected, stale.Actual, current, current+1)
	}
	if got := store.Domains(); got[0] != "a.example.com" {
		t.Errorf("a rejected write changed the store: %v", got)
	}
}

func TestConfigStore_SetDomainsWithoutRevisionIsUnconditional(t *testing.T) {
	store := newTestStore(t, "example.com")

	if _, err := store.SetDomains("", []string{"a.example.com", "b.example.com"}, 0); err != nil {
		t.Fatalf("SetDomains() error = %v", err)
	}
	if got := store.Domains(); len(got) != 2 {
		t.Errorf("domains = %v, want 2", got)
	}
}

func TestConfigStore_RejectsTooManyDomains(t *testing.T) {
	store := newTestStore(t, "example.com")

	patterns := make([]string, config.MaxDomainPatterns+1)
	for i := range patterns {
		patterns[i] = domainAt(i)
	}

	if _, err := store.SetDomains("", patterns, 0); err == nil {
		t.Fatal("expected an over-limit domain list to be rejected")
	}
	if got := store.Domains(); len(got) != 1 {
		t.Errorf("a rejected write changed the store: %v", got)
	}
}

// A config that cannot be written must not become visible in memory either,
// otherwise a restart would silently revert what the user was told succeeded.
func TestConfigStore_PersistFailureLeavesStoreUnchanged(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("root ignores directory permissions, and Windows has none to chmod")
	}

	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: "example.com"}}
	store := NewConfigStore(cfg, config.YAMLFile(filepath.Join(dir, "config.yaml")))

	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	_, err := store.AddDomain("", "api.example.com")
	if err == nil {
		t.Fatal("expected AddDomain to fail when the config cannot be written")
	}
	if !errors.Is(err, ErrPersistFailed) {
		t.Errorf("error = %v, want it to wrap ErrPersistFailed so callers can tell it apart from a bad request", err)
	}
	if got := store.Domains(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("domains = %v, want the failed mutation discarded", got)
	}
	if store.Revision() != 1 {
		t.Errorf("revision = %d, want it unchanged after a failed persist", store.Revision())
	}
}

// Concurrent mutations must serialize: every accepted change bumps the revision
// exactly once and the final config must be one the daemon can load.
func TestConfigStore_ConcurrentMutations(t *testing.T) {
	store := newTestStore(t, "example.com")

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_, _ = store.AddDomain("", domainAt(i))
				return
			}
			// Readers run alongside the writers so a race between a
			// snapshot and a commit shows up under -race.
			snapshot, _ := store.Snapshot()
			_ = snapshot.Domains
			_ = store.Domains()
		}(i)
	}
	wg.Wait()

	snapshot, rev := store.Snapshot()
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("store settled on an invalid config: %v", err)
	}
	if rev < 2 {
		t.Errorf("revision = %d, want it to advance past the initial value", rev)
	}
	// Every even worker added a distinct domain, on top of the seeded one.
	if got := len(snapshot.Domains); got != workers/2+1 {
		t.Errorf("domains = %d, want %d; concurrent adds must not be lost", got, workers/2+1)
	}
}

// domainAt builds a distinct valid pattern for index i.
func domainAt(i int) string {
	return string(rune('a'+(i%26))) + string(rune('a'+((i/26)%26))) + string(rune('a'+((i/676)%26))) + ".example.com"
}
