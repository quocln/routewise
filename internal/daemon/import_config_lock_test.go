package daemon

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
)

func TestDefaultProfileNameFollowsTheKind(t *testing.T) {
	for kind, want := range map[string]string{
		config.ProfileKindWireGuard: "WireGuard",
		config.ProfileKindOutline:   "Outline",
		"future":                    "VPN",
	} {
		if got := defaultProfileName(kind, ""); got != want {
			t.Errorf("defaultProfileName(%q) = %q, want %q", kind, got, want)
		}
	}
	if got := defaultProfileName("future", "Travel"); got != "Travel" {
		t.Errorf("a valid label wins: got %q", got)
	}
}

// ImportConfig reads the profiles it will reconcile against and replaces them
// as one step under profileMu, so it must wait for a profile import in flight.
func TestImportConfigWaitsForProfileMu(t *testing.T) {
	e := newBuiltinEnv(t, newFakeKernel(), []string{"any.example.com"}, nil, nil)
	export := e.d.ExportConfig()
	_, before := e.d.store.Snapshot()

	e.d.tunnels.profileMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := e.d.ImportConfig(export)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("ImportConfig finished while profileMu was held (err=%v)", err)
	case <-time.After(150 * time.Millisecond):
	}
	if _, now := e.d.store.Snapshot(); now != before {
		t.Fatalf("the store changed while profileMu was held: revision %d -> %d", before, now)
	}
	e.d.tunnels.profileMu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ImportConfig: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ImportConfig did not finish after profileMu was released")
	}
}

// Whichever order a profile import and a config import land in, no credential
// outlives its profile and no run outlives its profile.
func TestConcurrentProfileImportAndConfigImportLeaveNoOrphan(t *testing.T) {
	e := newBuiltinEnv(t, newFakeKernel(), []string{"any.example.com"}, nil, nil)
	export := e.d.ExportConfig()

	for round := range 15 {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := e.d.ProfileImport(api.ProfileImportParams{
				Kind: "wireguard", Name: fmt.Sprintf("Race %d", round),
				WireguardConfig: wireGuardConfWith(wgPrivateKeyText, fmt.Sprintf("10.9.%d.2/24", round)),
			})
			if err != nil {
				t.Errorf("ProfileImport: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := e.d.ImportConfig(export); err != nil {
				t.Errorf("ImportConfig: %v", err)
			}
		}()
		wg.Wait()

		var ids []string
		for _, p := range e.d.store.Profiles() {
			ids = append(ids, p.ID)
		}
		e.secrets.mu.Lock()
		var orphans []string
		for id := range e.secrets.m {
			if !slices.Contains(ids, id) {
				orphans = append(orphans, id)
			}
		}
		e.secrets.mu.Unlock()
		if len(orphans) > 0 {
			t.Fatalf("round %d: credentials without a profile: %v", round, orphans)
		}
		// Leave a clean slate for the next round.
		for _, id := range ids {
			if err := e.d.ProfileRemove(id); err != nil {
				t.Fatalf("remove %s: %v", id, err)
			}
		}
	}
}
