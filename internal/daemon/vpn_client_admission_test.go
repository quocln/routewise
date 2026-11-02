package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/testenv"
	"github.com/quocln/routewise/internal/vpnclient"
)

var wireGuardPath = testenv.Exe("/Applications/WireGuard.app/Contents/PlugIns/WireGuardNetworkExtension.appex/Contents/MacOS/WireGuardNetworkExtension")

func TestATunnelIsManagedOnlyOnceItsClientIsAllowed(t *testing.T) {
	var lookups atomic.Int32
	d, _, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.identifyClient = func(context.Context, string) (vpnclient.Client, error) {
			lookups.Add(1)
			return vpnclient.FromPath(wireGuardPath), nil
		}
	}, "api.rw-test.invalid")

	if d.admitTunnel("utun6") {
		t.Fatal("a client that is not on the allowlist must not be managed")
	}
	_, pending := d.VPNClients()
	if len(pending) != 1 || pending[0].Interface != "utun6" || pending[0].Client.Name != "WireGuard" {
		t.Fatalf("pending = %+v, want utun6 from WireGuard waiting for approval", pending)
	}

	if err := d.SetVPNClientAllowed(wireGuardPath, true); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if !d.admitTunnel("utun6") {
		t.Fatal("an allowed client's tunnel must be managed")
	}
	if got := d.Settings().AllowedVPNClients; len(got) != 1 || got[0].Name != "WireGuard" {
		t.Fatalf("allowed clients = %+v, want WireGuard", got)
	}
	if cfg, _ := d.store.Snapshot(); len(cfg.VPNs) != 1 {
		t.Fatal("the allowlist must be saved to the config")
	}
	if lookups.Load() != 1 {
		t.Fatalf("the owner was looked up %d times, want once thanks to the cache", lookups.Load())
	}

	if err := d.SetVPNClientAllowed(wireGuardPath, false); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if d.admitTunnel("utun6") {
		t.Fatal("a revoked client's tunnel must be handed back")
	}
}

func TestATunnelWhoseOwnerIsUnknownIsLeftAlone(t *testing.T) {
	d, _, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.identifyClient = func(context.Context, string) (vpnclient.Client, error) {
			return vpnclient.Client{}, errors.New("no process owns utun6")
		}
	}, "api.rw-test.invalid")

	if d.admitTunnel("utun6") {
		t.Fatal("a tunnel whose owner cannot be identified must never be managed")
	}
	if _, pending := d.VPNClients(); len(pending) != 1 || pending[0].Client.ID != "" {
		t.Fatalf("pending = %+v, want an unidentified tunnel that cannot be allowed", pending)
	}
	if err := d.SetVPNClientAllowed("", true); err == nil {
		t.Fatal("an empty client id must be rejected")
	}
}

// A managed tunnel's owner is asked for once; the monitor's polls after that
// only re-check the allowlist, however long the tunnel stays up.
func TestAManagedTunnelsOwnerIsIdentifiedOnceForTheLifeOfTheInterface(t *testing.T) {
	var lookups atomic.Int32
	d, _, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.identifyClient = func(context.Context, string) (vpnclient.Client, error) {
			lookups.Add(1)
			return vpnclient.FromPath(wireGuardPath), nil
		}
	}, "api.rw-test.invalid")
	if err := d.SetVPNClientAllowed(wireGuardPath, true); err != nil {
		t.Fatal(err)
	}

	expire := func() {
		d.clientMu.Lock()
		defer d.clientMu.Unlock()
		for iface, c := range d.clientCache {
			c.at = c.at.Add(-time.Hour)
			d.clientCache[iface] = c
		}
	}
	for range 5 {
		if !d.admitTunnel("utun6") {
			t.Fatal("an allowed client's tunnel must be managed")
		}
		expire()
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("a managed tunnel was identified %d times, want once", got)
	}

	// The disconnect forgets the owner: a name macOS reuses is a new tunnel.
	d.forgetClient("utun6")
	if !d.admitTunnel("utun6") || lookups.Load() != 2 {
		t.Fatalf("after the interface went away the owner must be identified again; lookups = %d", lookups.Load())
	}

	// Revoking the client ends the exemption: the cached answer then expires
	// like any other.
	if err := d.SetVPNClientAllowed(wireGuardPath, false); err != nil {
		t.Fatal(err)
	}
	if d.admitTunnel("utun6") {
		t.Fatal("a revoked client's tunnel must be handed back")
	}
	expire()
	d.admitTunnel("utun6")
	if lookups.Load() != 3 {
		t.Fatalf("a tunnel that is not managed must be identified again after the cache expires; lookups = %d", lookups.Load())
	}
}

// An owner that cannot be found is not looked for at every monitor check: the
// failure is remembered and retried after a doubling wait.
func TestAFailedIdentificationIsRetriedWithGrowingBackoff(t *testing.T) {
	var lookups atomic.Int32
	d, _, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.identifyClient = func(context.Context, string) (vpnclient.Client, error) {
			lookups.Add(1)
			return vpnclient.Client{}, errors.New("no process owns utun6")
		}
	}, "api.rw-test.invalid")

	for range 20 {
		if d.admitTunnel("utun6") {
			t.Fatal("an unidentified tunnel must not be managed")
		}
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("lookups = %d, want the failure cached across checks", got)
	}

	due := func() {
		d.clientMu.Lock()
		defer d.clientMu.Unlock()
		c := d.clientCache["utun6"]
		c.retryAt = time.Now().Add(-time.Millisecond)
		d.clientCache["utun6"] = c
	}
	due()
	d.admitTunnel("utun6")
	if got := lookups.Load(); got != 2 {
		t.Fatalf("lookups = %d, want a retry once the wait has passed", got)
	}
	d.clientMu.Lock()
	c := d.clientCache["utun6"]
	d.clientMu.Unlock()
	if c.failures != 2 || time.Until(c.retryAt) < identifyBackoffMin || time.Until(c.retryAt) > 2*identifyBackoffMin {
		t.Fatalf("after two failures want a wait of about %v, got failures=%d retry in %v", 2*identifyBackoffMin, c.failures, time.Until(c.retryAt))
	}

	// A recreated link (new interface index) is a new tunnel: no backoff applies.
	d.clientMu.Lock()
	c = d.clientCache["utun6"]
	c.index = 12345
	d.clientCache["utun6"] = c
	d.clientMu.Unlock()
	d.admitTunnel("utun6")
	if got := lookups.Load(); got != 3 {
		t.Fatalf("lookups = %d, want the changed link looked up at once", got)
	}

	// The disconnect forgets the failure too.
	d.forgetClient("utun6")
	d.admitTunnel("utun6")
	if got := lookups.Load(); got != 4 {
		t.Fatalf("lookups = %d, want a forgotten interface looked up again", got)
	}
}

func TestIdentifyBackoffDoublesUpToItsCap(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		if got := identifyBackoff(i + 1); got != w*time.Second {
			t.Errorf("identifyBackoff(%d) = %v, want %v", i+1, got, w*time.Second)
		}
	}
	if got := identifyBackoff(1 << 20); got != identifyBackoffMax {
		t.Errorf("identifyBackoff(huge) = %v, want %v", got, identifyBackoffMax)
	}
}
