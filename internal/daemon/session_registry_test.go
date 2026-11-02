package daemon

import (
	"slices"
	"testing"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/route"
	"github.com/quocln/routewise/internal/vpnclient"
)

func testSession(iface, client string) *tunnelSession {
	return &tunnelSession{iface: iface, client: vpnclient.Client{ID: client, Name: client}, manager: route.NewManager()}
}

func ifaces(sessions []*tunnelSession) []string {
	var out []string
	for _, s := range sessions {
		out = append(out, s.iface)
	}
	return out
}

func policyWithOrder(revision uint64, prev *routingPolicy, clients ...string) *routingPolicy {
	cfg := &config.Config{}
	for _, c := range clients {
		cfg.VPNs = append(cfg.VPNs, config.VPNRoute{Client: c})
	}
	return newRoutingPolicy(cfg, revision, prev)
}

func TestOrderedViewFollowsAllowlistPriorityThenInterfaceName(t *testing.T) {
	r := newSessionRegistry()
	r.add(testSession("utun9", "/b"))
	r.add(testSession("utun7", "/a"))
	r.add(testSession("utun3", "/b"))
	r.add(testSession("utun5", "/unlisted"))
	pol := policyWithOrder(1, nil, "/a", "/b")

	if got, want := ifaces(r.ordered(pol)), []string{"utun7", "utun3", "utun9", "utun5"}; !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestOrderedViewIsCachedUntilTheSessionsOrTheAllowlistOrderChange(t *testing.T) {
	r := newSessionRegistry()
	a, b := testSession("utun7", "/a"), testSession("utun9", "/b")
	r.add(a)
	r.add(b)
	pol := policyWithOrder(1, nil, "/a", "/b")

	first := r.ordered(pol)
	if again := r.ordered(pol); &again[0] != &first[0] {
		t.Error("an unchanged registry must serve the cached view")
	}
	// A commit that leaves the allowlist order alone keeps the cache.
	edited := newRoutingPolicy(&config.Config{
		Domains: domainRules([]string{"example.com"}),
		VPNs:    []config.VPNRoute{{Client: "/a"}, {Client: "/b"}},
	}, 2, pol)
	if again := r.ordered(edited); &again[0] != &first[0] {
		t.Error("a domain edit must not rebuild the view")
	}

	// A reorder rebuilds it.
	reordered := policyWithOrder(3, edited, "/b", "/a")
	if got, want := ifaces(r.ordered(reordered)), []string{"utun9", "utun7"}; !slices.Equal(got, want) {
		t.Errorf("after a reorder = %v, want %v", got, want)
	}

	// So does adding and removing a session.
	c := testSession("utun3", "/a")
	r.add(c)
	if got, want := ifaces(r.ordered(reordered)), []string{"utun9", "utun3", "utun7"}; !slices.Equal(got, want) {
		t.Errorf("after an add = %v, want %v", got, want)
	}
	r.remove(c)
	r.remove(testSession("utun7", "/a")) // a different value with a registered name is not removed
	if got, want := ifaces(r.ordered(reordered)), []string{"utun9", "utun7"}; !slices.Equal(got, want) {
		t.Errorf("after a remove = %v, want %v", got, want)
	}
}

func TestAppendingToTheOrderedViewNeverCorruptsIt(t *testing.T) {
	r := newSessionRegistry()
	r.add(testSession("utun7", "/a"))
	pol := policyWithOrder(1, nil, "/a")
	view := r.ordered(pol)
	_ = append(view, testSession("utun99", "/a"))
	if got := ifaces(r.ordered(pol)); !slices.Equal(got, []string{"utun7"}) {
		t.Fatalf("the cached view changed: %v", got)
	}
}

func TestTakeAllReturnsNewestFirstAndEmptiesTheRegistry(t *testing.T) {
	r := newSessionRegistry()
	for _, s := range []*tunnelSession{testSession("utun9", "/a"), testSession("utun3", "/b"), testSession("utun5", "/a")} {
		r.add(s)
	}
	if got, want := ifaces(r.takeAll()), []string{"utun5", "utun3", "utun9"}; !slices.Equal(got, want) {
		t.Fatalf("takeAll = %v, want newest first %v", got, want)
	}
	if r.has() || len(r.ordered(policyWithOrder(1, nil))) != 0 {
		t.Error("the registry must be empty after takeAll")
	}
}

func TestRegistryTracksDetectedSessionsAndRetiredManagers(t *testing.T) {
	r := newSessionRegistry()
	owned := testSession("utun9", "/a")
	owned.owned = true
	r.add(owned)
	if r.hasDetected() {
		t.Error("an owned session is not a detected one")
	}
	r.add(testSession("utun7", "/b"))
	if !r.hasDetected() {
		t.Error("a detected session must be reported")
	}
	if !r.isRegistered(owned) || r.isRegistered(nil) || r.isRegistered(testSession("utun9", "/a")) {
		t.Error("isRegistered must compare the session itself")
	}

	m := route.NewManager()
	r.retire(m)
	if got := r.retiredManagers(); len(got) != 1 || got[0] != m {
		t.Fatalf("retiredManagers = %v", got)
	}
	if got := r.takeRetired(); len(got) != 1 || len(r.retiredManagers()) != 0 {
		t.Fatalf("takeRetired = %v, then %v", got, r.retiredManagers())
	}
}
