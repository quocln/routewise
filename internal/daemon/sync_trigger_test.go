package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/api"
)

// allowAll admits every peer, so a test can drive the RPC handler.
type allowAll struct{}

func (allowAll) AllowMutation(api.Peer) error { return nil }

// promptSyncBound is far below the one-second poll the trigger replaced, and
// far above the time a sync takes in a test.
const promptSyncBound = 400 * time.Millisecond

func rpcCall(t *testing.T, h *api.Handler, method string, params any) *api.Response {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return h.Handle(&api.Request{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}, api.Peer{UID: 0, Verified: true})
}

func waitWithin(t *testing.T, bound time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %v", what, bound)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestDomainRPCsSyncRoutesPromptly(t *testing.T) {
	env := newTunnelEnv(t, nil, []string{"wg.example.com"}, nil, nil)
	env.answers.set("wg.example.com", "10.100.0.1")
	env.answers.set("added.example.com", "10.100.0.2")
	env.answers.set("set.example.com", "10.100.0.3")
	env.connectWG()
	waitForRoutes(t, env.d, wgIface, "10.100.0.1")
	h := api.NewHandler(env.d, allowAll{})

	if resp := rpcCall(t, h, api.MethodDomainsAdd, api.AddDomainParams{VPN: wireGuardPath, Pattern: "added.example.com"}); resp.Error != nil {
		t.Fatalf("domains.add: %+v", resp.Error)
	}
	waitWithin(t, promptSyncBound, "the route for an added domain", func() bool { return holds(env.d, wgIface, "10.100.0.2") })

	if resp := rpcCall(t, h, api.MethodDomainsSet, api.SetDomainsParams{VPN: wireGuardPath, Patterns: []string{"set.example.com"}}); resp.Error != nil {
		t.Fatalf("domains.set: %+v", resp.Error)
	}
	waitWithin(t, promptSyncBound, "the routes after a domains.set", func() bool {
		return holds(env.d, wgIface, "10.100.0.3") && !holds(env.d, wgIface, "10.100.0.2")
	})

	if resp := rpcCall(t, h, api.MethodDomainsRemove, api.RemoveDomainParams{VPN: wireGuardPath, Pattern: "set.example.com"}); resp.Error != nil {
		t.Fatalf("domains.remove: %+v", resp.Error)
	}
	waitWithin(t, promptSyncBound, "the route of a removed domain to go", func() bool { return !holds(env.d, wgIface, "10.100.0.3") })
}

func TestTriggerSyncRequestsMergeAndDoNotBlock(t *testing.T) {
	env := newTunnelEnv(t, []string{"any.example.com"}, nil, nil, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			env.d.TriggerSync()
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TriggerSync blocked while a request was pending")
	}
	if got := len(env.d.syncTrigger); got > 1 {
		t.Fatalf("pending sync requests = %d, want them merged into one", got)
	}
}

func TestStopDropsAPendingSyncRequest(t *testing.T) {
	d, _, _, _ := newDNSTestDaemonWith(t, nil, "example.com")
	d.TriggerSync()
	d.Stop()
	if got := len(d.syncTrigger); got != 0 {
		t.Fatalf("a request raised before Stop stayed pending (%d)", got)
	}
}
