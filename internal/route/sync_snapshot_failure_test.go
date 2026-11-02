package route

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// netstatFails stands for a routing table that cannot be read at the moment.
type netstatFails struct{ *fakeRunner }

func (r netstatFails) Run(ctx context.Context, tool string, args ...string) (string, error) {
	if tool == toolNetstat {
		return "", errors.New("netstat: command output exceeded maximum size")
	}
	return r.fakeRunner.Run(ctx, tool, args...)
}

// A routing table that cannot be read is a transient fault, not a reason to
// record a pending item that never clears and stops all routing for the session.
func TestSyncRoutesKeepsRoutingWhenTheTableCannotBeRead(t *testing.T) {
	m, fake := newTestManager(t)
	m.table = newCommandTable(netstatFails{fake})
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun5)

	if err := m.SyncRoutes(map[netip.Addr]string{netip.MustParseAddr("1.1.1.1"): "example.com"}); err != nil {
		t.Fatalf("SyncRoutes: %v", err)
	}
	if pending := m.PendingCleanup(); len(pending) != 0 {
		t.Fatalf("a failed table read left pending items: %+v", pending)
	}
	if degraded, why := m.Degraded(); degraded {
		t.Fatalf("manager degraded after a transient read failure: %s", why)
	}
	added := false
	for _, call := range fake.callLog {
		added = added || strings.HasPrefix(call, "route -n add -host 1.1.1.1")
	}
	if !added {
		t.Fatalf("the route was not added: %v", fake.callLog)
	}
}
