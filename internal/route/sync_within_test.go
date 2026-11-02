package route

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// slowRoute makes every route tool call take as long as one /sbin/route
// process does on macOS.
type slowRoute struct {
	*fakeRunner
	delay time.Duration
}

func (r slowRoute) Run(ctx context.Context, tool string, args ...string) (string, error) {
	if tool == toolRoute {
		time.Sleep(r.delay)
	}
	return r.fakeRunner.Run(ctx, tool, args...)
}

func desiredAddrs(n int) map[netip.Addr]string {
	desired := make(map[netip.Addr]string, n)
	for i := range n {
		desired[netip.MustParseAddr(fmt.Sprintf("93.184.%d.%d", i/200, i%200+1))] = "example.com"
	}
	return desired
}

func slowManager(t *testing.T, delay time.Duration) *Manager {
	t.Helper()
	m, fake := newTestManager(t)
	m.table = newCommandTable(slowRoute{fakeRunner: fake, delay: delay})
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun5)
	return m
}

func TestSyncRoutesWithinConvergesInSlices(t *testing.T) {
	m := slowManager(t, 2*time.Millisecond)
	desired := desiredAddrs(60)

	passes := 0
	var longest time.Duration
	for {
		start := time.Now()
		more, err := m.SyncRoutesWithin(desired, 20*time.Millisecond)
		longest = max(longest, time.Since(start))
		if err != nil {
			t.Fatal(err)
		}
		passes++
		if !more {
			break
		}
		if passes > 60 {
			t.Fatal("the sync did not converge")
		}
	}
	if got := len(m.GetActiveRoutes()); got != len(desired) {
		t.Fatalf("%d routes active, want %d", got, len(desired))
	}
	if passes < 3 {
		t.Fatalf("passes = %d, want the work split into slices", passes)
	}
	if longest > 20*time.Millisecond+10*time.Millisecond+2*time.Millisecond {
		t.Fatalf("a pass held the lock for %v, want about the 20ms budget", longest)
	}
}

func TestSyncRoutesWithinRemovesInSlicesToo(t *testing.T) {
	m := slowManager(t, time.Millisecond)
	if err := m.SyncRoutes(desiredAddrs(40)); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		more, err := m.SyncRoutesWithin(map[netip.Addr]string{}, 5*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
	}
	if got := len(m.GetActiveRoutes()); got != 0 {
		t.Fatalf("%d routes left, want all removed", got)
	}
}

// A budget of zero is the whole sync in one call, as SyncRoutes always was.
func TestSyncRoutesWithoutABudgetFinishesInOneCall(t *testing.T) {
	m := slowManager(t, time.Millisecond)
	more, err := m.SyncRoutesWithin(desiredAddrs(30), 0)
	if err != nil || more || len(m.GetActiveRoutes()) != 30 {
		t.Fatalf("more=%v err=%v routes=%d", more, err, len(m.GetActiveRoutes()))
	}
}

// Changes that keep failing are not retried forever: a pass that changed
// nothing does not ask for another.
func TestSyncRoutesWithinStopsWhenNothingCanBeChanged(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun5)
	desired := desiredAddrs(30)
	for ip := range desired {
		fake.failNextCall("add_host "+ip.String(), fmt.Errorf("network is unreachable"))
	}
	m.table = newCommandTable(slowRoute{fakeRunner: fake, delay: 3 * time.Millisecond})
	more, _ := m.SyncRoutesWithin(desired, 10*time.Millisecond)
	if more || len(m.GetActiveRoutes()) != 0 {
		t.Fatalf("more=%v with %d routes: a pass that changed nothing must not ask for another", more, len(m.GetActiveRoutes()))
	}
}

// lookupLatency runs a sync of n routes and, while it runs, adds one route as
// a DNS answer would. It returns how long that add waited and how long the
// whole sync took.
func lookupLatency(t *testing.T, budget time.Duration, n int) (wait, total time.Duration) {
	t.Helper()
	m := slowManager(t, 6700*time.Microsecond) // one /sbin/route process
	desired := desiredAddrs(n)

	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-started
		time.Sleep(50 * time.Millisecond)
		begin := time.Now()
		if err := m.AddRoute(netip.MustParseAddr("198.51.100.7"), "answer.example", false); err != nil {
			t.Error(err)
		}
		wait = time.Since(begin)
	}()

	begin := time.Now()
	close(started)
	for {
		more, err := m.SyncRoutesWithin(desired, budget)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
		time.Sleep(2 * time.Millisecond) // the daemon's pause between passes
	}
	total = time.Since(begin)
	wg.Wait()
	return wait, total
}

// TestAnAnswerDoesNotWaitForABulkSync measures the stall a DNS answer sees
// behind a first sync, with a route tool that takes 6.7ms per call as on macOS.
func TestAnAnswerDoesNotWaitForABulkSync(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about a second")
	}
	const routes = 100
	whole, wholeTotal := lookupLatency(t, 0, routes)
	sliced, slicedTotal := lookupLatency(t, 100*time.Millisecond, routes)
	t.Logf("%d routes: answer waited %v behind one unbroken sync (sync %v); %v with 100ms slices (sync %v)",
		routes, whole.Round(time.Millisecond), wholeTotal.Round(time.Millisecond), sliced.Round(time.Millisecond), slicedTotal.Round(time.Millisecond))
	if sliced > 250*time.Millisecond {
		t.Fatalf("an answer waited %v behind a sliced sync, want about one slice (100ms)", sliced)
	}
	if whole < 3*sliced {
		t.Fatalf("expected the unbroken sync to stall the answer far longer: %v vs %v", whole, sliced)
	}
}
