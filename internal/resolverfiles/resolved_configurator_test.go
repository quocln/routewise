package resolverfiles

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

// fakeBackend records what the configurator asks of the system and lets a test
// raise the "resolved restarted" signal.
type fakeBackend struct {
	mu        sync.Mutex
	configure [][]string
	removes   int
	failNext  error
	restart   chan struct{}
	watching  chan struct{} // closed once WatchRestart is running
	watchOnce sync.Once
	stopped   chan struct{} // closed when WatchRestart returns
	server    netip.AddrPort
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		restart:  make(chan struct{}),
		watching: make(chan struct{}),
		stopped:  make(chan struct{}),
	}
}

func (f *fakeBackend) Configure(server netip.AddrPort, domains []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	f.server = server
	f.configure = append(f.configure, append([]string(nil), domains...))
	return nil
}

func (f *fakeBackend) Remove() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removes++
	return nil
}

func (f *fakeBackend) WatchRestart(ctx context.Context, fn func()) error {
	f.watchOnce.Do(func() { close(f.watching) })
	defer close(f.stopped)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-f.restart:
			fn()
		}
	}
}

func (f *fakeBackend) configures() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.configure...)
}

func testResolved(f *fakeBackend) *Resolved {
	return newResolved(f, netip.MustParseAddrPort("127.0.0.1:53053"))
}

func TestResolvedApplyConfiguresNormalizedDomains(t *testing.T) {
	f := newFakeBackend()
	r := testResolved(f)
	defer r.RemoveAll()

	skipped, err := r.Apply([]string{"Example.COM", "corp.example.org", "example.com"})
	if err != nil || len(skipped) != 0 {
		t.Fatalf("Apply = %v, %v; want no skips, nil", skipped, err)
	}
	want := []string{"corp.example.org", "example.com"}
	if got := f.configures(); !reflect.DeepEqual(got, [][]string{want}) {
		t.Errorf("configured %v, want %v", got, [][]string{want})
	}
	if got := r.Active(); !reflect.DeepEqual(got, want) {
		t.Errorf("Active = %v, want %v", got, want)
	}
	if f.server != netip.MustParseAddrPort("127.0.0.1:53053") {
		t.Errorf("server = %v, want the forwarder address", f.server)
	}
}

func TestResolvedApplyRejectsBadDomainBeforeTouchingTheSystem(t *testing.T) {
	f := newFakeBackend()
	r := testResolved(f)
	for _, d := range []string{"../etc", "bad domain.com", "single", "a.b;c.com"} {
		if _, err := r.Apply([]string{"ok.example.com", d}); err == nil {
			t.Errorf("Apply accepted %q", d)
		}
	}
	if n := len(f.configures()); n != 0 || r.Active() != nil {
		t.Errorf("a rejected Apply configured the system: %d calls, active %v", n, r.Active())
	}
}

func TestResolvedApplyReplacesTheWholeSet(t *testing.T) {
	f := newFakeBackend()
	r := testResolved(f)
	defer r.RemoveAll()

	r.Apply([]string{"a.example.com", "b.example.com"})
	r.Apply([]string{"b.example.com"})
	want := [][]string{{"a.example.com", "b.example.com"}, {"b.example.com"}}
	if got := f.configures(); !reflect.DeepEqual(got, want) {
		t.Errorf("configured %v, want %v", got, want)
	}
	if got := r.Active(); !reflect.DeepEqual(got, []string{"b.example.com"}) {
		t.Errorf("Active = %v", got)
	}
}

func TestResolvedApplyEmptyRemovesTheLink(t *testing.T) {
	f := newFakeBackend()
	r := testResolved(f)
	r.Apply([]string{"a.example.com"})
	<-f.watching
	if _, err := r.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if f.removes != 1 || r.Active() != nil {
		t.Errorf("removes = %d, active = %v; want 1, none", f.removes, r.Active())
	}
	select {
	case <-f.stopped:
	case <-time.After(2 * time.Second):
		t.Error("the restart watcher kept running after the link was removed")
	}
}

func TestResolvedRemoveAllWorksWithoutApply(t *testing.T) {
	f := newFakeBackend()
	r := testResolved(f)
	if err := r.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	// A link a previous process left behind is deleted even though this one
	// never applied anything.
	if f.removes != 1 {
		t.Errorf("removes = %d, want 1", f.removes)
	}
}

func TestResolvedApplyFailureIsReportedAndRetriedOnRestart(t *testing.T) {
	f := newFakeBackend()
	f.failNext = errors.New("resolved is not running")
	r := testResolved(f)
	defer r.RemoveAll()

	if _, err := r.Apply([]string{"a.example.com"}); err == nil {
		t.Fatal("Apply hid a backend failure")
	}
	if r.Active() != nil {
		t.Errorf("Active = %v after a failed Apply", r.Active())
	}

	// The watcher brings the configuration up once resolved appears.
	<-f.watching
	f.restart <- struct{}{}
	waitFor(t, func() bool { return len(r.Active()) == 1 })
}

func TestResolvedReappliesAfterResolvedRestarts(t *testing.T) {
	f := newFakeBackend()
	r := testResolved(f)
	defer r.RemoveAll()

	r.Apply([]string{"a.example.com"})
	<-f.watching
	f.restart <- struct{}{}
	waitFor(t, func() bool { return len(f.configures()) == 2 })
	if got := f.configures()[1]; !reflect.DeepEqual(got, []string{"a.example.com"}) {
		t.Errorf("reapplied %v, want the full desired set", got)
	}
}

func TestResolvedDoesNotReapplyAfterRemoveAll(t *testing.T) {
	f := newFakeBackend()
	r := testResolved(f)
	r.Apply([]string{"a.example.com"})
	<-f.watching
	r.RemoveAll()
	<-f.stopped
	if n := len(f.configures()); n != 1 {
		t.Errorf("configure calls = %d, want 1", n)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}
