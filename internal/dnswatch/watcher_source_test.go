package dnswatch

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSource feeds scripted frame batches to a watcher and reports a
// settable kernel drop count. Closing batches ends the capture with an error.
type fakeSource struct {
	batches chan [][]byte
	drops   atomic.Uint64
	closed  atomic.Bool
}

func newFakeSource() *fakeSource { return &fakeSource{batches: make(chan [][]byte)} }

func (f *fakeSource) ifaceName() string { return "en9" }
func (f *fakeSource) linkType() int     { return dltRaw }
func (f *fakeSource) close()            { f.closed.Store(true) }
func (f *fakeSource) kernelDrops() (uint64, error) {
	return f.drops.Load(), nil
}
func (f *fakeSource) read() ([][]byte, error) {
	b, ok := <-f.batches
	if !ok {
		return nil, errors.New("device gone")
	}
	return b, nil
}

func syncWithSources(w *Watcher, srcs ...*fakeSource) {
	next := 0
	w.open = func(string) (packetSource, error) {
		s := srcs[next]
		next++
		return s, nil
	}
	ifaces := make([]string, len(srcs))
	for i := range ifaces {
		ifaces[i] = string(rune('a' + i))
	}
	w.Sync(ifaces)
}

func TestWatcherDeliversFramesFromASource(t *testing.T) {
	w, rec, _ := newTestWatcher("10.0.0.2")
	src := newFakeSource()
	syncWithSources(w, src)

	syn := ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagSYN, nil))
	src.batches <- [][]byte{syn}
	close(src.batches)
	w.Stop()

	flows := rec.all()
	if len(flows) != 1 || flows[0].Interface != "en9" {
		t.Fatalf("flows = %+v, want one flow tagged with the source interface", flows)
	}
	if !src.closed.Load() {
		t.Error("the source must be closed when its reader ends")
	}
}

func TestWatcherCountsKernelDropsAcrossCaptures(t *testing.T) {
	w, _, _ := newTestWatcher("10.0.0.2")
	// The readers consult the clock while the test advances it.
	var offset atomic.Int64
	base := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return base.Add(time.Duration(offset.Load())) }
	first, second := newFakeSource(), newFakeSource()
	syncWithSources(w, first, second)

	first.drops.Store(5)
	offset.Store(int64(dropPollInterval + time.Second))
	first.batches <- nil // a timeout read; the poll is due after it
	first.drops.Store(9)
	close(first.batches) // the final poll on exit picks up the rest
	second.drops.Store(3)
	close(second.batches)
	w.Stop()

	if got := w.Dropped(); got != 12 {
		t.Errorf("Dropped = %d, want 12 (9 + 3)", got)
	}
}

func TestWatcherDropCountIgnoresACounterThatGoesBackwards(t *testing.T) {
	w, _, _ := newTestWatcher("10.0.0.2")
	src := newFakeSource()
	syncWithSources(w, src)
	src.drops.Store(4)
	close(src.batches)
	w.Stop()
	if got := w.Dropped(); got != 4 {
		t.Fatalf("Dropped = %d, want 4", got)
	}
}
