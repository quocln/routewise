package daemon

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/dnswatch"
)

func answerNamed(name string) dnswatch.Answer {
	return dnswatch.Answer{Name: name, Addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
}

type answerCollector struct {
	mu    sync.Mutex
	names []string
}

func (c *answerCollector) add(a dnswatch.Answer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.names = append(c.names, a.Name)
}

func (c *answerCollector) got() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.names)
}

func TestAnswersAreReleasedInOrderOnlyAfterTheSettleDelay(t *testing.T) {
	q := newAnswerQueue(80 * time.Millisecond)
	var c answerCollector
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); q.run(ctx, c.add) }()

	start := time.Now()
	for _, name := range []string{"a", "b", "c"} {
		q.push(answerNamed(name))
	}
	time.Sleep(30 * time.Millisecond)
	if got := c.got(); len(got) != 0 {
		t.Fatalf("answers released before the delay: %v", got)
	}
	waitFor(t, "all three answers", func() bool { return len(c.got()) == 3 })
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Errorf("released after %v, before the settle delay", elapsed)
	}
	if got := c.got(); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("release order = %v", got)
	}

	// An answer pushed while the loop idles wakes it.
	q.push(answerNamed("d"))
	waitFor(t, "a late answer", func() bool { return len(c.got()) == 4 })

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop when its context ended")
	}
}

func TestAnswersStillWaitingWhenTheLoopStopsAreNeverReleased(t *testing.T) {
	q := newAnswerQueue(time.Hour)
	var c answerCollector
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); q.run(ctx, c.add) }()
	q.push(answerNamed("late"))
	cancel()
	<-done
	if got := c.got(); len(got) != 0 {
		t.Fatalf("released %v after shutdown", got)
	}
}

func TestTheAnswerQueueIsBounded(t *testing.T) {
	q := newAnswerQueue(time.Hour)
	for i := range maxQueuedAnswers {
		if !q.push(answerNamed("x")) {
			t.Fatalf("answer %d refused below the bound", i)
		}
	}
	if q.push(answerNamed("overflow")) {
		t.Fatal("an answer beyond the bound must be refused")
	}
}

func TestCapturedAnswersAreRecordedOnceSettledAndNothingFiresAfterStop(t *testing.T) {
	d, _, _, _ := newDNSTestDaemonWith(t, nil, "api.rw-test.invalid")
	d.answers.delay = 40 * time.Millisecond

	d.onDNSAnswer(answerNamed("settled.example.com"))
	if got := len(eventsOfKind(d, activity.KindDNS)); got != 0 {
		t.Fatalf("recorded %d events before the settle delay", got)
	}
	waitFor(t, "the answer to be recorded", func() bool { return len(eventsOfKind(d, activity.KindDNS)) == 1 })

	d.onDNSAnswer(answerNamed("after-stop.example.com"))
	d.Stop()
	time.Sleep(120 * time.Millisecond)
	for _, e := range eventsOfKind(d, activity.KindDNS) {
		if e.Name == "after-stop.example.com" {
			t.Fatal("an answer queued before Stop was recorded after it")
		}
	}
}
