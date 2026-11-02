package activity

import (
	"context"
	"sync"
	"testing"
	"time"
)

func names(events []Event) []string {
	var out []string
	for _, e := range events {
		out = append(out, e.Name)
	}
	return out
}

func TestListReturnsEventsNewerThanSinceOldestFirst(t *testing.T) {
	l := New(10)
	for _, n := range []string{"a", "b", "c"} {
		l.Add(Event{Kind: KindDNS, Name: n})
	}

	if got := names(l.List(0, 0)); len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("List(0) = %v, want [a b c]", got)
	}
	if got := names(l.List(2, 0)); len(got) != 1 || got[0] != "c" {
		t.Fatalf("List(2) = %v, want [c]", got)
	}
	if got := l.List(3, 0); len(got) != 0 {
		t.Fatalf("List(latest) = %v, want nothing new", got)
	}
}

func TestRingKeepsOnlyTheNewestEvents(t *testing.T) {
	l := New(3)
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		l.Add(Event{Kind: KindDNS, Name: n})
	}

	if got := names(l.List(0, 0)); len(got) != 3 || got[0] != "c" || got[2] != "e" {
		t.Fatalf("List = %v, want the newest three [c d e]", got)
	}
	if l.Latest() != 5 {
		t.Fatalf("Latest = %d, want 5: sequence numbers keep counting past the ring size", l.Latest())
	}
}

func TestLimitKeepsTheNewestEvents(t *testing.T) {
	l := New(10)
	for _, n := range []string{"a", "b", "c", "d"} {
		l.Add(Event{Kind: KindDNS, Name: n})
	}

	if got := names(l.List(0, 2)); len(got) != 2 || got[0] != "c" || got[1] != "d" {
		t.Fatalf("List(0, 2) = %v, want [c d]", got)
	}
}

func TestAddStampsSequenceAndTime(t *testing.T) {
	l := New(2)
	e := l.Add(Event{Kind: KindVPN})
	if e.Seq != 1 || e.Time.IsZero() {
		t.Fatalf("Add = %+v, want seq 1 and a time", e)
	}
}

func TestConcurrentAddAndList(t *testing.T) {
	l := New(50)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 100 {
				l.Add(Event{Kind: KindDNS})
			}
		}()
		go func() {
			defer wg.Done()
			for range 100 {
				_ = l.List(0, 10)
			}
		}()
	}
	wg.Wait()
	if l.Latest() != 800 {
		t.Fatalf("Latest = %d, want 800", l.Latest())
	}
}

func TestWaitReturnsAsSoonAsAnEventArrives(t *testing.T) {
	l := New(10)
	l.Add(Event{Kind: KindDNS})

	go func() {
		time.Sleep(50 * time.Millisecond)
		l.Add(Event{Kind: KindDNS, Name: "new"})
	}()
	start := time.Now()
	l.Wait(context.Background(), 1, 5*time.Second)
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("Wait took %v, want it to return once the new event arrived", waited)
	}
	if got := l.List(1, 0); len(got) != 1 || got[0].Name != "new" {
		t.Fatalf("List after Wait = %+v", got)
	}
}

func TestWaitReturnsAtOnceWhenAlreadyBehindAndOnTimeout(t *testing.T) {
	l := New(10)
	l.Add(Event{Kind: KindDNS})

	start := time.Now()
	l.Wait(context.Background(), 0, 5*time.Second)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("a caller that is already behind must not wait")
	}

	start = time.Now()
	l.Wait(context.Background(), 1, 50*time.Millisecond)
	if waited := time.Since(start); waited < 40*time.Millisecond {
		t.Fatalf("Wait returned after %v without a new event, want the timeout", waited)
	}
}

func TestListAcrossTheRingWrapAndAfterResume(t *testing.T) {
	l := New(4)
	l.Resume(100)
	for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
		l.Add(Event{Kind: KindDNS, Name: n})
	}
	// Seqs 101-106 were added; the ring keeps c-f (103-106) across a wrap.
	for _, tt := range []struct {
		since uint64
		limit int
		want  string
	}{
		{0, 0, "cdef"}, {100, 0, "cdef"}, {103, 0, "def"}, {105, 0, "f"}, {106, 0, ""},
		{0, 3, "def"}, {104, 5, "ef"}, {0, 1, "f"}, {200, 0, ""},
	} {
		got := ""
		for _, e := range l.List(tt.since, tt.limit) {
			got += e.Name
		}
		if got != tt.want {
			t.Errorf("List(%d, %d) = %q, want %q", tt.since, tt.limit, got, tt.want)
		}
	}
}

func BenchmarkListOneNewEventFromAFullRing(b *testing.B) {
	l := New(2000)
	for range 2500 {
		l.Add(Event{Kind: KindDNS, Name: "example.com", Detail: "answered"})
	}
	since := l.Latest() - 1
	b.ReportAllocs()
	for b.Loop() {
		l.List(since, 200)
	}
}
