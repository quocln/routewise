// Package activity keeps the recent routing decisions RouteWise made, so a
// user can see what goes through the VPN and what goes direct. The Log holds
// them in memory; they reach disk only through a Store, which the helper opens
// only while history.enabled is true, because the DNS lookup history they
// include is private and is never written to disk at the default log level.
package activity

import (
	"context"
	"sync"
	"time"
)

// Kind classifies an event.
type Kind string

const (
	// KindVPN is the VPN connecting or disconnecting.
	KindVPN Kind = "vpn"
	// KindRouteAdded is a /32 RouteWise added through the tunnel.
	KindRouteAdded Kind = "route_added"
	// KindRouteRemoved is a /32 RouteWise removed from the tunnel.
	KindRouteRemoved Kind = "route_removed"
	// KindRefused is an answer RouteWise would not route, with the reason.
	KindRefused Kind = "refused"
	// KindDNS is a DNS answer the machine received.
	KindDNS Kind = "dns"
)

// Verdict says where traffic to an address goes.
type Verdict string

const (
	// ViaVPN means RouteWise routes the address through the tunnel.
	ViaVPN Verdict = "vpn"
	// Direct means the address leaves through the local network.
	Direct Verdict = "direct"
)

// Address is one IP an event concerns and where traffic to it goes.
type Address struct {
	IP      string  `json:"ip"`
	Verdict Verdict `json:"verdict"`
	// Blocked marks an IPv6 address RouteWise made unreachable so apps use IPv4.
	Blocked bool `json:"blocked,omitempty"`
}

// Event is one entry in the activity log.
type Event struct {
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`
	Kind      Kind      `json:"kind"`
	Name      string    `json:"name,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
	Interface string    `json:"interface,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	// List is the client id of the domain list whose entry the event's name or
	// address matched: "" is the Any VPN list, nil is no list.
	List *string `json:"list,omitempty"`
	// Rule is the list entry it matched: a domain, a wildcard, an IP or a CIDR.
	Rule string `json:"rule,omitempty"`
	// VPN is the managed tunnel's client name the event concerns, when known.
	VPN string `json:"vpn,omitempty"`
}

// Log is a fixed-size ring of events, safe for concurrent use.
type Log struct {
	mu     sync.Mutex
	events []Event
	next   int    // index the next event is written to
	full   bool   // the ring has wrapped at least once
	seq    uint64 // sequence number of the newest event
	now    func() time.Time
	// changed is closed and replaced on every Add, waking every Wait.
	changed chan struct{}
}

// New returns a log that keeps the newest capacity events.
func New(capacity int) *Log {
	if capacity <= 0 {
		capacity = 1
	}
	return &Log{events: make([]Event, capacity), now: time.Now, changed: make(chan struct{})}
}

// Add records an event, stamping its sequence number and time.
func (l *Log) Add(e Event) Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	e.Seq = l.seq
	if e.Time.IsZero() {
		e.Time = l.now()
	}
	l.events[l.next] = e
	l.next = (l.next + 1) % len(l.events)
	if l.next == 0 {
		l.full = true
	}
	close(l.changed)
	l.changed = make(chan struct{})
	return e
}

// Resume continues the sequence numbering from seq, the highest number already
// stored, so a restart never reuses one. It only ever raises the sequence, and
// is meant for before the first Add.
func (l *Log) Resume(seq uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq = max(l.seq, seq)
}

// Covers reports whether the ring holds every event newer than since, so List
// is complete without the database: nothing newer exists, or the oldest event
// kept directly follows since.
func (l *Log) Covers(since uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seq <= since {
		return true
	}
	oldest := l.events[0]
	if l.full {
		oldest = l.events[l.next]
	} else if l.next == 0 {
		return false // events exist but none is in the ring: they predate it
	}
	return oldest.Seq <= since+1
}

// Wait blocks until an event newer than since exists, timeout passes, or ctx
// ends, so a client can long-poll and see each event the moment it happens.
func (l *Log) Wait(ctx context.Context, since uint64, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		l.mu.Lock()
		newer := l.seq > since
		changed := l.changed
		l.mu.Unlock()
		if newer {
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			return
		case <-ctx.Done():
			return
		}
	}
}

// List returns, oldest first, up to limit events newer than since. A limit of
// zero or less means no limit. When more than limit events are newer than
// since, the newest limit are returned, so a client that fell behind catches
// up with the present instead of paging through history.
func (l *Log) List(since uint64, limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.seq <= since {
		return nil
	}
	stored := l.next
	if l.full {
		stored = len(l.events)
	}
	// Stored events carry consecutive sequence numbers ending at l.seq, so the
	// ones newer than since are the last l.seq-since of them: only those are
	// copied, not the whole ring.
	n := stored
	if gap := l.seq - since; gap < uint64(n) {
		n = int(gap)
	}
	if limit > 0 && n > limit {
		n = limit
	}
	out := make([]Event, n)
	// The n newest events end just before l.next, wrapping around the ring.
	tail := min(n, l.next)
	copy(out[n-tail:], l.events[l.next-tail:l.next])
	if n > tail {
		copy(out, l.events[len(l.events)-(n-tail):])
	}
	return out
}

// Latest returns the sequence number of the newest event, or 0 when empty.
func (l *Log) Latest() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}
