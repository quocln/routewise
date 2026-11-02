// Package history keeps what this Mac connected to: a bounded map from IP to
// the name it was recently resolved from, and a SQLite store of access records.
package history

import (
	"container/heap"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// MaxNames bounds the IP-to-name map.
	MaxNames = 20000
	// MinNameLifetime is the shortest an entry lives: a connection opened on
	// an answer keeps using the address long after the answer's TTL.
	MinNameLifetime = time.Hour
)

type nameEntry struct {
	name    string
	expires time.Time
	// seq is when the entry was last written, to find the oldest on overflow.
	seq uint64
}

type queued struct {
	ip  netip.Addr
	seq uint64
	// expires is the entry's expiry when it was written; only the expiry heap
	// reads it.
	expires time.Time
}

// expiryHeap is a min-heap on expires, so a full map can drop every expired
// entry without scanning the live ones.
type expiryHeap []queued

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(queued)) }
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// NameMap remembers which name an IP address was most recently resolved from.
// It is safe for concurrent use; its lock is a leaf.
type NameMap struct {
	now func() time.Time
	max int

	mu      sync.Mutex
	entries map[netip.Addr]nameEntry
	// order lists writes oldest first. A write of an IP already present
	// leaves its older item behind; seq tells a live item from a stale one.
	order []queued
	// byExpiry holds the same writes keyed by expiry, with the same stale
	// items.
	byExpiry expiryHeap
	seq      uint64
}

// NewNameMap returns an empty map bounded at MaxNames entries.
func NewNameMap() *NameMap { return newNameMap(time.Now, MaxNames) }

func newNameMap(now func() time.Time, max int) *NameMap {
	return &NameMap{now: now, max: max, entries: make(map[netip.Addr]nameEntry)}
}

// Add records name for every ip. Each entry lives max(ttl, 1h); a later Add
// for the same address replaces the name.
func (m *NameMap) Add(name string, ips []netip.Addr, ttl time.Duration) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" || len(ips) == 0 {
		return
	}
	expires := m.now().Add(max(ttl, MinNameLifetime))

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() {
			continue
		}
		m.seq++
		m.entries[ip] = nameEntry{name: name, expires: expires, seq: m.seq}
		item := queued{ip: ip, seq: m.seq, expires: expires}
		m.order = append(m.order, item)
		heap.Push(&m.byExpiry, item)
	}
	m.trimLocked()
}

// Lookup returns the most recent unexpired name for ip.
func (m *NameMap) Lookup(ip netip.Addr) (string, bool) {
	ip = ip.Unmap()
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[ip]
	if !ok {
		return "", false
	}
	if !m.now().Before(e.expires) {
		delete(m.entries, ip)
		return "", false
	}
	return e.name, true
}

// Len returns how many entries the map holds, expired ones included.
func (m *NameMap) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// trimLocked enforces the bound: expired entries go first, then the least
// recently written.
func (m *NameMap) trimLocked() {
	if len(m.entries) > m.max {
		now := m.now()
		for len(m.byExpiry) > 0 && !now.Before(m.byExpiry[0].expires) {
			head := heap.Pop(&m.byExpiry).(queued)
			if m.liveLocked(head) {
				delete(m.entries, head.ip)
			}
		}
	}
	for len(m.entries) > m.max && len(m.order) > 0 {
		head := m.order[0]
		m.order = m.order[1:]
		if m.liveLocked(head) {
			delete(m.entries, head.ip)
		}
	}
	// Repeated writes leave stale items; rebuild when they dominate.
	if len(m.order) > 2*m.max+16 || len(m.byExpiry) > 2*m.max+16 {
		live := make([]queued, 0, len(m.entries))
		for _, q := range m.order {
			if m.liveLocked(q) {
				live = append(live, q)
			}
		}
		m.order = live
		m.byExpiry = append(expiryHeap(nil), live...)
		heap.Init(&m.byExpiry)
	}
}

// liveLocked reports whether q is the latest write of its address, as opposed
// to an item left behind by a later write or an eviction.
func (m *NameMap) liveLocked(q queued) bool {
	e, ok := m.entries[q.ip]
	return ok && e.seq == q.seq
}
