package history

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

func ips(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, v := range s {
		out[i] = netip.MustParseAddr(v)
	}
	return out
}

func TestNameMapReturnsTheMostRecentName(t *testing.T) {
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	m := newNameMap(func() time.Time { return now }, 100)

	m.Add("A.Example.com.", ips("1.2.3.4", "1.2.3.5"), time.Minute)
	m.Add("b.example.com", ips("1.2.3.4"), time.Minute)

	if name, ok := m.Lookup(netip.MustParseAddr("1.2.3.4")); !ok || name != "b.example.com" {
		t.Errorf("1.2.3.4 = %q %v, want the later name", name, ok)
	}
	if name, ok := m.Lookup(netip.MustParseAddr("1.2.3.5")); !ok || name != "a.example.com" {
		t.Errorf("1.2.3.5 = %q %v, want a normalized name", name, ok)
	}
	if _, ok := m.Lookup(netip.MustParseAddr("9.9.9.9")); ok {
		t.Error("an unknown address has no name")
	}
	if name, ok := m.Lookup(netip.MustParseAddr("::ffff:1.2.3.4")); !ok || name != "b.example.com" {
		t.Errorf("an IPv4-mapped address must find the IPv4 entry, got %q %v", name, ok)
	}
}

func TestNameMapEntriesLiveAtLeastAnHourOrTheirTTL(t *testing.T) {
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	m := newNameMap(func() time.Time { return now }, 100)
	m.Add("short.example.com", ips("1.1.1.1"), 30*time.Second)
	m.Add("long.example.com", ips("2.2.2.2"), 3*time.Hour)

	now = now.Add(59 * time.Minute)
	if _, ok := m.Lookup(netip.MustParseAddr("1.1.1.1")); !ok {
		t.Error("a 30s TTL still lives for an hour")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := m.Lookup(netip.MustParseAddr("1.1.1.1")); ok {
		t.Error("the entry must expire after an hour")
	}
	if _, ok := m.Lookup(netip.MustParseAddr("2.2.2.2")); !ok {
		t.Error("a 3h TTL outlives the one-hour minimum")
	}
	now = now.Add(3 * time.Hour)
	if _, ok := m.Lookup(netip.MustParseAddr("2.2.2.2")); ok {
		t.Error("the entry must expire after its TTL")
	}
}

func TestNameMapIsBoundedAndEvictsTheOldest(t *testing.T) {
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	m := newNameMap(func() time.Time { return now }, 50)
	for i := range 120 {
		m.Add("host.example.com", []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}, 0)
	}
	if m.Len() > 50 {
		t.Fatalf("len = %d, want at most 50", m.Len())
	}
	if _, ok := m.Lookup(netip.AddrFrom4([4]byte{10, 0, 0, 119})); !ok {
		t.Error("the newest entry must survive")
	}
	if _, ok := m.Lookup(netip.AddrFrom4([4]byte{10, 0, 0, 0})); ok {
		t.Error("the oldest entry must be evicted")
	}
}

func TestNameMapKeepsARefreshedEntryOverOlderOnes(t *testing.T) {
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	m := newNameMap(func() time.Time { return now }, 3)
	m.Add("old.example.com", ips("10.0.0.1"), 0)
	m.Add("b.example.com", ips("10.0.0.2"), 0)
	m.Add("c.example.com", ips("10.0.0.3"), 0)
	m.Add("fresh.example.com", ips("10.0.0.1"), 0) // rewrite: now the newest
	m.Add("d.example.com", ips("10.0.0.4"), 0)     // evicts 10.0.0.2, the oldest

	if name, ok := m.Lookup(netip.MustParseAddr("10.0.0.1")); !ok || name != "fresh.example.com" {
		t.Errorf("10.0.0.1 = %q %v, want the refreshed entry kept", name, ok)
	}
	if _, ok := m.Lookup(netip.MustParseAddr("10.0.0.2")); ok {
		t.Error("10.0.0.2 was the oldest write and must be evicted")
	}
}

func TestNameMapStaysBoundedUnderRepeatedWrites(t *testing.T) {
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	m := newNameMap(func() time.Time { return now }, 10)
	for range 1000 {
		m.Add("same.example.com", ips("10.0.0.1"), 0)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.order) > 2*m.max+16 {
		t.Fatalf("order grew to %d for one live entry", len(m.order))
	}
}

func TestNameMapIgnoresEmptyInput(t *testing.T) {
	m := NewNameMap()
	m.Add("", ips("1.1.1.1"), 0)
	m.Add("a.example.com", nil, 0)
	if m.Len() != 0 {
		t.Fatal("empty names and address lists record nothing")
	}
}

// BenchmarkNameMapAddAtCapacity measures Add on a full map whose entries are
// all still live, the case where every Add has to make room.
func BenchmarkNameMapAddAtCapacity(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	m := newNameMap(func() time.Time { return now }, MaxNames)
	for i := 0; i < MaxNames; i++ {
		m.Add("seed.example.com", []netip.Addr{benchAddr(i)}, 0)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Add("live.example.com", []netip.Addr{benchAddr(MaxNames + i)}, 0)
	}
}

func benchAddr(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
}

func TestNameMapOverflowDropsExpiredBeforeLongLivedOlderWrites(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := newNameMap(func() time.Time { return now }, 2)
	m.Add("long.example.com", ips("10.0.0.1"), 5*time.Hour)
	m.Add("short.example.com", ips("10.0.0.2"), 0) // expires first despite being written later
	now = now.Add(MinNameLifetime + time.Minute)
	m.Add("fresh.example.com", ips("10.0.0.3"), 0)

	if _, ok := m.Lookup(netip.MustParseAddr("10.0.0.1")); !ok {
		t.Error("the long-lived older write must survive when an expired entry can make room")
	}
	if _, ok := m.Lookup(netip.MustParseAddr("10.0.0.3")); !ok {
		t.Error("the new entry must be present")
	}
	if got := m.Len(); got != 2 {
		t.Errorf("Len = %d, want 2", got)
	}
}

// referenceNameMap is the straightforward bounded map: a full scan for expired
// entries on overflow, then eviction of the oldest write.
type referenceNameMap struct {
	max     int
	entries map[netip.Addr]nameEntry
	order   []queued
	seq     uint64
}

func (r *referenceNameMap) add(now time.Time, name string, ip netip.Addr, ttl time.Duration) {
	r.seq++
	r.entries[ip] = nameEntry{name: name, expires: now.Add(max(ttl, MinNameLifetime)), seq: r.seq}
	r.order = append(r.order, queued{ip: ip, seq: r.seq})
	if len(r.entries) > r.max {
		for k, e := range r.entries {
			if !now.Before(e.expires) {
				delete(r.entries, k)
			}
		}
	}
	for len(r.entries) > r.max && len(r.order) > 0 {
		head := r.order[0]
		r.order = r.order[1:]
		if e, ok := r.entries[head.ip]; ok && e.seq == head.seq {
			delete(r.entries, head.ip)
		}
	}
}

func TestNameMapMatchesReferenceUnderRandomLoad(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	now := time.Unix(1_700_000_000, 0)
	const bound = 40
	m := newNameMap(func() time.Time { return now }, bound)
	ref := &referenceNameMap{max: bound, entries: map[netip.Addr]nameEntry{}}

	for step := 0; step < 20000; step++ {
		now = now.Add(time.Duration(rng.IntN(90)) * time.Second)
		ip := benchAddr(rng.IntN(120))
		ttl := time.Duration(rng.IntN(5)) * 30 * time.Minute
		name := fmt.Sprintf("n%d.example.com", step)
		m.Add(name, []netip.Addr{ip}, ttl)
		ref.add(now, name, ip, ttl)

		probe := benchAddr(rng.IntN(120))
		got, gotOK := m.Lookup(probe)
		want, wantOK := ref.entries[probe]
		if wantOK && !now.Before(want.expires) {
			wantOK = false
			delete(ref.entries, probe)
		}
		if gotOK != wantOK || (gotOK && got != want.name) {
			t.Fatalf("step %d: Lookup(%v) = %q,%v; reference %q,%v", step, probe, got, gotOK, want.name, wantOK)
		}
		if m.Len() != len(ref.entries) {
			t.Fatalf("step %d: Len = %d, reference %d", step, m.Len(), len(ref.entries))
		}
	}
}
