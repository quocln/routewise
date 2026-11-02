package daemon

import (
	"net/netip"
	"testing"
	"time"
)

func TestLocalPrefixCacheReadsOncePerTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	reads := 0
	c := &localPrefixCache{
		read: func() []netip.Prefix {
			reads++
			return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
		},
		now: func() time.Time { return now },
	}
	for range 5 {
		if got := c.get(); len(got) != 1 {
			t.Fatalf("get() = %v", got)
		}
	}
	if reads != 1 {
		t.Fatalf("reads = %d, want 1 within the TTL", reads)
	}
	now = now.Add(localPrefixTTL)
	c.get()
	if reads != 2 {
		t.Fatalf("reads = %d, want a fresh read after the TTL", reads)
	}
}

func BenchmarkLocalInterfacePrefixes(b *testing.B) {
	b.Run("enumerate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			localInterfacePrefixes()
		}
	})
	b.Run("cached", func(b *testing.B) {
		c := &localPrefixCache{read: localInterfacePrefixes, now: time.Now}
		b.ReportAllocs()
		for b.Loop() {
			c.get()
		}
	})
}
