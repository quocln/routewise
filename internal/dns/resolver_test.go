package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNewResolver(t *testing.T) {
	t.Run("with defaults", func(t *testing.T) {
		r := NewResolver(nil, 0)
		defer r.Close()

		if r.client == nil {
			t.Error("client should not be nil")
		}
		if len(r.servers) != 2 {
			t.Errorf("expected 2 default servers, got %d", len(r.servers))
		}
		if r.cacheTTL != 5*time.Minute {
			t.Errorf("expected 5m default TTL, got %v", r.cacheTTL)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		servers := []string{"1.1.1.1", "8.8.4.4"}
		r := NewResolver(servers, 10*time.Minute)
		defer r.Close()

		if len(r.servers) != 2 {
			t.Errorf("expected 2 servers, got %d", len(r.servers))
		}
		if r.cacheTTL != 10*time.Minute {
			t.Errorf("expected 10m TTL, got %v", r.cacheTTL)
		}
	})
}

func TestResolverCache(t *testing.T) {
	// Use short minTTL for testing cache expiration
	r := NewResolverWithTTLBounds([]string{"8.8.8.8"}, 1*time.Second, 500*time.Millisecond, 1*time.Hour)
	defer r.Close()

	// Manually put in cache with short TTL
	testIP := net.ParseIP("192.168.1.1")
	r.putInCacheWithTTL("test.example.com.", []net.IP{testIP}, 1*time.Second)

	// Should get from cache
	ips := r.getFromCache("test.example.com.")
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP from cache, got %d", len(ips))
	}
	if !ips[0].Equal(testIP) {
		t.Errorf("expected %v, got %v", testIP, ips[0])
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	// Should return nil (expired)
	ips = r.getFromCache("test.example.com.")
	if ips != nil {
		t.Errorf("expected nil after expiration, got %v", ips)
	}
}

func TestResolverCacheStats(t *testing.T) {
	// Use longer TTL to avoid race with cleanup loop
	r := NewResolver([]string{"8.8.8.8"}, 2*time.Second)
	defer r.Close()

	// Add entries
	r.putInCache("test1.com.", []net.IP{net.ParseIP("1.1.1.1")})
	r.putInCache("test2.com.", []net.IP{net.ParseIP("2.2.2.2")})

	total, expired := r.CacheStats()
	if total != 2 {
		t.Errorf("expected 2 total, got %d", total)
	}
	if expired != 0 {
		t.Errorf("expected 0 expired, got %d", expired)
	}

	// Manually expire entries by modifying expiration time
	r.mu.Lock()
	for _, entry := range r.cache {
		entry.ExpiresAt = time.Now().Add(-1 * time.Second)
	}
	r.mu.Unlock()

	total, expired = r.CacheStats()
	if total != 2 {
		t.Errorf("expected 2 total, got %d", total)
	}
	if expired != 2 {
		t.Errorf("expected 2 expired, got %d", expired)
	}
}

func TestResolverClearCache(t *testing.T) {
	r := NewResolver([]string{"8.8.8.8"}, 5*time.Minute)
	defer r.Close()

	r.putInCache("test.com.", []net.IP{net.ParseIP("1.1.1.1")})

	total, _ := r.CacheStats()
	if total != 1 {
		t.Errorf("expected 1 entry, got %d", total)
	}

	r.ClearCache()

	total, _ = r.CacheStats()
	if total != 0 {
		t.Errorf("expected 0 entries after clear, got %d", total)
	}
}

func TestResolverResolveIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	r := NewResolver([]string{"8.8.8.8", "1.1.1.1"}, 5*time.Minute)
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Resolve a known domain
	ips, err := r.Resolve(ctx, "google.com")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(ips) == 0 {
		t.Error("expected at least one IP")
	}

	// Second call should use cache
	start := time.Now()
	ips2, err := r.Resolve(ctx, "google.com")
	if err != nil {
		t.Fatalf("cached Resolve failed: %v", err)
	}
	if time.Since(start) > 10*time.Millisecond {
		t.Error("cached lookup took too long, might not be cached")
	}
	if len(ips2) != len(ips) {
		t.Errorf("cached result differs: got %d IPs, expected %d", len(ips2), len(ips))
	}
}

func TestResolverResolveAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	r := NewResolver([]string{"8.8.8.8"}, 5*time.Minute)
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	domains := []string{"google.com", "cloudflare.com"}
	results, err := r.ResolveAll(ctx, domains)
	if err != nil {
		t.Fatalf("ResolveAll failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	for _, d := range domains {
		if _, ok := results[d]; !ok {
			t.Errorf("missing result for %s", d)
		}
	}
}

func TestResolverContextCancellation(t *testing.T) {
	r := NewResolver([]string{"8.8.8.8"}, 5*time.Minute)
	defer r.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := r.Resolve(ctx, "google.com")
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

// answerA builds a reply carrying one A record per ip, with the given TTL.
func answerA(m *dns.Msg, ttl uint32, ips ...string) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(m)
	for _, ip := range ips {
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.ParseIP(ip),
		})
	}
	return reply
}

func TestResolverCloseIsIdempotent(t *testing.T) {
	r := NewResolver([]string{"192.0.2.1"}, time.Minute)
	r.Close()
	r.Close()
}

func TestQueryServersStopsAskingAfterContextCancel(t *testing.T) {
	r := NewResolver([]string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, time.Minute)
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var asked []string
	r.exchange = func(_ context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
		asked = append(asked, addr)
		cancel() // the caller gives up right after the first server answers
		return answerA(m, 60, "10.0.0.1"), nil
	}

	ips, _, err := r.queryServers(ctx, "a.example.com.", r.servers)
	if err != nil {
		t.Fatalf("queryServers: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("ips = %v, want the first server's answer", ips)
	}
	if len(asked) != 1 {
		t.Errorf("asked %v after cancel, want only the first server", asked)
	}
}

func TestQueryServersCancelledWithNothingReturnsContextError(t *testing.T) {
	r := NewResolver([]string{"192.0.2.1"}, time.Minute)
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.exchange = func(context.Context, *dns.Msg, string) (*dns.Msg, error) {
		t.Error("no server should be asked with a cancelled context")
		return nil, errors.New("unreachable")
	}
	if _, _, err := r.queryServers(ctx, "a.example.com.", r.servers); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestResolveAllBoundsConcurrencyAndKeepsResults(t *testing.T) {
	r := NewResolver([]string{"192.0.2.1"}, time.Minute)
	defer r.Close()
	var inFlight, peak atomic.Int32
	r.exchange = func(_ context.Context, m *dns.Msg, _ string) (*dns.Msg, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		if strings.HasPrefix(m.Question[0].Name, "bad") {
			return nil, errors.New("no route")
		}
		return answerA(m, 60, "10.0.0.1"), nil
	}

	var domains []string
	for i := 0; i < 40; i++ {
		domains = append(domains, fmt.Sprintf("host%d.example.com", i))
	}
	domains = append(domains, "bad.example.com")
	results, err := r.ResolveAll(context.Background(), domains)
	if err != nil {
		t.Fatalf("ResolveAll: %v", err)
	}
	if len(results) != 40 {
		t.Errorf("got %d results, want 40 (the failing domain is omitted)", len(results))
	}
	if got := peak.Load(); got > resolveAllWorkers {
		t.Errorf("peak concurrency %d exceeds limit %d", got, resolveAllWorkers)
	}
}

func TestResolveAllFailsWhenEveryDomainFails(t *testing.T) {
	r := NewResolver([]string{"192.0.2.1"}, time.Minute)
	defer r.Close()
	r.exchange = func(context.Context, *dns.Msg, string) (*dns.Msg, error) {
		return nil, errors.New("down")
	}
	if _, err := r.ResolveAll(context.Background(), []string{"a.example.com", "b.example.com"}); err == nil {
		t.Error("expected an error when nothing resolves")
	}
}
