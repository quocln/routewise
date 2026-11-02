package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry stores resolved IPs with expiration.
type CacheEntry struct {
	IPs       []net.IP
	ExpiresAt time.Time
}

// Default TTL bounds
const (
	DefaultMinTTL   = 30 * time.Second // Prevent excessive queries
	DefaultMaxTTL   = 1 * time.Hour    // Ensure eventual refresh
	MaxCacheEntries = 10000            // Prevent unbounded memory growth

	// resolveAllWorkers bounds the lookups ResolveAll runs at once, so a long
	// domain list does not open a socket per domain.
	resolveAllWorkers = 8
)

// Resolver handles DNS resolution with caching.
type Resolver struct {
	client   *dns.Client
	servers  []string      // configured servers; always the fallback
	cacheTTL time.Duration // Fallback TTL if DNS doesn't provide one
	minTTL   time.Duration // Minimum cache TTL (prevents excessive queries)
	maxTTL   time.Duration // Maximum cache TTL (ensures refresh)

	mu    sync.RWMutex
	cache map[string]*CacheEntry
	// preferred holds the VPN-pushed DNS servers while dns.use_vpn_dns is on
	// and the tunnel is up. When set, they are asked first and the configured
	// servers only answer if none of them returns an address.
	preferred []string

	stopCh    chan struct{}
	closeOnce sync.Once

	// exchange sends one query to addr; tests replace it.
	exchange func(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error)
}

// NewResolver creates a new DNS resolver with caching.
func NewResolver(servers []string, cacheTTL time.Duration) *Resolver {
	return NewResolverWithTTLBounds(servers, cacheTTL, DefaultMinTTL, DefaultMaxTTL)
}

// NewResolverWithTTLBounds creates a resolver with custom TTL bounds.
func NewResolverWithTTLBounds(servers []string, cacheTTL, minTTL, maxTTL time.Duration) *Resolver {
	if len(servers) == 0 {
		servers = []string{"8.8.8.8", "1.1.1.1"}
	}
	if cacheTTL <= 0 {
		cacheTTL = 5 * time.Minute
	}
	if minTTL <= 0 {
		minTTL = DefaultMinTTL
	}
	if maxTTL <= 0 {
		maxTTL = DefaultMaxTTL
	}

	r := &Resolver{
		client: &dns.Client{
			Timeout: 5 * time.Second,
			Net:     "udp",
		},
		servers:  servers,
		cacheTTL: cacheTTL,
		minTTL:   minTTL,
		maxTTL:   maxTTL,
		cache:    make(map[string]*CacheEntry),
		stopCh:   make(chan struct{}),
	}

	r.exchange = func(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
		reply, _, err := r.client.ExchangeContext(ctx, m, addr)
		return reply, err
	}

	// Start background cache cleanup
	go r.cleanupLoop()

	return r
}

// SetPreferredServers replaces the servers asked before the configured ones.
// Pass nil to go back to the configured servers alone. The cache is cleared
// when the set changes, because answers from the previous upstreams may not
// match what the new ones return (split-horizon DNS).
func (r *Resolver) SetPreferredServers(servers []netip.Addr) {
	next := make([]string, 0, len(servers))
	for _, s := range servers {
		next = append(next, s.String())
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if slices.Equal(r.preferred, next) {
		return
	}
	r.preferred = next
	r.cache = make(map[string]*CacheEntry)
}

// Upstreams returns every server this resolver may ask, preferred first, in the
// order they are tried.
func (r *Resolver) Upstreams() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.preferred)+len(r.servers))
	out = append(out, r.preferred...)
	return append(out, r.servers...)
}

// UpstreamGroups returns the same servers as Upstreams, as the groups they are
// tried in: the preferred servers, then the configured ones. The groups must not
// be mixed: a name is sent to the configured servers only when the preferred
// ones failed, since those may be public servers that must not see internal names.
func (r *Resolver) UpstreamGroups() [][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	groups := make([][]string, 0, 2)
	if len(r.preferred) > 0 {
		groups = append(groups, slices.Clone(r.preferred))
	}
	if len(r.servers) > 0 {
		groups = append(groups, slices.Clone(r.servers))
	}
	return groups
}

// Resolve queries DNS for a domain and returns all A record IPs.
func (r *Resolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	domain = dns.Fqdn(domain)

	// Check cache first
	if ips := r.getFromCache(domain); ips != nil {
		return ips, nil
	}

	// Query DNS servers (returns IPs and TTL from response)
	ips, ttl, err := r.queryDNSWithTTL(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Store in cache with actual TTL (clamped to min/max bounds)
	r.putInCacheWithTTL(domain, ips, ttl)

	return ips, nil
}

// ResolveAll resolves multiple domains, up to resolveAllWorkers at a time.
func (r *Resolver) ResolveAll(ctx context.Context, domains []string) (map[string][]net.IP, error) {
	results := make(map[string][]net.IP)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, len(domains))

	slots := make(chan struct{}, resolveAllWorkers)
	for _, domain := range domains {
		wg.Add(1)
		slots <- struct{}{}
		go func(d string) {
			defer wg.Done()
			defer func() { <-slots }()

			ips, err := r.Resolve(ctx, d)
			if err != nil {
				errCh <- fmt.Errorf("%s: %w", d, err)
				return
			}

			mu.Lock()
			results[d] = ips
			mu.Unlock()
		}(domain)
	}

	wg.Wait()
	close(errCh)

	// Collect errors (non-fatal, just log)
	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}

	if len(results) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("all DNS resolutions failed: %v", errs)
	}

	return results, nil
}

// RefreshCache forces re-resolution of all cached domains.
func (r *Resolver) RefreshCache(ctx context.Context) error {
	r.mu.RLock()
	domains := make([]string, 0, len(r.cache))
	for domain := range r.cache {
		domains = append(domains, domain)
	}
	r.mu.RUnlock()

	for _, domain := range domains {
		ips, ttl, err := r.queryDNSWithTTL(ctx, domain)
		if err != nil {
			continue // Skip failures, keep old cache
		}
		r.putInCacheWithTTL(domain, ips, ttl)
	}

	return nil
}

// Close stops the resolver and cleans up resources. It is safe to call more
// than once.
func (r *Resolver) Close() {
	r.closeOnce.Do(func() { close(r.stopCh) })
}

// ClearCache removes all cached entries.
func (r *Resolver) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]*CacheEntry)
}

// CacheStats returns cache statistics.
func (r *Resolver) CacheStats() (total, expired int) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	total = len(r.cache)
	for _, entry := range r.cache {
		if entry.ExpiresAt.Before(now) {
			expired++
		}
	}
	return total, expired
}

// queryDNSWithTTL asks the preferred (VPN) servers first and falls back to the
// configured servers only when the preferred ones return no address.
func (r *Resolver) queryDNSWithTTL(ctx context.Context, domain string) ([]net.IP, time.Duration, error) {
	r.mu.RLock()
	preferred := r.preferred
	r.mu.RUnlock()

	if len(preferred) > 0 {
		ips, ttl, err := r.queryServers(ctx, domain, preferred)
		if err == nil {
			return ips, ttl, nil
		}
	}
	return r.queryServers(ctx, domain, r.servers)
}

// queryServers queries every server in the group and merges the results. This
// is critical for CDN/GeoDNS services (e.g., CloudFront) that return different
// IPs depending on which resolver is queried. Returns deduplicated IPs, the
// minimum TTL across all responses, and an error when no server answered.
func (r *Resolver) queryServers(ctx context.Context, domain string, servers []string) ([]net.IP, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeA)
	m.RecursionDesired = true

	seen := make(map[string]bool)
	var allIPs []net.IP
	var globalMinTTL uint32 = 0xFFFFFFFF
	var lastErr error

servers:
	for _, server := range servers {
		select {
		case <-ctx.Done():
			if len(allIPs) > 0 {
				break servers // Return what we have so far
			}
			return nil, 0, ctx.Err()
		default:
		}

		addr := net.JoinHostPort(server, "53")
		reply, err := r.exchange(ctx, m, addr)
		if err != nil {
			lastErr = err
			continue
		}

		if reply.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS response code: %s", dns.RcodeToString[reply.Rcode])
			continue
		}

		for _, ans := range reply.Answer {
			if a, ok := ans.(*dns.A); ok {
				ipStr := a.A.String()
				if !seen[ipStr] {
					seen[ipStr] = true
					allIPs = append(allIPs, a.A)
				}
				if ans.Header().Ttl < globalMinTTL {
					globalMinTTL = ans.Header().Ttl
				}
			}
		}
	}

	if len(allIPs) > 0 {
		ttl := r.cacheTTL
		if globalMinTTL < 0xFFFFFFFF {
			ttl = time.Duration(globalMinTTL) * time.Second
		}
		return allIPs, ttl, nil
	}

	if lastErr != nil {
		return nil, 0, fmt.Errorf("DNS resolution failed for %s: %w", domain, lastErr)
	}
	return nil, 0, fmt.Errorf("no A records found for %s", domain)
}

func (r *Resolver) getFromCache(domain string) []net.IP {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.cache[domain]
	if !ok {
		return nil
	}

	if entry.ExpiresAt.Before(time.Now()) {
		return nil // Expired
	}

	// Return a copy to prevent modification
	ips := make([]net.IP, len(entry.IPs))
	copy(ips, entry.IPs)
	return ips
}

func (r *Resolver) putInCache(domain string, ips []net.IP) {
	r.putInCacheWithTTL(domain, ips, r.cacheTTL)
}

// putInCacheWithTTL stores IPs with the specified TTL, clamped to min/max bounds.
func (r *Resolver) putInCacheWithTTL(domain string, ips []net.IP, ttl time.Duration) {
	// Clamp TTL to configured bounds
	if ttl < r.minTTL {
		ttl = r.minTTL
	}
	if ttl > r.maxTTL {
		ttl = r.maxTTL
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Enforce cache size limit
	if len(r.cache) >= MaxCacheEntries {
		r.cleanupExpiredLocked()
		if len(r.cache) >= MaxCacheEntries {
			// Still full after evicting expired — clear all and let repopulate
			r.cache = make(map[string]*CacheEntry)
		}
	}

	// Store a copy
	ipsCopy := make([]net.IP, len(ips))
	copy(ipsCopy, ips)

	r.cache[domain] = &CacheEntry{
		IPs:       ipsCopy,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func (r *Resolver) cleanupLoop() {
	ticker := time.NewTicker(r.cacheTTL)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.cleanupExpired()
		}
	}
}

func (r *Resolver) cleanupExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupExpiredLocked()
}

// cleanupExpiredLocked removes expired cache entries. Caller must hold r.mu.
func (r *Resolver) cleanupExpiredLocked() {
	now := time.Now()
	for domain, entry := range r.cache {
		if entry.ExpiresAt.Before(now) {
			delete(r.cache, domain)
		}
	}
}
