package daemon

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/route"
	"github.com/quocln/routewise/internal/vpnclient"
)

// patternPool is every kind of entry a list may hold, valid or not, so the
// compiled policy is compared with the reference over the whole input space.
func patternPool() []string {
	pool := []string{
		"example.com", "Example.COM", "example.com.", "api.example.com", "*.example.com", "qa*.staging.example.com",
		"*.corp.example.com", "*.a.b.c.example.net", "*", "*.", "a*b.example.org", "bad_domain", "-x.example.com",
		"10.0.0.1", "10.0.0.1/32", "10.0.0.0/8", "10.20.0.0/16", "10.20.30.0/24", "192.168.1.0/24", "198.51.100.7",
		"300.1.1.1", "fe80::1", "2001:db8::/32", "0.0.0.0/0", "127.0.0.1", "10.0.0.0/7", "bücher.example.de", "*.bücher.example.de",
		"1.2.3.4", "1.2.3.0/24", "", ".", "..",
	}
	for i := range 12 {
		pool = append(pool,
			fmt.Sprintf("h%d.pool.example.com", i),
			fmt.Sprintf("*.w%d.pool.example.com", i),
			fmt.Sprintf("10.%d.0.0/16", i*7),
			fmt.Sprintf("10.%d.%d.%d", i, i, i))
	}
	return pool
}

func queryNames() []string {
	names := []string{
		"", "example.com", "EXAMPLE.com", "example.com.", "api.example.com", "API.Example.COM.", "a.b.example.com",
		"x.corp.example.com", "qa1.staging.example.com", "qa.staging.example.com", "x.a.b.c.example.net", "a.b.c.example.net",
		"axb.example.org", "ab.example.org", "bad_domain", "10.0.0.1", "10.20.30.40", "*.example.com", "*.corp.example.com",
		"bücher.example.de", "x.bücher.example.de", "BÜCHER.example.de", "nothing.example.invalid", "*", ".", "..",
		"h3.pool.example.com", "x.w5.pool.example.com", "x.y.w5.pool.example.com",
	}
	return names
}

func queryAddrs() []netip.Addr {
	var out []netip.Addr
	out = append(out, netip.Addr{})
	for _, s := range []string{
		"10.0.0.1", "10.0.0.2", "10.20.30.40", "10.20.99.1", "10.200.0.1", "10.14.0.5", "192.168.1.9", "198.51.100.7",
		"203.0.113.9", "1.2.3.4", "1.2.3.99", "127.0.0.1", "::ffff:10.0.0.1", "2001:db8::5",
	} {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// randomPolicyConfig builds a config with a random Any list and 0 to 4 VPN
// lists drawn from the pool. Lists may share entries, which is what makes the
// priority order matter.
func randomPolicyConfig(r *rand.Rand, pool []string) *config.Config {
	pick := func() []config.DomainRule {
		n := r.IntN(14)
		rules := make([]config.DomainRule, 0, n)
		for range n {
			rules = append(rules, config.DomainRule{Pattern: pool[r.IntN(len(pool))]})
		}
		return rules
	}
	cfg := &config.Config{Domains: pick()}
	clients := []string{"/vpn/a", "/vpn/b", "/vpn/c", "/vpn/d"}
	r.Shuffle(len(clients), func(i, j int) { clients[i], clients[j] = clients[j], clients[i] })
	for _, c := range clients[:r.IntN(len(clients)+1)] {
		cfg.VPNs = append(cfg.VPNs, config.VPNRoute{Client: c, Domains: pick()})
	}
	return cfg
}

// randomSessions makes a session per allowed client the dice pick, in priority
// order, some owned and unproven, so clientSession and anyVPNSession see both
// healthy and unusable tunnels.
func randomSessions(r *rand.Rand, cfg *config.Config) []*tunnelSession {
	var out []*tunnelSession
	for i, v := range cfg.VPNs {
		if r.IntN(4) == 0 {
			continue
		}
		s := &tunnelSession{
			iface:   fmt.Sprintf("utun%d", 20+i),
			client:  vpnclient.Client{ID: v.Client, Name: v.Client},
			manager: route.NewManager(),
		}
		if r.IntN(3) == 0 {
			s.owned = true
			s.proven.Store(r.IntN(2) == 0)
		}
		out = append(out, s)
	}
	return out
}

func samePatterns(a, b []sessionPatterns) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].session != b[i].session || !slices.Equal(a[i].patterns, b[i].patterns) {
			return false
		}
	}
	return true
}

func TestCompiledPolicyAnswersLikeTheReferenceRules(t *testing.T) {
	pool, names, addrs := patternPool(), queryNames(), queryAddrs()
	r := rand.New(rand.NewPCG(7, 11))

	for round := range 30 {
		cfg := randomPolicyConfig(r, pool)
		pol := newRoutingPolicy(cfg, 1, nil)
		sessions := randomSessions(r, cfg)

		// A pattern is also a name someone may look up, so each round adds a
		// sample of them to the fixed names.
		allNames := slices.Clone(names)
		for range 12 {
			allNames = append(allNames, pool[r.IntN(len(pool))])
		}
		for i, name := range allNames {
			wantOwner, wantOK := oracleListOwner(cfg, name)
			if gotOwner, gotOK := pol.listOwner(name); gotOwner != wantOwner || gotOK != wantOK {
				t.Fatalf("round %d listOwner(%q) = %q,%v; want %q,%v\n%+v", round, name, gotOwner, gotOK, wantOwner, wantOK, cfg)
			}
			wantEO, wantEOK := oracleEntryOwner(cfg, name)
			if gotEO, gotEOK := pol.entryOwner(name); gotEO != wantEO || gotEOK != wantEOK {
				t.Fatalf("round %d entryOwner(%q) = %q,%v; want %q,%v", round, name, gotEO, gotEOK, wantEO, wantEOK)
			}
			wantRules, wantSession := oracleOwningList(cfg, sessions, name)
			gotList, gotSession := pol.owningList(sessions, name)
			if gotSession != wantSession {
				t.Fatalf("round %d owningList(%q) session = %v; want %v\n%+v", round, name, gotSession, wantSession, cfg)
			}
			if (gotList == nil) != (wantRules == nil) {
				t.Fatalf("round %d owningList(%q) list presence differs", round, name)
			}
			if gotList != nil {
				var want []string
				for _, rule := range wantRules {
					want = append(want, rule.Pattern)
				}
				if !slices.Equal(gotList.patterns, want) {
					t.Fatalf("round %d owningList(%q) list = %v; want %v", round, name, gotList.patterns, want)
				}
			}
			if got, want := pol.wildcardOwnerOf(sessions, name), oracleWildcardOwnerOf(cfg, sessions, name); got != want {
				t.Fatalf("round %d wildcardOwnerOf(%q) = %v; want %v\n%+v", round, name, got, want, cfg)
			}
			// A few addresses per name keeps the run short; the rotation covers
			// every address across the names.
			for k := range 4 {
				ip := addrs[(i+k*5)%len(addrs)]
				want, wantOK := oracleMatchingEntry(cfg, name, ip)
				if got, gotOK := pol.matchingEntry(name, ip); got != want || gotOK != wantOK {
					t.Fatalf("round %d matchingEntry(%q, %v) = %+v,%v; want %+v,%v\n%+v", round, name, ip, got, gotOK, want, wantOK, cfg)
				}
			}
		}
		for _, ip := range addrs {
			want, wantOK := oracleMatchingEntry(cfg, "", ip)
			if got, gotOK := pol.matchingEntry("", ip); got != want || gotOK != wantOK {
				t.Fatalf("round %d matchingEntry(\"\", %v) = %+v,%v; want %+v,%v", round, ip, got, gotOK, want, wantOK)
			}
		}
		for _, pattern := range pool {
			want, wantOK := oracleListHolding(cfg, pattern)
			if got, gotOK := pol.listHolding(pattern); got != want || gotOK != wantOK {
				t.Fatalf("round %d listHolding(%q) = %q,%v; want %q,%v", round, pattern, got, gotOK, want, wantOK)
			}
		}
		if got, want := assignPatterns(pol, sessions), oracleAssignPatterns(cfg, sessions); !samePatterns(got, want) {
			t.Fatalf("round %d assignPatterns differ\n got %+v\nwant %+v\n%+v", round, got, want, cfg)
		}
		if want := slices.ContainsFunc(slices.Concat(patternsOf(cfg.Domains), vpnPatterns(cfg)), config.IsWildcardPattern); pol.hasWildcards != want {
			t.Fatalf("round %d hasWildcards = %v; want %v", round, pol.hasWildcards, want)
		}
	}
}

func patternsOf(rules []config.DomainRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Pattern)
	}
	return out
}

func vpnPatterns(cfg *config.Config) []string {
	var out []string
	for _, v := range cfg.VPNs {
		out = append(out, patternsOf(v.Domains)...)
	}
	return out
}

func TestPolicyRankEpochChangesOnlyWithTheAllowlistOrder(t *testing.T) {
	cfg := &config.Config{VPNs: []config.VPNRoute{{Client: "/a"}, {Client: "/b"}}}
	first := newRoutingPolicy(cfg, 1, nil)

	edited := cfg.Clone()
	edited.Domains = domainRules([]string{"example.com"})
	if p := newRoutingPolicy(edited, 2, first); p.rankEpoch != first.rankEpoch {
		t.Error("a domain edit must keep the rank epoch")
	}
	reordered := cfg.Clone()
	reordered.VPNs[0], reordered.VPNs[1] = reordered.VPNs[1], reordered.VPNs[0]
	if p := newRoutingPolicy(reordered, 2, first); p.rankEpoch == first.rankEpoch {
		t.Error("a reorder must change the rank epoch")
	}
}

func TestStoreReadsNeverWaitForAPersist(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domains = domainRules([]string{"example.com"})
	persist := &blockingPersister{entered: make(chan struct{}), release: make(chan struct{})}
	store := NewConfigStore(cfg, persist)

	done := make(chan error, 1)
	go func() {
		_, err := store.AddDomain(config.AnyVPN, "other.example.com")
		done <- err
	}()
	<-persist.entered

	// The save is in flight: every reader answers from the previous revision.
	read := make(chan struct{})
	go func() {
		defer close(read)
		_, rev := store.Snapshot()
		_ = store.Revision()
		_ = store.AllowedVPNClients()
		_ = store.AllPatterns()
		_, _ = store.DomainList(config.AnyVPN)
		_ = store.Profiles()
		_, _ = store.Policy().matchingEntry("example.com", netip.Addr{})
		if rev != 1 {
			t.Errorf("revision during the save = %d, want the previous one", rev)
		}
	}()
	select {
	case <-read:
	case <-timeAfterShort():
		t.Fatal("a reader waited for the persist")
	}
	close(persist.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := store.Domains(); len(got) != 2 {
		t.Errorf("domains after the save = %v", got)
	}
}

// blockingPersister holds a save open until release closes.
type blockingPersister struct {
	entered chan struct{}
	release chan struct{}
}

func (p *blockingPersister) Save(*config.Config) error {
	close(p.entered)
	<-p.release
	return nil
}

func timeAfterShort() <-chan time.Time { return time.After(2 * time.Second) }
