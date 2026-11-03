package daemon

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/dns"
)

// routingPolicy is an immutable, precompiled view of the configuration's
// domain lists and allowlist. The ConfigStore builds one for every committed
// configuration and publishes it atomically, so the per-query and per-flow hot
// paths answer ownership questions with map lookups and no lock, deep copy, or
// repeated rule parsing. Nothing may modify a policy or the slices it returns
// after it is built.
//
// Ownership is decided in a fixed order: each VPN client's own list by
// allowlist priority, then the Any VPN list. The methods below reproduce that
// order exactly (see the reference implementations kept in the tests).
type routingPolicy struct {
	revision uint64
	// cfg is the committed configuration this policy was built from. The store
	// replaces its configuration on every commit and never writes to a committed
	// one, so it is safe to read; it is never handed to a caller, who gets a
	// clone through ConfigStore.Snapshot.
	cfg *config.Config

	// allowed are the VPN client ids in priority order.
	allowed []string
	rank    map[string]int
	// rankEpoch identifies the priority order: it stays the same across commits
	// that leave the allowlist order alone, so a cached ordering of sessions
	// stays valid until the order itself changes.
	rankEpoch uint64

	// vpn are the VPN clients' lists in priority order; any is the Any VPN list.
	vpn      []*policyList
	any      *policyList
	byClient map[string]*policyList
	// except is what goes direct instead of through the default VPN. It owns
	// nothing: see exceptedName.
	except *policyList
	// holder maps a pattern written exactly so to the list holding it: the
	// highest-priority VPN's, else Any ("" is Any VPN). vpnHolder is holder
	// without the Any VPN list.
	holder    map[string]string
	vpnHolder map[string]string

	// entries indexes every list entry by what it covers, for attribution.
	entries entryIndex

	// patterns lists every pattern: the Any VPN list, then each VPN's.
	patterns     []string
	hasWildcards bool

	profiles []config.TunnelProfile
	profile  map[string]int
}

// policyList is one domain list, compiled for matching a name.
type policyList struct {
	client   string
	patterns []string
	// exact holds the folded form of every pattern without a wildcard; wild
	// indexes the patterns containing '*'.
	exact map[string]struct{}
	wild  wildcardIndex
}

// foldName is the form two names are compared in: one trailing dot dropped and
// ASCII (or, for non-ASCII text, Unicode) case folded, as dns.MatchDomain does.
// It does not allocate for a name that is already lowercase.
func foldName(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func newPolicyList(client string, rules []config.DomainRule) *policyList {
	l := &policyList{
		client:   client,
		patterns: make([]string, 0, len(rules)),
		exact:    make(map[string]struct{}, len(rules)),
	}
	for i, r := range rules {
		l.patterns = append(l.patterns, r.Pattern)
		if config.IsWildcardPattern(r.Pattern) {
			l.wild.add(wildcardEntry{pattern: r.Pattern, ref: entryRef{ord: i}})
			continue
		}
		l.exact[foldName(r.Pattern)] = struct{}{}
	}
	return l
}

// matches reports whether name falls under any pattern of the list. key is
// foldName(name).
func (l *policyList) matches(name, key string) bool {
	if _, ok := l.exact[key]; ok {
		return true
	}
	return l.matchesWildcard(name)
}

// matchesWildcard reports whether name falls under a wildcard pattern.
func (l *policyList) matchesWildcard(name string) bool {
	_, ok := l.wild.first(name)
	return ok
}

// entryRef locates a list entry: ord is its position in the order ownership is
// decided (VPN lists by priority, then Any VPN, each in list order).
type entryRef struct {
	ord   int
	match listMatch
}

// entryIndex answers matchingEntry. Each kind keeps the first entry in
// ownership order that could cover a lookup.
type entryIndex struct {
	exactDomains map[string]entryRef
	wild         wildcardIndex
	ips          map[netip.Addr]entryRef
	cidrs        []cidrEntry
}

type wildcardEntry struct {
	pattern string
	ref     entryRef
}

// wildcardIndex finds the wildcard patterns that can match a name without
// trying every one. A '*' never crosses a dot, so a pattern whose '*' sits in
// its first label can only match a name whose first dot meets the pattern's:
// the rest of the name must equal the rest of the pattern. Those patterns are
// bucketed by that remainder, folded. Any other shape (a '*' in a later label)
// is tried against every name.
type wildcardIndex struct {
	bySuffix map[string][]wildcardEntry
	other    []wildcardEntry
}

// wildcardSuffixKey is the bucket of a pattern, or false when its '*' is not
// confined to the first label.
func wildcardSuffixKey(pattern string) (string, bool) {
	trimmed := strings.TrimSuffix(pattern, ".")
	dot := strings.IndexByte(trimmed, '.')
	if dot < 0 || strings.IndexByte(trimmed[dot+1:], '*') >= 0 {
		return "", false
	}
	return strings.ToLower(trimmed[dot+1:]), true
}

// add records e; entries must be added in ascending ord.
func (w *wildcardIndex) add(e wildcardEntry) {
	key, ok := wildcardSuffixKey(e.pattern)
	if !ok {
		w.other = append(w.other, e)
		return
	}
	if w.bySuffix == nil {
		w.bySuffix = make(map[string][]wildcardEntry)
	}
	w.bySuffix[key] = append(w.bySuffix[key], e)
}

// first returns the matching entry with the lowest ord.
func (w *wildcardIndex) first(name string) (wildcardEntry, bool) {
	var best wildcardEntry
	found := false
	scan := func(entries []wildcardEntry) {
		for _, e := range entries {
			if found && e.ref.ord > best.ref.ord {
				return
			}
			if dns.MatchDomain(name, e.pattern) {
				best, found = e, true
				return
			}
		}
	}
	trimmed := strings.TrimSuffix(name, ".")
	if dot := strings.IndexByte(trimmed, '.'); dot >= 0 {
		scan(w.bySuffix[strings.ToLower(trimmed[dot+1:])])
	}
	scan(w.other)
	return best, found
}

type cidrEntry struct {
	prefix netip.Prefix
	ref    entryRef
}

func buildEntryIndex(lists []*policyList) entryIndex {
	idx := entryIndex{
		exactDomains: make(map[string]entryRef),
		ips:          make(map[netip.Addr]entryRef),
	}
	ord := 0
	for _, l := range lists {
		for _, pattern := range l.patterns {
			ref := entryRef{ord: ord, match: listMatch{list: l.client, rule: pattern}}
			ord++
			switch config.ClassifyEntry(pattern) {
			case config.EntryDomain:
				if config.IsWildcardPattern(pattern) {
					idx.wild.add(wildcardEntry{pattern: pattern, ref: ref})
				} else if key := foldName(pattern); !hasEntry(idx.exactDomains, key) {
					idx.exactDomains[key] = ref
				}
			case config.EntryIP:
				if e, err := config.ParseEntry(pattern); err == nil && !hasEntry(idx.ips, e.Addr) {
					idx.ips[e.Addr] = ref
				}
			case config.EntryCIDR:
				if e, err := config.ParseEntry(pattern); err == nil {
					idx.cidrs = append(idx.cidrs, cidrEntry{prefix: e.Prefix, ref: ref})
				}
			}
		}
	}
	return idx
}

func hasEntry[K comparable](m map[K]entryRef, k K) bool {
	_, ok := m[k]
	return ok
}

// newRoutingPolicy compiles cfg. prev, when not nil, is the policy it follows:
// an unchanged allowlist order keeps the previous rank epoch.
func newRoutingPolicy(cfg *config.Config, revision uint64, prev *routingPolicy) *routingPolicy {
	p := &routingPolicy{
		revision:  revision,
		cfg:       cfg,
		allowed:   cfg.AllowedClients(),
		byClient:  make(map[string]*policyList, len(cfg.VPNs)),
		holder:    make(map[string]string),
		vpnHolder: make(map[string]string),
	}
	p.rank = make(map[string]int, len(p.allowed))
	for i, id := range p.allowed {
		if _, dup := p.rank[id]; !dup {
			p.rank[id] = i
		}
	}
	switch {
	case prev == nil:
		p.rankEpoch = 1
	case slices.Equal(prev.allowed, p.allowed):
		p.rankEpoch = prev.rankEpoch
	default:
		p.rankEpoch = prev.rankEpoch + 1
	}

	p.any = newPolicyList(config.AnyVPN, cfg.Domains)
	p.except = newPolicyList(config.AnyVPN, cfg.Routing.ExceptRules())
	p.patterns = slices.Clone(p.any.patterns)
	for _, v := range cfg.VPNs {
		l := newPolicyList(v.Client, v.Domains)
		p.vpn = append(p.vpn, l)
		if _, dup := p.byClient[v.Client]; !dup {
			p.byClient[v.Client] = l
		}
		p.patterns = append(p.patterns, l.patterns...)
		for _, pattern := range l.patterns {
			if _, held := p.vpnHolder[pattern]; !held {
				p.vpnHolder[pattern] = v.Client
			}
			if _, held := p.holder[pattern]; !held {
				p.holder[pattern] = v.Client
			}
		}
	}
	for _, pattern := range p.any.patterns {
		if _, held := p.holder[pattern]; !held {
			p.holder[pattern] = config.AnyVPN
		}
	}
	p.hasWildcards = slices.ContainsFunc(p.patterns, config.IsWildcardPattern)
	p.entries = buildEntryIndex(append(slices.Clone(p.vpn), p.any))

	p.profiles = make([]config.TunnelProfile, len(cfg.Profiles))
	p.profile = make(map[string]int, len(cfg.Profiles))
	for i, pr := range cfg.Profiles {
		pr.DNS = slices.Clone(pr.DNS)
		p.profiles[i] = pr
		if _, dup := p.profile[pr.ID]; !dup {
			p.profile[pr.ID] = i
		}
	}
	return p
}

// clientRank is a client's position in the allowlist; unknown clients rank
// after every allowed one.
func (p *routingPolicy) clientRank(id string) int {
	if i, ok := p.rank[id]; id != "" && ok {
		return i
	}
	return len(p.allowed)
}

// list returns the list of a VPN client, or the Any VPN list for config.AnyVPN.
func (p *routingPolicy) list(client string) (*policyList, bool) {
	if client == config.AnyVPN {
		return p.any, true
	}
	l, ok := p.byClient[client]
	return l, ok
}

// listOwner returns the VPN client a name belongs to: the highest-priority
// client whose own list (exact entries and wildcards) matches it. A client owns
// its names whether or not its tunnel is up; when it is down they go direct.
func (p *routingPolicy) listOwner(name string) (string, bool) {
	key := foldName(name)
	for _, l := range p.vpn {
		if l.matches(name, key) {
			return l.client, true
		}
	}
	return "", false
}

// entryOwner returns the VPN client an exact name or an IP or CIDR entry
// belongs to: the highest-priority client whose own list holds it. An entry is
// the same entry only when written identically (lists hold canonical forms);
// overlapping but different networks are separate entries and the kernel's
// longest-prefix rule arbitrates between them.
func (p *routingPolicy) entryOwner(pattern string) (string, bool) {
	if config.IsLiteralEntry(pattern) {
		client, ok := p.vpnHolder[pattern]
		return client, ok
	}
	return p.listOwner(pattern)
}

// owningList finds the list a name belongs to and the session serving it. A
// name in any client's own list belongs to that client alone: it is routed
// only through that client's tunnel, and goes direct (nil session) while the
// tunnel is down or degraded, never through the Any VPN owner or another VPN.
// Only a name in no client's list uses the Any VPN list, which is served by the
// highest-priority healthy detected tunnel. sessions must be in priority order.
func (p *routingPolicy) owningList(sessions []*tunnelSession, name string) (*policyList, *tunnelSession) {
	key := foldName(name)
	for _, l := range p.vpn {
		if l.matches(name, key) {
			return l, clientSession(sessions, l.client)
		}
	}
	if p.any.matches(name, key) {
		return p.any, anyVPNSession(sessions)
	}
	return nil, nil
}

// wildcardOwnerOf returns the session a name routes through when it reaches
// its owner through a wildcard pattern, which is how names are routed as DNS
// answers arrive. A name its owning list holds only as an exact entry is
// resolved up front by that session's sync.
func (p *routingPolicy) wildcardOwnerOf(sessions []*tunnelSession, name string) *tunnelSession {
	l, s := p.owningList(sessions, name)
	if s == nil || !l.matchesWildcard(name) {
		return nil
	}
	return s
}

// exceptedName reports whether name goes direct instead of through the default VPN:
// the exception list covers it, and no connected VPN's list claims it. A list keeps
// its name while its VPN is up, and the exception decides only once it is down.
// sessions must be in priority order.
func (p *routingPolicy) exceptedName(sessions []*tunnelSession, name string) bool {
	if !p.except.matches(name, foldName(name)) {
		return false
	}
	_, owner := p.owningList(sessions, name)
	return owner == nil
}

// matchingEntry finds the list entry that covers name or ip, by the order
// ownership is decided: each VPN's own list by priority, then the Any VPN list.
// A domain entry is looked for first, since its /32 route outranks any network
// route an IP or CIDR entry adds; an IP entry then outranks a CIDR. name may be
// empty and ip invalid when one of them is unknown.
func (p *routingPolicy) matchingEntry(name string, ip netip.Addr) (listMatch, bool) {
	if p == nil {
		return listMatch{}, false
	}
	idx := &p.entries
	if name != "" {
		best, found := idx.exactDomains[foldName(name)]
		if w, ok := idx.wild.first(name); ok && (!found || w.ref.ord < best.ord) {
			best, found = w.ref, true
		}
		if found {
			return best.match, true
		}
	}
	if !ip.IsValid() {
		return listMatch{}, false
	}
	ip = ip.Unmap()
	if ref, ok := idx.ips[ip]; ok {
		return ref.match, true
	}
	for _, c := range idx.cidrs {
		if c.prefix.Contains(ip) {
			return c.ref.match, true
		}
	}
	return listMatch{}, false
}

// listHolding returns the list that holds pattern written exactly so: the
// highest-priority VPN's own list, then the Any VPN list.
func (p *routingPolicy) listHolding(pattern string) (string, bool) {
	if p == nil {
		return "", false
	}
	client, ok := p.holder[pattern]
	return client, ok
}

// profileByID returns a copy of one built-in profile.
func (p *routingPolicy) profileByID(id string) (config.TunnelProfile, bool) {
	i, ok := p.profile[id]
	if !ok {
		return config.TunnelProfile{}, false
	}
	pr := p.profiles[i]
	pr.DNS = slices.Clone(pr.DNS)
	return pr, true
}

// profileName is a profile's name, or its id when it no longer exists.
func (p *routingPolicy) profileName(id string) string {
	if i, ok := p.profile[id]; ok {
		return p.profiles[i].Name
	}
	return id
}
