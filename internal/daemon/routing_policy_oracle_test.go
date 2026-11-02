package daemon

import (
	"net/netip"
	"slices"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/dns"
)

// The functions below are the ownership rules written straight against a raw
// configuration, with no precompilation. The compiled routingPolicy must
// answer exactly as they do; the equivalence tests run both.

func oracleListMatches(rules []config.DomainRule, name string) bool {
	return slices.ContainsFunc(rules, func(r config.DomainRule) bool { return dns.MatchDomain(name, r.Pattern) })
}

func oracleListOwner(cfg *config.Config, name string) (string, bool) {
	for _, v := range cfg.VPNs {
		if oracleListMatches(v.Domains, name) {
			return v.Client, true
		}
	}
	return "", false
}

func oracleEntryOwner(cfg *config.Config, pattern string) (string, bool) {
	if config.IsLiteralEntry(pattern) {
		for _, v := range cfg.VPNs {
			if slices.ContainsFunc(v.Domains, func(r config.DomainRule) bool { return r.Pattern == pattern }) {
				return v.Client, true
			}
		}
		return "", false
	}
	return oracleListOwner(cfg, pattern)
}

func oracleOwningList(cfg *config.Config, sessions []*tunnelSession, name string) ([]config.DomainRule, *tunnelSession) {
	for _, v := range cfg.VPNs {
		if oracleListMatches(v.Domains, name) {
			return v.Domains, clientSession(sessions, v.Client)
		}
	}
	if oracleListMatches(cfg.Domains, name) {
		return cfg.Domains, anyVPNSession(sessions)
	}
	return nil, nil
}

func oracleWildcardOwnerOf(cfg *config.Config, sessions []*tunnelSession, name string) *tunnelSession {
	rules, s := oracleOwningList(cfg, sessions, name)
	if s == nil {
		return nil
	}
	for _, r := range rules {
		if config.IsWildcardPattern(r.Pattern) && dns.MatchDomain(name, r.Pattern) {
			return s
		}
	}
	return nil
}

func oracleMatchingEntry(cfg *config.Config, name string, ip netip.Addr) (listMatch, bool) {
	if cfg == nil {
		return listMatch{}, false
	}
	type list struct {
		id    string
		rules []config.DomainRule
	}
	lists := make([]list, 0, len(cfg.VPNs)+1)
	for _, v := range cfg.VPNs {
		lists = append(lists, list{v.Client, v.Domains})
	}
	lists = append(lists, list{"", cfg.Domains})

	for _, want := range []config.EntryKind{config.EntryDomain, config.EntryIP, config.EntryCIDR} {
		for _, l := range lists {
			for _, r := range l.rules {
				if oracleEntryCovers(r.Pattern, want, name, ip) {
					return listMatch{list: l.id, rule: r.Pattern}, true
				}
			}
		}
	}
	return listMatch{}, false
}

func oracleEntryCovers(pattern string, want config.EntryKind, name string, ip netip.Addr) bool {
	if config.ClassifyEntry(pattern) != want {
		return false
	}
	switch want {
	case config.EntryDomain:
		return name != "" && dns.MatchDomain(name, pattern)
	default:
		if !ip.IsValid() {
			return false
		}
		e, err := config.ParseEntry(pattern)
		if err != nil {
			return false
		}
		if want == config.EntryIP {
			return e.Addr == ip.Unmap()
		}
		return e.Prefix.Contains(ip.Unmap())
	}
}

func oracleListHolding(cfg *config.Config, pattern string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	has := func(rules []config.DomainRule) bool {
		return slices.ContainsFunc(rules, func(r config.DomainRule) bool { return r.Pattern == pattern })
	}
	for _, v := range cfg.VPNs {
		if has(v.Domains) {
			return v.Client, true
		}
	}
	if has(cfg.Domains) {
		return "", true
	}
	return "", false
}

// oracleAssignPatterns is assignPatterns over a raw configuration.
func oracleAssignPatterns(cfg *config.Config, sessions []*tunnelSession) []sessionPatterns {
	anyOwner := anyVPNSession(sessions)
	out := make([]sessionPatterns, 0, len(sessions))
	for _, s := range sessions {
		var list []string
		if s == anyOwner {
			for _, r := range cfg.Domains {
				if !config.IsWildcardPattern(r.Pattern) {
					if _, owned := oracleEntryOwner(cfg, r.Pattern); owned {
						continue
					}
				}
				list = append(list, r.Pattern)
			}
		}
		if id := s.client.ID; clientSession(sessions, id) == s {
			if rules, ok := cfg.DomainList(id); ok {
				for _, r := range rules {
					if !config.IsWildcardPattern(r.Pattern) {
						owner, _ := oracleEntryOwner(cfg, r.Pattern)
						if owner != id && (!config.IsLiteralEntry(r.Pattern) || clientSession(sessions, owner) == nil) {
							continue
						}
					}
					list = append(list, r.Pattern)
				}
			}
		}
		var deduped []string
		for _, v := range list {
			if !slices.Contains(deduped, v) {
				deduped = append(deduped, v)
			}
		}
		out = append(out, sessionPatterns{session: s, patterns: deduped})
	}
	return out
}
