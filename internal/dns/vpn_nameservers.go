package dns

import (
	"bufio"
	"context"
	"net/netip"
	"strings"

	"github.com/quocln/routewise/internal/ifacename"
)

// FallbackOptions controls the guess VPNNameservers falls back on when no
// server is bound to the tunnel.
type FallbackOptions struct {
	// Enabled allows the guess. Callers keep it off for the first seconds of
	// a connection, so a VPN that binds its servers a moment late is not
	// mistaken for one that never will.
	Enabled bool
	// IsLocal reports whether an address sits on a directly connected network.
	IsLocal func(netip.Addr) bool
	// Known reports whether a server was already configured before the VPN
	// connected, and so is the network's own rather than the VPN's.
	Known func(netip.Addr) bool
}

// VPNNameservers returns the IPv4 DNS servers the VPN on iface serves, read
// from the system's resolver configuration (`scutil --dns` on macOS), and whether they were bound to the tunnel (as opposed
// to guessed).
func VPNNameservers(ctx context.Context, iface string, opts FallbackOptions) ([]netip.Addr, bool, error) {
	out, err := systemDNSConfig(ctx)
	if err != nil {
		return nil, false, err
	}
	servers, bound := SelectVPNNameservers(out, iface, opts)
	return servers, bound, nil
}

// SystemNameservers returns every IPv4 DNS server in the current
// configuration, used as the baseline of servers that are not the VPN's.
func SystemNameservers(ctx context.Context) ([]netip.Addr, error) {
	out, err := systemDNSConfig(ctx)
	if err != nil {
		return nil, err
	}
	var all []netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, b := range parseResolverBlocks(out) {
		for _, addr := range b.servers {
			if !seen[addr] {
				seen[addr] = true
				all = append(all, addr)
			}
		}
	}
	return all, nil
}

// SelectVPNNameservers picks the VPN's DNS servers from `scutil --dns` output
// and reports whether they were bound to the tunnel.
//
// Servers bound to the tunnel interface win, as AWS Client VPN, OpenVPN
// Connect, and the WireGuard app publish them. wg-quick instead writes its
// servers onto every network service. For that case, when allowed, the guess
// takes private or CGNAT servers from default (non-supplemental) resolvers
// that are not bound to any tunnel, sit outside every directly connected
// network, and were not configured before the VPN connected: with a full
// tunnel up, the tunnel is the only path to them.
func SelectVPNNameservers(output, iface string, opts FallbackOptions) ([]netip.Addr, bool) {
	blocks := parseResolverBlocks(output)
	if bound := collectServers(blocks, func(b resolverBlock) bool { return b.iface == iface }); len(bound) > 0 {
		return bound, true
	}
	if !opts.Enabled {
		return nil, false
	}
	candidates := collectServers(blocks, func(b resolverBlock) bool {
		return b.domain == "" && !ifacename.IsTunnel(b.iface)
	})
	var guessed []netip.Addr
	for _, addr := range candidates {
		if !addr.IsPrivate() && !cgnat.Contains(addr) {
			continue
		}
		if (opts.IsLocal != nil && opts.IsLocal(addr)) || (opts.Known != nil && opts.Known(addr)) {
			continue
		}
		guessed = append(guessed, addr)
	}
	return guessed, false
}

// cgnat is the shared address space (RFC 6598) some VPNs hand out.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// ParseScutilNameservers extracts, in order and without duplicates, the IPv4
// nameservers of every resolver block whose if_index names iface. Both the
// default and the scoped sections are read, because a VPN may publish its
// servers in either. Loopback servers are skipped: RouteWise's own wildcard
// resolver files point at 127.0.0.1 and must never become an upstream.
func ParseScutilNameservers(output, iface string) []netip.Addr {
	return collectServers(parseResolverBlocks(output), func(b resolverBlock) bool { return b.iface == iface })
}

// resolverBlock is one "resolver #N" entry of `scutil --dns`.
type resolverBlock struct {
	iface   string // from if_index, "" when unbound
	domain  string // set for supplemental (per-domain) resolvers
	servers []netip.Addr
}

func collectServers(blocks []resolverBlock, match func(resolverBlock) bool) []netip.Addr {
	var result []netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, b := range blocks {
		if !match(b) {
			continue
		}
		for _, addr := range b.servers {
			if !seen[addr] {
				seen[addr] = true
				result = append(result, addr)
			}
		}
	}
	return result
}

// parseResolverBlocks reads the resolver blocks of `scutil --dns` output,
// keeping IPv4 non-loopback nameservers only.
func parseResolverBlocks(output string) []resolverBlock {
	var blocks []resolverBlock
	var cur *resolverBlock
	flush := func() {
		if cur != nil {
			blocks = append(blocks, *cur)
		}
		cur = nil
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "resolver #") {
			flush()
			cur = &resolverBlock{}
			continue
		}
		if strings.HasPrefix(line, "DNS configuration") {
			flush()
			continue
		}
		if cur == nil {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch {
		case strings.HasPrefix(key, "nameserver["):
			addr, err := netip.ParseAddr(value)
			if err == nil && addr.Is4() && !addr.IsLoopback() {
				cur.servers = append(cur.servers, addr)
			}
		case key == "domain":
			cur.domain = value
		case key == "if_index":
			// "23 (utun3)"
			if open := strings.IndexByte(value, '('); open >= 0 && strings.HasSuffix(value, ")") {
				cur.iface = value[open+1 : len(value)-1]
			}
		}
	}
	flush()
	return blocks
}
