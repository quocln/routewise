package dns

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/quocln/routewise/internal/resolverfiles"
)

// resolvedEntry is one DNS server systemd-resolved holds, with the link it
// belongs to (0 for the global configuration).
type resolvedEntry struct {
	ifindex int
	addr    netip.Addr
	port    uint16
}

// resolvedLink is what the nameserver selection needs to know about a link.
type resolvedLink struct {
	name string
	// defaultRoute is whether resolved sends names that no routing domain
	// claims to this link's servers, as it does for the LAN uplink and for a
	// full-tunnel VPN (which publishes the routing domain "~.").
	defaultRoute bool
	// domains are the link's search and routing domains.
	domains []string
}

// renderResolvedConfig writes systemd-resolved's server list in the
// `scutil --dns` layout parseResolverBlocks reads, so macOS and Linux share one
// selection of system and VPN nameservers. Each link becomes one resolver
// block bound to its interface; a link that is not a default route is written
// with a domain, which is how the parser tells a supplemental resolver from a
// default one.
//
// Left out: RouteWise's own link, which points at the local forwarder, and any
// server on a port other than 53, which a plain upstream address cannot
// express. The 127.0.0.53 stub is loopback and never survives the parser, so
// the forwarder is never pointed back at resolved.
func renderResolvedConfig(entries []resolvedEntry, links map[int]resolvedLink) string {
	byLink := make(map[int][]netip.Addr)
	for _, e := range entries {
		if e.port != 0 && e.port != 53 {
			continue
		}
		byLink[e.ifindex] = append(byLink[e.ifindex], e.addr)
	}
	indexes := make([]int, 0, len(byLink))
	for idx := range byLink {
		indexes = append(indexes, idx)
	}
	slices.Sort(indexes) // the global block (0) first, then links in index order

	var b strings.Builder
	b.WriteString("DNS configuration\n")
	n := 0
	for _, idx := range indexes {
		var link resolvedLink
		if idx != 0 {
			var ok bool
			if link, ok = links[idx]; !ok || link.name == resolverfiles.LinkName {
				continue
			}
		}
		n++
		fmt.Fprintf(&b, "\nresolver #%d\n", n)
		for i, addr := range byLink[idx] {
			fmt.Fprintf(&b, "  nameserver[%d] : %s\n", i, addr)
		}
		if idx == 0 {
			continue
		}
		fmt.Fprintf(&b, "  if_index : %d (%s)\n", idx, link.name)
		if !link.defaultRoute {
			domain := "(routing only)"
			for _, d := range link.domains {
				if d = strings.TrimPrefix(d, "~"); d != "" {
					domain = d
					break
				}
			}
			fmt.Fprintf(&b, "  domain   : %s\n", domain)
		}
	}
	return b.String()
}
