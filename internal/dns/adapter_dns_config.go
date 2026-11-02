package dns

import (
	"fmt"
	"net/netip"
	"strings"
)

// adapterDNS is one network adapter's DNS servers as Windows reports them
// (GetAdaptersAddresses). The conversion from the Windows structures lives in
// system_dns_windows.go; the selection below is plain data.
type adapterDNS struct {
	index int
	// alias is the adapter's friendly name ("Ethernet", "Local Area
	// Connection 2"), the name RouteWise uses for an interface on Windows.
	alias string
	// up is whether the adapter is operational; a disconnected adapter keeps
	// its configured servers, which are not reachable.
	up      bool
	servers []netip.Addr
}

// renderAdapterConfig writes the adapters' servers in the `scutil --dns`
// layout parseResolverBlocks reads, so macOS, Linux and Windows share one
// selection of system and VPN nameservers. Each adapter becomes one resolver
// block bound to its interface, as default (not supplemental): Windows has no
// per-adapter routing domains.
//
// Left out: adapters that are down and adapters with no servers. Loopback
// servers are dropped by the parser, so the forwarder is never pointed back at
// itself, and NRPT rules (which are not adapter settings) never appear here.
func renderAdapterConfig(adapters []adapterDNS) string {
	var b strings.Builder
	b.WriteString("DNS configuration\n")
	n := 0
	for _, a := range adapters {
		if !a.up || len(a.servers) == 0 {
			continue
		}
		n++
		fmt.Fprintf(&b, "\nresolver #%d\n", n)
		for i, s := range a.servers {
			fmt.Fprintf(&b, "  nameserver[%d] : %s\n", i, s)
		}
		fmt.Fprintf(&b, "  if_index : %d (%s)\n", a.index, singleLine(a.alias))
	}
	return b.String()
}

// singleLine keeps an alias on one line so it cannot start another field.
func singleLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}
