package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Network routes carry the CIDR entries of a domain list. They are kept in
// their own map beside the host routes (a single IP entry is just a host
// route) and follow the same rules: one owner per destination across every
// tunnel, an existing kernel route is adopted only when it already leads
// through this tunnel, and Cleanup removes them.
//
// The kernel picks the longest matching prefix, so overlapping entries are not
// prevented: a domain's /32 inside another tunnel's CIDR leaves through the
// /32's tunnel, and nested CIDRs on different tunnels are both installed, the
// narrower one winning for the addresses it covers.

// minPrefixBits mirrors config.MinEntryPrefixBits: the route manager refuses a
// network broader than this even if a caller asks, because it runs as root.
const minPrefixBits = 8

// isRoutablePrefix reports whether a network route to p may be installed:
// IPv4, no shorter than /8, and clear of the this-network, loopback,
// link-local, and multicast/reserved ranges. config.ParseEntry applies the
// same rules to what a user may configure.
func isRoutablePrefix(p netip.Prefix) bool {
	if !p.IsValid() || !p.Addr().Is4() || p.Bits() < minPrefixBits {
		return false
	}
	for _, blocked := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/3"),
	} {
		if blocked.Overlaps(p) {
			return false
		}
	}
	return true
}

// SyncPrefixes makes the network routes the manager holds equal desired, a map
// of prefix to the list entry it serves: routes that left the set are deleted,
// missing ones are added. A prefix another manager holds, or the kernel
// already routes elsewhere, is reported as ErrRouteOwnedElsewhere and left
// alone; it does not degrade this manager.
func (m *Manager) SyncPrefixes(desired map[netip.Prefix]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.state.VPNGateway.IsValid() && m.state.VPNInterface == "" {
		return fmt.Errorf("VPN gateway or interface not set")
	}
	ctx := context.Background()

	// A route whose delete failed stays recorded: the kernel entry is still
	// there, so no other manager may take the prefix until it is retried.
	for p, info := range m.netRoutes {
		if _, keep := desired[p]; keep {
			continue
		}
		if err := m.table.DeleteNet(ctx, p.String(), info.Gateway.String(), info.Interface); err != nil {
			m.addPendingOnceLocked(PendingCleanup{Kind: "delete_route", Destination: p.String(), Gateway: info.Gateway.String(), Interface: info.Interface, Reason: err.Error()})
			continue
		}
		m.forgetPrefixLocked(p)
		m.recordPrefixChange(RouteRemoved, p, netip.Addr{}, info.SourceEntry)
	}

	var conflicts []error
	for p, entry := range desired {
		if !isRoutablePrefix(p) {
			conflicts = append(conflicts, fmt.Errorf("refusing to route %s: not a routable IPv4 network", p))
			continue
		}
		if info, exists := m.netRoutes[p]; exists {
			if info.SourceEntry != entry {
				info.SourceEntry = entry
				m.netRoutes[p] = info
			}
			continue
		}
		if err := m.claimPrefixLocked(p); err != nil {
			conflicts = append(conflicts, err)
			continue
		}
		if err := m.table.AddPrefix(ctx, p, m.state.VPNGateway, m.state.VPNInterface); err != nil {
			m.releasePrefixClaimLocked(p)
			if errors.Is(err, ErrRouteOwnedElsewhere) {
				conflicts = append(conflicts, err)
				continue
			}
			m.addPendingLocked(PendingCleanup{Kind: "restore_route", Destination: p.String(), Gateway: m.state.VPNGateway.String(), Interface: m.state.VPNInterface, Reason: err.Error()})
			continue
		}
		m.netRoutes[p] = PrefixRouteInfo{
			Prefix:      p,
			Gateway:     m.state.VPNGateway,
			Interface:   m.state.VPNInterface,
			SourceEntry: entry,
			AddedAt:     time.Now(),
		}
		m.recordPrefixChange(RouteAdded, p, m.state.VPNGateway, entry)
	}
	return errors.Join(conflicts...)
}

// releasePrefixClaimLocked gives up this manager's claim on p without touching
// netRoutes. The caller must hold m.mu.
func (m *Manager) releasePrefixClaimLocked(p netip.Prefix) {
	if m.registry != nil {
		m.registry.releasePrefix(p, m)
	}
}
