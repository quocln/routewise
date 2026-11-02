package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// The default VPN carries the traffic no list claims through four /2 routes, not
// the /1 pair a full-tunnel client installs. The table keeps one route per
// destination, so holding the /1 pair would stop the next VPN client from adding
// its own, and that pair is how the monitor detects a client at all. /2 routes
// leave those destinations free and outrank them, so a client that connects
// later is still detected, and swept, while the role stays where it is. No list
// entry can be as broad (config.MinEntryPrefixBits), so a listed name keeps its
// own tunnel, and the default route stays on the LAN.
var catchAllPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/2"),
	netip.MustParsePrefix("64.0.0.0/2"),
	netip.MustParsePrefix("128.0.0.0/2"),
	netip.MustParsePrefix("192.0.0.0/2"),
}

// CatchAllPrefixes returns the networks a tunnel holding the role must accept.
func CatchAllPrefixes() []netip.Prefix { return catchAllPrefixes[:] }

// isCatchAllRoute returns which of the role's networks e is, in any notation
// the table prints.
func isCatchAllRoute(e RouteEntry) (netip.Prefix, bool) {
	p, err := parseRouteDest(e.Destination)
	if err != nil {
		return netip.Prefix{}, false
	}
	for _, want := range catchAllPrefixes {
		if p == want {
			return want, true
		}
	}
	return netip.Prefix{}, false
}

// SetCatchAll installs the role's routes on this manager's tunnel, or removes
// them. A failure leaves CatchAll true while routes may remain, so the caller can
// see that and try again: a half-removed set would keep part of IPv4 in a tunnel
// nothing else knows about.
func (m *Manager) SetCatchAll(on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !on && !m.catchAll {
		return nil
	}
	ctx := context.Background()
	entries, err := m.table.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshot route table: %w", err)
	}
	if on {
		m.catchAll = true
		return m.ensureCatchAllLocked(ctx, entries)
	}
	var errs []error
	for _, e := range entries {
		if _, ok := isCatchAllRoute(e); !ok || e.Interface != m.state.VPNInterface {
			continue
		}
		if err := m.table.DeleteNet(ctx, e.Destination, e.Gateway, e.Interface); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", e.Destination, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	m.catchAll = false
	return nil
}

// CatchAll reports whether this manager's tunnel holds, or may still hold, the
// role's routes.
func (m *Manager) CatchAll() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.catchAll
}

// PolicyRouted reports whether the tunnel's traffic is steered by a policy rule,
// as wg-quick on Linux does. Such a client marks its transport packets and relies
// on main having no route for them, so a route to its tunnel in main would loop
// the transport back in.
func (m *Manager) PolicyRouted() bool {
	m.mu.RLock()
	table, iface := m.table, m.state.VPNInterface
	m.mu.RUnlock()
	rules, ok := table.(policyRuleTable)
	if !ok || iface == "" {
		return false
	}
	_, found, err := rules.MainLookupPriority(context.Background(), iface)
	return err != nil || found
}

// ensureCatchAllLocked adds the missing routes. A network another tunnel holds is
// reported before anything is added, and the additions are read back: the route
// tool accepts `File exists` as success, so a route that appeared after the
// snapshot would otherwise pass for ours.
func (m *Manager) ensureCatchAllLocked(ctx context.Context, entries []RouteEntry) error {
	if m.state.VPNInterface == "" {
		return errors.New("default VPN route: tunnel interface not set")
	}
	missing, err := m.missingCatchAllLocked(entries)
	if err != nil || len(missing) == 0 {
		return err
	}
	for _, p := range missing {
		if err := m.table.AddNet(ctx, p.String(), "", m.state.VPNInterface); err != nil {
			return fmt.Errorf("default VPN route %s: %w", p, err)
		}
	}
	entries, err = m.table.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshot route table: %w", err)
	}
	if missing, err = m.missingCatchAllLocked(entries); err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("default VPN route %s did not appear in the table", missing[0])
	}
	return nil
}

// missingCatchAllLocked lists the networks not yet through this tunnel, or fails
// when another interface holds one. An interface-scoped route overrides nothing,
// so it is in no one's way.
func (m *Manager) missingCatchAllLocked(entries []RouteEntry) ([]netip.Prefix, error) {
	held := make(map[netip.Prefix]bool, len(catchAllPrefixes))
	for _, e := range entries {
		p, ok := isCatchAllRoute(e)
		if !ok {
			continue
		}
		if e.Interface == m.state.VPNInterface {
			held[p] = true
		} else if !strings.Contains(e.Flags, "I") {
			return nil, fmt.Errorf("default VPN route: %s already leads through %s", p, e.Interface)
		}
	}
	var missing []netip.Prefix
	for _, p := range catchAllPrefixes {
		if !held[p] {
			missing = append(missing, p)
		}
	}
	return missing, nil
}
