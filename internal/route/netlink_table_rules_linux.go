//go:build linux

package route

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ownedRuleProtocol stamps every policy rule RouteWise adds (FRA_PROTOCOL,
// Linux 4.17 and later), the counterpart of ownedProtocol for routes:
// `ip rule show protocol 245` lists exactly what it owns, and a delete names it
// so a rule an administrator added for the same priority is never removed.
const ownedRuleProtocol uint8 = uint8(ownedProtocol)

// defaultMainRulePriority is where the kernel puts the lookup of the main table
// when no rule says otherwise.
const defaultMainRulePriority = 32766

// MainLookupPriority returns the priority at which a rule that looks up the
// main table runs just ahead of the policy rule sending all unmarked traffic
// into iface's own routing table. wg-quick, NetworkManager's WireGuard and
// Mullvad work that way: the tunnel's default route lives in a table of its own
// and the main table never holds it, so moving the main default cannot send
// unlisted traffic anywhere but the tunnel. found is false when no such rule
// exists, the case for every VPN that puts its routes in the main table.
func (t *netlinkTable) MainLookupPriority(ctx context.Context, iface string) (priority int, found bool, err error) {
	h, err := t.handle(ctx)
	if err != nil {
		return 0, false, err
	}
	link, err := h.LinkByName(iface)
	if err != nil {
		return 0, false, fmt.Errorf("interface %s: %w", iface, err)
	}
	rules, err := ruleList(h)
	if err != nil {
		return 0, false, err
	}

	mainPriority := defaultMainRulePriority
	for _, r := range rules {
		if isMainLookupRule(r) && r.Priority >= 0 && r.Priority < mainPriority {
			mainPriority = r.Priority
		}
	}

	best := -1
	for _, r := range rules {
		switch r.Table {
		case 0, unix.RT_TABLE_MAIN, unix.RT_TABLE_DEFAULT, unix.RT_TABLE_LOCAL:
			continue
		}
		if r.Priority < 0 || r.Priority >= mainPriority || !isCatchAllRule(r) {
			continue
		}
		if best >= 0 && r.Priority >= best {
			continue
		}
		leads, err := tableDefaultLeadsTo(h, r.Table, link.Attrs().Index)
		if err != nil {
			return 0, false, err
		}
		if leads {
			best = r.Priority
		}
	}
	if best < 0 {
		return 0, false, nil
	}
	if best < 2 {
		return 0, false, fmt.Errorf("the full tunnel rule of %s has priority %d, which leaves no room for a rule ahead of it", iface, best)
	}
	return best - 1, true, nil
}

// ruleList reads the IPv4 policy rules, repeating the dump when the kernel says
// the rule set moved underneath it.
func ruleList(h *netlink.Handle) ([]netlink.Rule, error) {
	var rules []netlink.Rule
	var err error
	for range maxDumpAttempts {
		rules, err = h.RuleList(netlink.FAMILY_V4)
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	return rules, nil
}

// isMainLookupRule reports whether r is an ordinary consultation of the main
// table for all traffic. A rule of ours, one that only suppresses short
// prefixes, and one that matches a mark, source or interface do not count: none
// of them is where unmarked traffic ordinarily reaches the main table.
func isMainLookupRule(r netlink.Rule) bool {
	return r.Table == unix.RT_TABLE_MAIN && r.Protocol != ownedRuleProtocol &&
		r.SuppressPrefixlen < 0 && r.Mark == 0 && !r.Invert && isMatchAll(r)
}

// isCatchAllRule reports whether r sends all traffic, or when inverted around a
// firewall mark all traffic that does not carry it, to its table.
func isCatchAllRule(r netlink.Rule) bool {
	if !isMatchAll(r) {
		return false
	}
	if r.Mark != 0 {
		return r.Invert
	}
	return !r.Invert
}

// isMatchAll reports whether r selects traffic by nothing but, possibly, a mark.
func isMatchAll(r netlink.Rule) bool {
	return isAnyNet(r.Src) && isAnyNet(r.Dst) && r.IifName == "" && r.OifName == "" &&
		r.Tos == 0 && r.IPProto == 0 && r.Dport == nil && r.Sport == nil && r.UIDRange == nil
}

func isAnyNet(n *net.IPNet) bool {
	if n == nil {
		return true
	}
	ones, _ := n.Mask.Size()
	return ones == 0
}

// tableDefaultLeadsTo reports whether the IPv4 default route of routing table
// id leaves through the link at index.
func tableDefaultLeadsTo(h *netlink.Handle, id, index int) (bool, error) {
	var routes []netlink.Route
	var err error
	for range maxDumpAttempts {
		routes, err = h.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: id, Type: unix.RTN_UNICAST}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE)
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			break
		}
	}
	if err != nil {
		return false, fmt.Errorf("list routes of table %d: %w", id, err)
	}
	for _, r := range routes {
		if _, via := nexthop(r); isDefaultRoute(r) && via == index {
			return true, nil
		}
	}
	return false, nil
}

// mainLookupRule is the rule AddMainLookupRule installs and
// DeleteMainLookupRule removes.
func mainLookupRule(priority int) *netlink.Rule {
	r := netlink.NewRule()
	r.Family = netlink.FAMILY_V4
	r.Priority = priority
	r.Table = unix.RT_TABLE_MAIN
	r.Protocol = ownedRuleProtocol
	return r
}

// AddMainLookupRule adds the rule `priority <n> lookup main`, which sends the
// traffic that reaches it by the main table's own routes: the LAN default for
// what is not listed, the host routes RouteWise added for what is. A rule that
// already exists is accepted, so a leftover of an earlier process is adopted.
func (t *netlinkTable) AddMainLookupRule(ctx context.Context, priority int) error {
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	if err := h.RuleAdd(mainLookupRule(priority)); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add rule %d lookup main: %w", priority, err)
	}
	return nil
}

// DeleteMainLookupRule removes that rule; one that is already gone is not an
// error. The delete names RouteWise's protocol, so a rule of the same priority
// somebody else added stays.
func (t *netlinkTable) DeleteMainLookupRule(ctx context.Context, priority int) error {
	h, err := t.handle(ctx)
	if err != nil {
		return err
	}
	if err := h.RuleDel(mainLookupRule(priority)); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("delete rule %d lookup main: %w", priority, err)
	}
	return nil
}
