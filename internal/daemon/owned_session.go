package daemon

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/vpnclient"
)

// An owned session is the session of a tunnel the helper itself runs for a
// built-in profile (WireGuard or Outline). It differs from a detected tunnel's
// session in what it never does:
//
//   - it never goes through the monitor, so it is never admitted, pending, or
//     identified with lsof;
//   - it never activates an inverted split tunnel: there are no catch-all
//     routes to remove, no default route to change, and nothing to reclaim, so
//     no enforcer runs for it;
//   - its manager is additive, which also keeps route syncs from touching any
//     catch-all route.
//
// Everything else is shared: its routes go through `-interface <utun>`, and its
// client ID sits in the allowlist so priority and list ownership follow the
// same rules.
//
// Three things are different for an owned session:
//
//   - it carries only its own list. The top-level Any VPN list routes through
//     detected tunnels alone (see anyVPNSession);
//   - it routes nothing once it stops working, and before its tunnel is proven
//     to work (tunnelSession.proven, set by the health checks) it routes only
//     while holding its first connect (tunnelSession.holding, at most
//     connectHoldLimit), so a connection made then waits instead of going
//     direct for good;
//   - the profile's DNS servers are routed into the utun only while
//     dns.use_vpn_dns is on, and never when they are one of this Mac's own
//     resolvers (see ensureOwnedDNS).

// attachOwnedSession registers the owned session of a tunnel that just came up.
// The session starts unproven but holding, so superviseHealth installs its list
// at once and keeps it while the tunnel proves itself (see connectHoldLimit).
func (d *Daemon) attachOwnedSession(gen *generation, p config.TunnelProfile, t builtinTunnel) (*tunnelSession, error) {
	client := vpnclient.Client{ID: p.ClientID(), Name: p.Name}
	s, err := d.newTunnelSession(gen, t.Name(), netip.Addr{}, client)
	if err != nil {
		return nil, err
	}
	s.owned, s.profileID = true, p.ID
	// A nil slice means unrestricted (Outline); a WireGuard tunnel always has a
	// non-nil one, possibly empty, naming where its peers accept packets.
	s.allowed = t.AllowedIPs()
	for _, text := range p.DNS {
		if addr, err := netip.ParseAddr(text); err == nil {
			s.ownedDNS = append(s.ownedDNS, addr)
		}
	}
	s.manager.SetAdditiveMode(true)
	s.holding.Store(true)

	ran, _ := d.withGenerationMutation(gen, func() error {
		d.sessions.add(s)
		return nil
	})
	if !ran {
		s.cancel()
		s.resolver.Close()
		return nil, errors.New("route management stopped")
	}

	// The history capture must see the utun's address at once, or the first
	// connections through it would be missed until the periodic rescan.
	d.rescanDNSWatch()
	d.recordActivity(activity.Event{Kind: activity.KindVPN, Name: p.Name, Interface: t.Name(), Detail: "connecting, its entries wait for the tunnel"})
	d.logger.Info("built-in VPN started", "profile", p.Name, "kind", p.Kind, "interface", t.Name())
	return s, nil
}

// releaseOwnedSession gives an owned session's routes back.
func (d *Daemon) releaseOwnedSession(gen *generation, s *tunnelSession) {
	if s == nil {
		return
	}
	d.releaseSession(gen, s)
	// A profile that was refused a DNS server because this one held it may have
	// it now.
	d.retryRefusedOwnedDNS(gen)
}

// outsideAllowedReason explains why ip must not be routed into s's tunnel
// because no peer of a WireGuard tunnel accepts it, or returns "". WireGuard
// drops a packet no peer's AllowedIPs covers, so such a route would silently
// blackhole the traffic.
func (s *tunnelSession) outsideAllowedReason(ip netip.Addr) string {
	if s.allowed == nil || addrCovered(s.allowed, ip) {
		return ""
	}
	return outsideAllowedText
}

// outsidePrefixReason is outsideAllowedReason for a network route.
func (s *tunnelSession) outsidePrefixReason(p netip.Prefix) string {
	if s.allowed == nil || prefixCovered(s.allowed, p) {
		return ""
	}
	return outsideAllowedText
}

const outsideAllowedText = "outside the peer's AllowedIPs, so WireGuard would drop its packets"

// v4Range is an inclusive range of IPv4 addresses as integers.
type v4Range struct{ lo, hi uint32 }

func v4Int(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func prefixRange(p netip.Prefix) (v4Range, bool) {
	a := p.Addr().Unmap()
	if !a.Is4() {
		return v4Range{}, false
	}
	p = netip.PrefixFrom(a, p.Bits()).Masked()
	lo := v4Int(p.Addr())
	return v4Range{lo: lo, hi: lo | (^uint32(0) >> uint(p.Bits()))}, true
}

// coveredRanges merges the IPv4 prefixes into sorted, disjoint, non-adjacent
// ranges, so a network the peers cover only together (two /9s making a /8) is
// recognized as covered.
func coveredRanges(allowed []netip.Prefix) []v4Range {
	var rs []v4Range
	for _, p := range allowed {
		if r, ok := prefixRange(p); ok {
			rs = append(rs, r)
		}
	}
	slices.SortFunc(rs, func(a, b v4Range) int { return cmp.Compare(a.lo, b.lo) })
	var out []v4Range
	for _, r := range rs {
		if n := len(out); n > 0 && (r.lo <= out[n-1].hi || r.lo-1 == out[n-1].hi) {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

func rangeCovered(allowed []netip.Prefix, want v4Range) bool {
	for _, r := range coveredRanges(allowed) {
		if r.lo <= want.lo && want.hi <= r.hi {
			return true
		}
	}
	return false
}

// addrCovered reports whether some AllowedIPs entry contains ip.
func addrCovered(allowed []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.Is4() {
		return false
	}
	n := v4Int(ip)
	return rangeCovered(allowed, v4Range{lo: n, hi: n})
}

// prefixCovered reports whether the AllowedIPs entries together contain every
// address of p.
func prefixCovered(allowed []netip.Prefix, p netip.Prefix) bool {
	r, ok := prefixRange(p)
	return ok && rangeCovered(allowed, r)
}

// endpointReason explains why ip must not be routed into any tunnel because it
// is the transport address of a running built-in tunnel, or returns "".
func (g lanGuard) endpointReason(ip netip.Addr) string {
	if name, ok := g.endpoints[ip]; ok {
		return "it is the server address of the built-in VPN " + name + ", whose own traffic must not enter a tunnel"
	}
	return ""
}

// endpointInPrefix explains why a network route to p must not exist because it
// covers a built-in tunnel's transport address, or returns "".
func (g lanGuard) endpointInPrefix(p netip.Prefix) string {
	for addr, name := range g.endpoints {
		if p.Contains(addr) {
			return "it covers the server address of the built-in VPN " + name + ", whose own traffic must not enter a tunnel"
		}
	}
	return ""
}
