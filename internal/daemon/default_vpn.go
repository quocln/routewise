package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/ledger"
	"github.com/quocln/routewise/internal/route"
)

// The default VPN carries the traffic no connected VPN's list claims, through the
// /2 routes in route/catch_all_routes.go. Every list route outranks them by being
// longer, so a listed name keeps its own VPN, and a listed name whose VPN is down
// has no route of its own and falls into them with no extra rule. The default
// route stays on the LAN, which is what makes "direct" a matter of removing them.
//
// reconcileLocked moves the role. It runs before each sync resolves any
// name, since a lookup would otherwise wait on a dead tunnel, and on a timer, which
// is also what restores a route the kernel dropped and retries after a failure.
// What it reports comes from what the managers hold, never from what it wanted.
//
// Two things must hold while the routes exist, and are put in place first:
//
//   - a built-in tunnel's transport must not enter a tunnel, so each running
//     tunnel's IPv4 server gets a host route through the LAN gateway. VPN apps
//     install their own, as they do for their own full tunnel;
//   - IPv6 must not leave around the routes, since RouteWise routes IPv4 only, so
//     global IPv6 is rejected unless routing.allow_ipv6 is on, or a built-in tunnel
//     connects over IPv6 and the block would kill it.
const (
	defaultVPNJournalName    = "default-vpn-routes.json"
	defaultVPNJournalVersion = 2
	defaultVPNCommandTimeout = 15 * time.Second
	// defaultVPNWatchEvery is how often the role's routes are checked against the kernel.
	defaultVPNWatchEvery = 5 * time.Second
)

// defaultVPNJournal records what would outlive a crashed helper, so the next start
// can remove it. A VPN app's tunnel survives the helper, and the role's routes with
// it, and a reject route or a server route would stay in the table until reboot.
type defaultVPNJournal struct {
	SchemaVersion int      `json:"schema_version"`
	CatchAll      bool     `json:"catch_all,omitempty"`
	Servers       []string `json:"servers,omitempty"`
	IPv6Rejected  bool     `json:"ipv6_rejected,omitempty"`
}

// defaultVPNRoutes is what the role holds outside the tunnel's own manager. It is
// guarded by mutationMu.
type defaultVPNRoutes struct {
	servers      map[netip.Addr]struct{}
	gateway      netip.Addr
	iface        string
	ipv6Rejected bool
}

// defaultVPNHost is what the role needs from the daemon that runs it. It decides nothing
// the role should: which tunnels exist and whether route state may change.
type defaultVPNHost interface {
	policy() *routingPolicy
	sessionList() []*tunnelSession
	isRegistered(s *tunnelSession) bool
	ownsGeneration(gen *generation) bool
	mayMutate(gen *generation) bool
	mayMutateSession(gen *generation, s *tunnelSession) bool
	routeTable() route.Table
	localInterface() string
	localPrefixes() []netip.Prefix
	endpointOwners() map[netip.Addr]string
	serverKnown(profileID string) bool
	ipv6TransportNames() []string
	ipv6Allowed() bool
	recordActivity(event activity.Event)
	defaultVPNJournalPath() string
}

// defaultVPNController holds the role: who carries the traffic no list claims, and what
// that needs in the routing table. reconcileLocked and what it calls run under the
// daemon's mutationMu; active, problem and ipv6Blocked may be read without it.
type defaultVPNController struct {
	host   defaultVPNHost
	logger *slog.Logger

	// active is the session holding the routes, nil while that traffic goes direct.
	// problem says why a connected VPN was passed over. ipv6Blocked says the IPv6 block
	// really is in place.
	active      atomic.Pointer[tunnelSession]
	problem     atomic.Pointer[string]
	ipv6Blocked atomic.Bool
	held        defaultVPNRoutes
	// journal records what would outlive a crash of this process.
	journal *ledger.Ledger[defaultVPNJournal]
}

func newDefaultVPNController(host defaultVPNHost, logger *slog.Logger) *defaultVPNController {
	return &defaultVPNController{
		host:    host,
		logger:  logger,
		journal: ledger.New[defaultVPNJournal](host.defaultVPNJournalPath),
	}
}

// carryAllReason explains why s must not carry all traffic, or returns "". An
// unproven built-in tunnel might not work, and with the routes on it nothing else
// would either; its server must be known, or the routes would swallow its own
// transport. A WireGuard peer drops what its AllowedIPs do not cover. A client that
// steers by policy rule would loop its transport back in.
func (s *tunnelSession) carryAllReason(serverKnown func(profileID string) bool) string {
	if !s.owned {
		if s.manager.PolicyRouted() {
			return "it steers traffic with a policy rule, so a route to it would loop its own transport"
		}
		return ""
	}
	if !s.proven.Load() {
		return "not proven to work yet"
	}
	if !serverKnown(s.profileID) {
		return "its server address is not known"
	}
	for _, p := range route.CatchAllPrefixes() {
		if reason := s.outsidePrefixReason(p); reason != "" {
			return "all traffic is " + reason
		}
	}
	return ""
}

// defaultVPNTarget picks the session the routes belong on: the default VPN, else its
// fallback, else none, which means direct. problem says why a connected VPN was
// passed over. sessions must be in priority order.
func defaultVPNTarget(pol *routingPolicy, sessions []*tunnelSession, serverKnown func(string) bool) (target *tunnelSession, problem string) {
	routing := pol.cfg.Routing
	if routing.DefaultVPN == "" || routing.Mode == config.RoutingModeAdditive {
		return nil, ""
	}
	for _, id := range []string{routing.DefaultVPN, routing.DefaultVPNFallback} {
		s := clientSession(sessions, id)
		if s == nil {
			continue
		}
		reason := s.carryAllReason(serverKnown)
		if reason == "" {
			return s, problem
		}
		if problem == "" {
			problem = fmt.Sprintf("%s cannot be the default VPN: %s", s.client.Name, reason)
		}
	}
	return nil, problem
}

// The daemon's side of the role.

// reconcileLocked moves the routes to the session that should hold them.
// Anything that stops the role from being safe leaves the traffic direct until the
// next pass tries again. Taking the routes away is allowed while route state is
// degraded, unlike every other mutation: nothing can check a tunnel then, and routes
// on a dead one would cut off the whole machine. The caller must hold mutationMu.
func (c *defaultVPNController) reconcileLocked(gen *generation) {
	if !c.host.ownsGeneration(gen) {
		return
	}
	pol := c.host.policy()
	sessions := c.host.sessionList()
	if pol.cfg.Routing.DefaultVPN == "" && !c.holdsAnything(sessions) {
		return
	}

	var target *tunnelSession
	var problems []string
	note := func(problem string) {
		if problem != "" {
			problems = append(problems, problem)
		}
	}
	if c.host.mayMutate(gen) {
		var problem string
		target, problem = defaultVPNTarget(pol, sessions, c.host.serverKnown)
		note(problem)
		if target != nil && !c.host.mayMutateSession(gen, target) {
			target = nil
		}
	} else if pol.cfg.Routing.DefaultVPN != "" {
		note("route state could not be verified, so traffic goes direct")
	}
	if target != nil {
		warning, err := c.holdRoutesLocked()
		note(warning)
		if err != nil {
			note("could not keep the built-in VPNs' servers out of the default VPN: " + err.Error())
			target = nil
		}
	}
	for _, s := range sessions {
		if s != target && s.manager.CatchAll() {
			if err := s.manager.SetCatchAll(false); err != nil {
				note(fmt.Sprintf("could not take the default VPN routes off %s: %v", s.iface, err))
			}
		}
	}
	if target != nil {
		if err := target.manager.SetCatchAll(true); err != nil {
			note(err.Error())
			if undo := target.manager.SetCatchAll(false); undo != nil {
				note(fmt.Sprintf("could not take the default VPN routes off %s: %v", target.iface, undo))
			}
		}
	}

	// Who holds the routes now, whatever was wanted. The server routes and the IPv6
	// block stay until nobody does.
	var holder *tunnelSession
	for _, s := range sessions {
		if s.manager.CatchAll() {
			holder = s
			break
		}
	}
	if holder == nil {
		c.releaseRoutesLocked()
	}
	c.publish(holder, strings.Join(problems, "; "))
}

// holdsAnything reports whether the role left anything to clean up. The
// caller must hold mutationMu.
func (c *defaultVPNController) holdsAnything(sessions []*tunnelSession) bool {
	h := &c.held
	return len(h.servers) > 0 || h.ipv6Rejected || c.active.Load() != nil ||
		slices.ContainsFunc(sessions, func(s *tunnelSession) bool { return s.manager.CatchAll() })
}

// publish records a change of holder or problem where the user can see it.
func (c *defaultVPNController) publish(holder *tunnelSession, problem string) {
	c.ipv6Blocked.Store(c.held.ipv6Rejected)
	if prev := c.active.Swap(holder); prev != holder {
		event := activity.Event{Kind: activity.KindVPN, Name: "Default VPN", Detail: "traffic no list claims now goes direct"}
		if holder != nil {
			event.Name, event.Interface = holder.client.Name, holder.iface
			event.Detail = "traffic no list claims now goes through this VPN"
		}
		c.host.recordActivity(event)
		c.logger.Info("default VPN changed", "detail", event.Detail, "client", event.Name, "interface", event.Interface)
	}
	var prevProblem string
	if p := c.problem.Swap(&problem); p != nil {
		prevProblem = *p
	}
	if problem != "" && problem != prevProblem {
		c.logger.Warn("default VPN problem", "problem", problem)
		c.host.recordActivity(activity.Event{Kind: activity.KindRefused, Name: "Default VPN", Detail: problem})
	}
}

// holdRoutesLocked puts in place what must exist before the routes do. It
// checks the kernel each time: a change of network can drop a static route, and a
// held route the kernel lost would send a tunnel's transport into a tunnel. warning
// says what could not be done without stopping the role; err means the role must not
// go ahead.
func (c *defaultVPNController) holdRoutesLocked() (warning string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultVPNCommandTimeout)
	defer cancel()
	table := c.host.routeTable()
	h := &c.held

	want := make(map[netip.Addr]struct{})
	prefixes := c.host.localPrefixes()
	for addr := range c.host.endpointOwners() {
		// A server on the LAN is reached over its connected route already.
		if !slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			want[addr] = struct{}{}
		}
	}
	var (
		gateway netip.Addr
		iface   string
	)
	if len(want) > 0 {
		if gateway, iface, err = table.LocalGateway(ctx, c.host.localInterface()); err != nil {
			return "", err
		}
	}
	ipv6Tunnels := c.host.ipv6TransportNames()
	rejectIPv6 := !c.host.ipv6Allowed() && len(ipv6Tunnels) == 0

	// The journal names everything this pass might leave behind, before any of it
	// can exist.
	if err := c.saveJournal(true, unionAddrs(h.servers, want), h.ipv6Rejected || rejectIPv6); err != nil {
		return "", err
	}
	for addr := range h.servers {
		_, keep := want[addr]
		if keep && gateway == h.gateway && iface == h.iface {
			if got, _, err := table.Lookup(ctx, addr); err == nil && got == iface {
				continue
			}
		}
		if err := table.DeleteHost(ctx, addr); err != nil {
			return "", fmt.Errorf("delete the route to %s: %w", addr, err)
		}
		delete(h.servers, addr)
	}
	for addr := range want {
		if _, held := h.servers[addr]; held {
			continue
		}
		if err := table.AddHost(ctx, addr, gateway, iface); err != nil {
			return "", fmt.Errorf("route %s through the LAN: %w", addr, err)
		}
		if h.servers == nil {
			h.servers = make(map[netip.Addr]struct{})
		}
		h.servers[addr] = struct{}{}
	}
	h.gateway, h.iface = gateway, iface

	if rejectIPv6 && !h.ipv6Rejected {
		if err := table.AddIPv6RejectAll(ctx); err != nil {
			warning = "IPv6 is not blocked and can leave around the default VPN: " + err.Error()
		} else {
			h.ipv6Rejected = true
		}
	} else if !rejectIPv6 && h.ipv6Rejected {
		if err := table.DeleteIPv6RejectAll(ctx); err != nil {
			warning = "could not lift the IPv6 block: " + err.Error()
		} else {
			h.ipv6Rejected = false
		}
	}
	if len(ipv6Tunnels) > 0 && !c.host.ipv6Allowed() {
		warning = "IPv6 is not blocked and can leave around the default VPN, because " +
			strings.Join(ipv6Tunnels, ", ") + " connects over IPv6"
	}
	return warning, c.saveJournal(true, h.servers, h.ipv6Rejected)
}

// releaseRoutesLocked removes what holdRoutesLocked put in place.
// What cannot be removed stays recorded for the next pass to try again.
func (c *defaultVPNController) releaseRoutesLocked() {
	h := &c.held
	ctx, cancel := context.WithTimeout(context.Background(), defaultVPNCommandTimeout)
	defer cancel()
	table := c.host.routeTable()
	for addr := range h.servers {
		if err := table.DeleteHost(ctx, addr); err != nil {
			c.logger.Error("could not remove a default VPN server route", "address", addr, "error", err)
			continue
		}
		delete(h.servers, addr)
	}
	if h.ipv6Rejected {
		if err := table.DeleteIPv6RejectAll(ctx); err != nil {
			c.logger.Error("could not remove the IPv6 block for the default VPN", "error", err)
		} else {
			h.ipv6Rejected = false
		}
	}
	c.ipv6Blocked.Store(h.ipv6Rejected)
	if err := c.saveJournal(false, h.servers, h.ipv6Rejected); err != nil {
		c.logger.Error("default VPN journal not saved", "error", err)
	}
}

func unionAddrs(a, b map[netip.Addr]struct{}) map[netip.Addr]struct{} {
	out := make(map[netip.Addr]struct{}, len(a)+len(b))
	for addr := range a {
		out[addr] = struct{}{}
	}
	for addr := range b {
		out[addr] = struct{}{}
	}
	return out
}

// saveJournal replaces the journal, or removes it with nothing to record.
func (c *defaultVPNController) saveJournal(catchAll bool, servers map[netip.Addr]struct{}, ipv6Rejected bool) error {
	if !catchAll && len(servers) == 0 && !ipv6Rejected {
		return c.journal.Remove()
	}
	j := defaultVPNJournal{SchemaVersion: defaultVPNJournalVersion, CatchAll: catchAll, IPv6Rejected: ipv6Rejected}
	for addr := range servers {
		j.Servers = append(j.Servers, addr.String())
	}
	slices.Sort(j.Servers)
	return c.journal.Save(j)
}

// recoverLeftovers removes what a crashed helper left. What cannot be
// removed is carried in defaultVPNHeld, so the next pass retries it and the journal
// keeps naming it. A journal that cannot be read still gets the reject route removed:
// only RouteWise adds that route, and left in place it blocks IPv6 for good.
func (c *defaultVPNController) recoverLeftovers() {
	ctx, cancel := context.WithTimeout(context.Background(), defaultVPNCommandTimeout)
	defer cancel()
	table := c.host.routeTable()

	j, found, err := c.journal.Load()
	if err == nil && !found {
		return
	}
	if err != nil || j.SchemaVersion != defaultVPNJournalVersion {
		c.logger.Error("default VPN journal is not usable; other leftovers may remain until reboot", "path", c.host.defaultVPNJournalPath(), "error", err)
		if err := table.DeleteIPv6RejectAll(ctx); err != nil {
			c.logger.Error("leftover IPv6 block not removed", "error", err)
		}
		return
	}

	h := &c.held
	failed := false
	if j.CatchAll {
		for _, p := range route.CatchAllPrefixes() {
			if err := table.DeleteNet(ctx, p.String(), "", ""); err != nil {
				c.logger.Error("leftover default VPN route not removed", "route", p, "error", err)
				failed = true
			}
		}
	}
	for _, text := range j.Servers {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			c.logger.Warn("default VPN journal names something that is not an address; skipped", "entry", text)
			continue
		}
		if err := table.DeleteHost(ctx, addr); err != nil {
			c.logger.Error("leftover default VPN server route not removed", "address", addr, "error", err)
			if h.servers == nil {
				h.servers = make(map[netip.Addr]struct{})
			}
			h.servers[addr] = struct{}{}
			failed = true
		}
	}
	if j.IPv6Rejected {
		if err := table.DeleteIPv6RejectAll(ctx); err != nil {
			c.logger.Error("leftover IPv6 block not removed", "error", err)
			h.ipv6Rejected = true
			failed = true
		}
	}
	if failed {
		return
	}
	if err := c.journal.Remove(); err != nil {
		c.logger.Error("default VPN journal not cleared", "path", c.host.defaultVPNJournalPath(), "error", err)
	}
}

// status reports the setting and who carries the traffic now, or nil while
// no default VPN is set.
func (c *defaultVPNController) status() *api.DefaultVPNStatus {
	routing := c.host.policy().cfg.Routing
	if routing.DefaultVPN == "" {
		return nil
	}
	status := &api.DefaultVPNStatus{Client: routing.DefaultVPN, Fallback: routing.DefaultVPNFallback, State: api.DefaultVPNDirect}
	if routing.Mode == config.RoutingModeAdditive {
		status.Problem = "a default VPN needs inverted routing mode"
		return status
	}
	if p := c.problem.Load(); p != nil {
		status.Problem = *p
	}
	if s := c.active.Load(); s != nil && c.host.isRegistered(s) {
		status.State = api.DefaultVPNFallback
		if s.client.ID == routing.DefaultVPN {
			status.State = api.DefaultVPNPrimary
		}
		status.ActiveClient, status.ActiveInterface = s.client.Name, s.iface
	}
	return status
}

// carries reports the session traffic to ip leaves through when no list
// route covers it. An address on this machine or its network never does.
func (c *defaultVPNController) carries(ip netip.Addr) *tunnelSession {
	s := c.active.Load()
	ip = ip.Unmap()
	if s == nil || !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || !c.host.isRegistered(s) {
		return nil
	}
	if slices.ContainsFunc(c.host.localPrefixes(), func(p netip.Prefix) bool { return p.Contains(ip) }) {
		return nil
	}
	return s
}
