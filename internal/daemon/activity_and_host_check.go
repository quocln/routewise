package daemon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/dns"
	"github.com/quocln/routewise/internal/dnswatch"
	"github.com/quocln/routewise/internal/route"
)

const (
	// activityCapacity is how many events the in-memory activity log keeps.
	activityCapacity = 2000
	// dnsAnswerSettle delays recording a captured DNS answer. The forwarder
	// adds a wildcard name's route after the upstream answer arrives (which
	// is when it is captured) but before it replies, so recording at once
	// would mark a routed address as direct.
	dnsAnswerSettle = 300 * time.Millisecond
	// dnsAnswerDedup suppresses the same answer seen again within this time,
	// such as the daemon's own lookup asking several servers at once.
	dnsAnswerDedup = 5 * time.Second
	// dnsWatchRescan is how often the watched interfaces are refreshed.
	dnsWatchRescan = 10 * time.Second
	// ipv6BlockedNote is what routes.check says of an IPv6 address that holds a
	// reject route.
	ipv6BlockedNote = "IPv6 blocked so apps use IPv4"
	// hostCheckTimeout bounds resolving a host for routes.check.
	hostCheckTimeout = 5 * time.Second
)

// recordActivity adds an event to the activity log and, while history is
// enabled, queues it for the activity table. It only appends in memory, so it is
// safe under the route manager's lock.
func (d *Daemon) recordActivity(e activity.Event) {
	if e.Kind != activity.KindDNS {
		e = d.attributeEvent(e)
	}
	e = d.activity.Add(e)
	if d.activityStore != nil && d.historyOn.Load() {
		d.activityStore.Record(e)
	}
}

// attributeEvent fills in the tunnel and the list entry a route or refusal
// concerns, when they are known: the tunnel from the interface the event names,
// the entry from the policy compiled right now. A label that is not a domain
// (the VPN DNS route) is never matched by name, and VPN events carry only their
// name. It reads only atomics and a leaf lock, so it is safe under the route
// manager's lock.
func (d *Daemon) attributeEvent(e activity.Event) activity.Event {
	if e.Kind == activity.KindVPN {
		return e
	}
	if e.VPN == "" && e.Interface != "" {
		if s := d.sessions.get(e.Interface); s != nil {
			e.VPN = s.client.Name
		}
	}
	if e.List != nil || d.store == nil {
		return e
	}
	name := e.Name
	if name == vpnDNSRouteLabel {
		name = ""
	}
	var ip netip.Addr
	if len(e.Addresses) > 0 {
		ip = addrOfEvent(e.Addresses[0].IP)
	}
	if m, ok := d.store.Policy().matchingEntry(name, ip); ok {
		e.List, e.Rule = &m.list, m.rule
	}
	return e
}

// addrOfEvent reads an event address, an IP or a CIDR (whose network address
// stands for it), or returns the zero address.
func addrOfEvent(s string) netip.Addr {
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr()
	}
	return netip.Addr{}
}

// Activity returns the events newer than since, oldest first. With wait set,
// it first waits up to that long for one to exist.
func (d *Daemon) Activity(since uint64, limit int, wait time.Duration) (uint64, []activity.Event) {
	if wait > 0 {
		ctx := d.baseCtx
		if ctx == nil {
			ctx = context.Background()
		}
		d.activity.Wait(ctx, since, wait)
	}
	latest := d.activity.Latest()
	if events, ok := d.storedActivity(since, limit); ok {
		// The reply is as new as its newest event: anything newer is read
		// next time, and none is skipped.
		if n := len(events); n > 0 {
			latest = events[n-1].Seq
		}
		return latest, events
	}
	return latest, d.activity.List(since, limit)
}

// onRouteChange records every host route and network route RouteWise adds or
// removes. A network route's address is its CIDR. It runs under the route
// manager's lock, so it only appends to the log.
func (d *Daemon) onRouteChange(c route.RouteChange) {
	kind, verdict := activity.KindRouteAdded, activity.ViaVPN
	if c.Type == route.RouteRemoved {
		kind, verdict = activity.KindRouteRemoved, activity.Direct
	}
	dest := c.Destination.String()
	if c.Prefix.IsValid() {
		dest = c.Prefix.String()
	}
	d.recordActivity(activity.Event{
		Kind:      kind,
		Name:      c.Domain,
		Addresses: []activity.Address{{IP: dest, Verdict: verdict}},
		Interface: c.Interface,
	})
	d.logger.Info("route "+c.Type.String(), "ip", dest, "domain", c.Domain, "interface", c.Interface)
}

// onDNSAnswer receives every DNS answer the watcher captures and records it
// once the routes it may trigger have settled.
func (d *Daemon) onDNSAnswer(a dnswatch.Answer) {
	// The name map needs no settling: a connection follows its answer.
	d.names.Add(a.Name, a.Addresses, a.TTL)
	// A connection follows its answer, so the block must be in place before the
	// settle delay, not after it.
	d.blockListedIPv6(a)
	if !d.answers.push(a) {
		d.logger.Debug("DNS answer queue is full; not recording the answer", "name", a.Name)
	}
}

func (d *Daemon) recordDNSAnswer(a dnswatch.Answer) {
	sorted := slices.Clone(a.Addresses)
	slices.SortFunc(sorted, func(x, y netip.Addr) int { return x.Compare(y) })
	key := a.Name
	for _, ip := range sorted {
		key += " " + ip.String()
	}

	now := time.Now()
	d.dnsSeenMu.Lock()
	if seen, ok := d.dnsSeen[key]; ok && now.Sub(seen) < dnsAnswerDedup {
		d.dnsSeenMu.Unlock()
		return
	}
	d.dnsSeen[key] = now
	if len(d.dnsSeen) > 1024 {
		for k, t := range d.dnsSeen {
			if now.Sub(t) >= dnsAnswerDedup {
				delete(d.dnsSeen, k)
			}
		}
	}
	d.dnsSeenMu.Unlock()

	sessions := d.sessionList()
	addresses := make([]activity.Address, 0, len(a.Addresses))
	// routed is the first address a managed tunnel carries, and via its tunnel:
	// the answer is attributed to where its traffic actually goes.
	var routed netip.Addr
	var via *tunnelSession
	for _, ip := range a.Addresses {
		verdict := activity.Direct
		s, _ := routedBy(sessions, ip)
		if s == nil {
			s = d.defaultVPN.carries(ip)
		}
		if s != nil {
			verdict = activity.ViaVPN
			if via == nil {
				routed, via = ip, s
			}
		}
		addresses = append(addresses, activity.Address{IP: ip.String(), Verdict: verdict, Blocked: d.ipv6Block.isBlocked(ip)})
	}
	event := activity.Event{
		Kind:      activity.KindDNS,
		Name:      a.Name,
		Addresses: addresses,
		Interface: a.Interface,
		Detail:    "answered by " + a.Server.String(),
	}
	if via != nil {
		event.VPN = via.client.Name
	}
	if d.store != nil {
		if m, ok := d.store.Policy().matchingEntry(a.Name, routed); ok {
			event.List, event.Rule = &m.list, m.rule
		}
	}
	d.recordActivity(event)
	d.logger.Debug("DNS answer", "name", a.Name, "addresses", a.Addresses, "interface", a.Interface)
}

// dnsWatchLoop keeps the DNS watcher on the current interfaces until the
// daemon stops. rescan asks for an immediate refresh, for example when a
// tunnel comes up.
func (d *Daemon) dnsWatchLoop(ctx context.Context) {
	defer close(d.dnsWatchDone)
	if d.dnsWatcher == nil {
		<-ctx.Done()
		return
	}
	defer d.dnsWatcher.Stop()

	ticker := time.NewTicker(dnsWatchRescan)
	defer ticker.Stop()
	for {
		d.dnsWatcher.Sync(dnswatch.WatchableInterfaces())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-d.dnsWatchRescan:
		}
	}
}

// rescanDNSWatch asks the DNS watcher to pick up interface changes now.
func (d *Daemon) rescanDNSWatch() {
	select {
	case d.dnsWatchRescan <- struct{}{}:
	default:
	}
}

// routedBy returns the session whose manager holds the route the kernel uses
// for ip, and the domain or list entry it was added for. That is the longest
// matching route (a host route, else the narrowest network route containing
// ip); sessions are in priority order, which breaks a tie.
func routedBy(sessions []*tunnelSession, ip netip.Addr) (*tunnelSession, string) {
	var best *tunnelSession
	var bestSource string
	bestBits := -1
	for _, s := range sessions {
		if source, bits, routed := s.manager.RouteMatch(ip); routed && bits > bestBits {
			best, bestSource, bestBits = s, source, bits
		}
	}
	return best, bestSource
}

// CheckHost resolves host the way any app on this Mac would and asks the
// kernel, for each address, which interface traffic to it leaves through.
// Resolving through the system also exercises wildcard routing: a name under
// a wildcard gets its route before the answer comes back.
func (d *Daemon) CheckHost(host string) (api.HostCheck, error) {
	host = normalizeHost(host)
	if host == "" {
		return api.HostCheck{}, fmt.Errorf("%w: empty host", api.ErrRejected)
	}

	result := api.HostCheck{Host: host, Addresses: []api.HostAddress{}}
	sessions := d.sessionList()
	if len(sessions) > 0 {
		result.VPNInterface = sessions[0].iface
	}

	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		result.MatchedPatterns = dns.FindMatchingPatterns(host, d.store.Policy().patterns)
		ctx, cancel := context.WithTimeout(context.Background(), hostCheckTimeout)
		defer cancel()
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return api.HostCheck{}, fmt.Errorf("%w: resolve %s: %v", api.ErrRejected, host, err)
		}
		ips = resolved
	}

	for _, ip := range ips {
		ip = ip.Unmap()
		addr := api.HostAddress{IP: ip.String(), Verdict: string(activity.Direct)}
		if !ip.Is4() {
			addr.Note = "IPv6 is not routed by RouteWise"
			if d.ipv6Block.isBlocked(ip) || d.defaultVPN.ipv6Blocked.Load() {
				addr.Note = ipv6BlockedNote
			}
			result.Addresses = append(result.Addresses, addr)
			continue
		}
		if _, domain := routedBy(sessions, ip); domain != "" {
			addr.RoutedFor = domain
		}
		iface, gw, err := d.routeManager.LookupRoute(ip)
		if err != nil {
			addr.Note = err.Error()
		} else {
			addr.Interface = iface
			if gw.IsValid() {
				addr.Gateway = gw.String()
			}
			// The kernel's answer decides: the address is "vpn" when it
			// leaves through any managed tunnel, whichever one.
			if s := sessionOnInterface(sessions, iface); s != nil {
				addr.Verdict = string(activity.ViaVPN)
				addr.VPN = s.client.Name
			}
		}
		result.Addresses = append(result.Addresses, addr)
	}
	return result, nil
}

// sessionOnInterface returns the session whose tunnel is iface, or nil.
func sessionOnInterface(sessions []*tunnelSession, iface string) *tunnelSession {
	for _, s := range sessions {
		if s.iface == iface {
			return s
		}
	}
	return nil
}

// normalizeHost accepts a bare host, an IP, or a URL someone pasted, and
// returns the lowercase host without a trailing dot.
func normalizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			raw = u.Hostname()
		}
	} else if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	return strings.TrimSuffix(strings.ToLower(raw), ".")
}
