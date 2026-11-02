package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"syscall"

	"github.com/quocln/routewise/internal/winnet"
)

// Errors the Windows route operations report in a form the table logic can act
// on; the IP Helper implementation maps ERROR_OBJECT_ALREADY_EXISTS and
// ERROR_NOT_FOUND to them.
var (
	errWinRouteExists = errors.New("route already exists")
	errWinRouteGone   = errors.New("route not found")
	// errGatewayNotOnLink means no adapter's connected network contains the
	// gateway, the Windows form of "network is unreachable".
	errGatewayNotOnLink = errors.New("gateway is not on any connected network")
)

// Win32 error codes for an unreachable network or host, which the stack
// returns when a route's next hop cannot be reached.
const (
	errnoNetworkUnreachable syscall.Errno = 1231
	errnoHostUnreachable    syscall.Errno = 1232
)

// newWinRoute is a route to create.
type newWinRoute struct {
	Adapter winnet.Adapter
	Dest    netip.Prefix
	// NextHop is the unspecified address of the family for an on-link route.
	NextHop netip.Addr
	Metric  uint32
}

// windowsOps is the Windows IP Helper API the table drives: it reads the route
// and adapter tables and creates, re-ranks and deletes single routes. Tests
// replace it with an in-memory table.
type windowsOps interface {
	adapters() ([]winnet.Adapter, error)
	// routes reads the table of one family, 4 or 6.
	routes(family int) ([]winnet.Route, error)
	// create adds r, failing with errWinRouteExists when a route with the same
	// interface, destination and next hop is there.
	create(r newWinRoute) error
	// setMetric changes the own metric of the route with r's key.
	setMetric(r winnet.Route, metric uint32) error
	// remove deletes the route with r's key, failing with errWinRouteGone when
	// there is none.
	remove(r winnet.Route) error
}

// hostMetric is the own metric of the host, prefix and restored routes
// RouteWise adds. Windows ranks routes by prefix length first, so a host route
// wins over any broader one whatever its metric; zero leaves the interface
// metric to decide between equal prefixes.
const hostMetric = 0

// windowsTable is the Table of Windows, over the IP Helper API.
//
// Windows records no marker on a route that says who added it: the route
// protocol of a route created through the API is always "static" and cannot
// be chosen, so the routes RouteWise owns are known only from the manager's own
// records and its transition journal, as on macOS, whose BSD table has no
// marker either. The one exception is a default route RouteWise created
// itself while swapping the global default: those keys are remembered for the
// life of the process so the swap back removes them and nothing else.
type windowsTable struct {
	ops windowsOps

	// mu serialises every method, which each read the table and then change it.
	mu    sync.Mutex
	owned map[routeKey]bool

	// While a batch is open (BeginBatch), adding and deleting routes read the
	// route and adapter tables once and keep that copy current with their own
	// changes, instead of reading both again for every route.
	batchDepth    int
	batchRoutes   []winnet.Route
	batchLoaded   bool
	batchAdapters []winnet.Adapter
	adaptersReady bool
}

func newWindowsTable(ops windowsOps) *windowsTable {
	return &windowsTable{ops: ops, owned: make(map[routeKey]bool)}
}

func (t *windowsTable) lock(ctx context.Context) (unlock func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.mu.Lock()
	return t.mu.Unlock, nil
}

// BeginBatch starts a batch: the routes added and deleted until the matching
// EndBatch share one read of the route and adapter tables. A change another
// process makes meanwhile is not seen until the batch ends, and an add the stack
// refuses as a duplicate is accepted as it always was. Batches nest.
func (t *windowsTable) BeginBatch() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.batchDepth++
}

// EndBatch ends the batch BeginBatch started and drops the copy of the tables
// once the outermost one ends.
func (t *windowsTable) EndBatch() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.batchDepth > 0 {
		t.batchDepth--
	}
	if t.batchDepth == 0 {
		t.batchRoutes, t.batchLoaded, t.batchAdapters, t.adaptersReady = nil, false, nil, false
	}
}

// ipv4Routes reads the IPv4 routes, or returns the batch's copy. The caller
// must hold mu.
func (t *windowsTable) ipv4Routes() ([]winnet.Route, error) {
	if t.batchDepth == 0 {
		return t.ops.routes(4)
	}
	if !t.batchLoaded {
		rs, err := t.ops.routes(4)
		if err != nil {
			return nil, err
		}
		t.batchRoutes, t.batchLoaded = rs, true
	}
	return t.batchRoutes, nil
}

// adapterList reads the adapters, or returns the batch's copy. The caller must
// hold mu.
func (t *windowsTable) adapterList() ([]winnet.Adapter, error) {
	if t.batchDepth == 0 {
		return t.ops.adapters()
	}
	if !t.adaptersReady {
		as, err := t.ops.adapters()
		if err != nil {
			return nil, err
		}
		t.batchAdapters, t.adaptersReady = as, true
	}
	return t.batchAdapters, nil
}

// noteCreated records a route just created in the batch's copy.
func (t *windowsTable) noteCreated(n newWinRoute) {
	if t.batchLoaded {
		t.batchRoutes = append(t.batchRoutes, winnet.Route{
			Adapter: n.Adapter, Dest: n.Dest, NextHop: n.NextHop, Metric: n.Metric, Protocol: winnet.ProtocolNetMgmt,
		})
	}
}

// noteRemoved drops a route just deleted from the batch's copy.
func (t *windowsTable) noteRemoved(r winnet.Route) {
	if !t.batchLoaded {
		return
	}
	key := keyOf(r)
	t.batchRoutes = slices.DeleteFunc(t.batchRoutes, func(e winnet.Route) bool { return keyOf(e) == key })
}

// Snapshot reads the IPv4 routes in the BSD table's notation.
func (t *windowsTable) Snapshot(ctx context.Context) ([]RouteEntry, error) {
	unlock, err := t.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	rs, err := t.ops.routes(4)
	if err != nil {
		return nil, err
	}
	return snapshotEntries(rs), nil
}

// Default returns the gateway and interface of the preferred default route.
func (t *windowsTable) Default(ctx context.Context) (netip.Addr, string, error) {
	unlock, err := t.lock(ctx)
	if err != nil {
		return netip.Addr{}, "", err
	}
	defer unlock()
	rs, err := t.ops.routes(4)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("get default route: %w", err)
	}
	defaults := defaultRoutesOf(rs)
	if len(defaults) == 0 {
		return netip.Addr{}, "", fmt.Errorf("default route not found in route table")
	}
	return defaults[0].Gateway(), defaults[0].Adapter.Alias, nil
}

// DefaultGateway returns the gateway of the preferred default route.
func (t *windowsTable) DefaultGateway(ctx context.Context) (netip.Addr, error) {
	gw, _, err := t.Default(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	if !gw.IsValid() {
		return netip.Addr{}, fmt.Errorf("default route has no gateway IP")
	}
	return gw, nil
}

// LocalGateway returns the LAN gateway and its interface even while a VPN owns
// the default route.
func (t *windowsTable) LocalGateway(ctx context.Context, prefer string) (netip.Addr, string, error) {
	unlock, err := t.lock(ctx)
	if err != nil {
		return netip.Addr{}, "", err
	}
	defer unlock()
	rs, err := t.ops.routes(4)
	if err != nil {
		return netip.Addr{}, "", err
	}
	return localGatewayOf(rs, prefer)
}

// Lookup returns the interface and gateway traffic to dest leaves through,
// chosen from the table by longest prefix and then lowest metric. The gateway
// is invalid for an on-link route.
func (t *windowsTable) Lookup(ctx context.Context, dest netip.Addr) (string, netip.Addr, error) {
	if !dest.IsValid() {
		return "", netip.Addr{}, fmt.Errorf("lookup route: invalid address")
	}
	unlock, err := t.lock(ctx)
	if err != nil {
		return "", netip.Addr{}, err
	}
	defer unlock()
	rs, err := t.ops.routes(4)
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("lookup route for %s: %w", dest, err)
	}
	best, ok := bestRouteTo(rs, dest.Unmap())
	if !ok {
		return "", netip.Addr{}, fmt.Errorf("lookup route for %s: no route", dest)
	}
	return best.Adapter.Alias, best.Gateway(), nil
}

// DropClonedLinkLayer does nothing: Windows keeps neighbour entries apart from
// routes.
func (t *windowsTable) DropClonedLinkLayer(context.Context, netip.Addr) {}

// IsUnreachable reports whether err means the gateway is not on any connected
// network.
func (t *windowsTable) IsUnreachable(err error) bool {
	return errors.Is(err, errGatewayNotOnLink) ||
		errors.Is(err, errnoNetworkUnreachable) || errors.Is(err, errnoHostUnreachable)
}

// target picks the adapter and next hop of a new route: the named interface
// when there is one (the next hop is gateway, or on-link without one),
// otherwise the interface that reaches gateway.
func (t *windowsTable) target(rs []winnet.Route, gateway netip.Addr, iface string) (winnet.Adapter, netip.Addr, error) {
	nextHop := netip.IPv4Unspecified()
	if gateway.IsValid() {
		nextHop = gateway.Unmap()
	}
	switch {
	case iface != "":
		adapters, err := t.adapterList()
		if err != nil {
			return winnet.Adapter{}, netip.Addr{}, err
		}
		a, ok := adapterByAlias(adapters, iface)
		if !ok {
			return winnet.Adapter{}, netip.Addr{}, fmt.Errorf("interface %s: not found", iface)
		}
		return a, nextHop, nil
	case gateway.IsValid():
		a, ok := adapterForGateway(rs, nextHop)
		if !ok {
			return winnet.Adapter{}, netip.Addr{}, fmt.Errorf("%s: %w", gateway, errGatewayNotOnLink)
		}
		return a, nextHop, nil
	}
	return winnet.Adapter{}, netip.Addr{}, fmt.Errorf("either gateway or interface must be specified")
}

// existingFor is how the route table already answers for a destination that
// is about to be added.
type existingFor struct {
	// exact is a route with the very key being added: that route is ours to
	// adopt, because it leads through the same interface and next hop.
	exact bool
	// sameIface is a route to the destination through the same interface.
	sameIface bool
	// otherIface names the interface of a route through a different one.
	otherIface string
}

func classifyExisting(rs []winnet.Route, prefix netip.Prefix, a winnet.Adapter, nextHop netip.Addr) existingFor {
	var ex existingFor
	want := routeKey{index: a.Index, dest: prefix, nextHop: nextHop}
	if !nextHop.IsValid() || nextHop.IsUnspecified() {
		want.nextHop = netip.Addr{}
	}
	for _, r := range routesTo(rs, prefix) {
		switch {
		case keyOf(r) == want:
			ex.exact, ex.sameIface = true, true
		case r.Adapter.Index == a.Index:
			ex.sameIface = true
		default:
			ex.otherIface = r.Adapter.Alias
		}
	}
	return ex
}

// addUnicast creates the route unless one with its key exists, and reports
// what already led to the destination. mustOwn makes a route through another
// interface a refusal, as the kernel's "File exists" with a foreign route is
// on the other platforms; AddNet, which only puts back a route taken away,
// adds alongside.
func (t *windowsTable) addUnicast(rs []winnet.Route, prefix netip.Prefix, gateway netip.Addr, iface string, mustOwn bool) error {
	a, nextHop, err := t.target(rs, gateway, iface)
	if err != nil {
		return fmt.Errorf("add route %s: %w", prefix, err)
	}
	ex := classifyExisting(rs, prefix, a, nextHop)
	switch {
	case ex.exact:
		return nil
	case mustOwn && ex.sameIface:
		return nil
	case mustOwn && ex.otherIface != "":
		return fmt.Errorf("%s is already routed through %s, not this tunnel: %w", prefix, ex.otherIface, ErrRouteOwnedElsewhere)
	}
	created := newWinRoute{Adapter: a, Dest: prefix, NextHop: nextHop, Metric: hostMetric}
	err = t.ops.create(created)
	if err != nil && !errors.Is(err, errWinRouteExists) {
		return fmt.Errorf("add route %s: %w", prefix, err)
	}
	if err == nil {
		t.noteCreated(created)
	}
	return nil
}

func (t *windowsTable) add(ctx context.Context, prefix netip.Prefix, gateway netip.Addr, iface string, mustOwn bool) error {
	unlock, err := t.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	rs, err := t.ipv4Routes()
	if err != nil {
		return fmt.Errorf("add route %s: %w", prefix, err)
	}
	return t.addUnicast(rs, prefix, gateway, iface, mustOwn)
}

// AddHost adds a host route via gateway, or through iface when gateway is
// invalid. A route to the host that already leads through this tunnel's
// interface is adopted; one through another interface is refused.
func (t *windowsTable) AddHost(ctx context.Context, dest, gateway netip.Addr, iface string) error {
	dest = dest.Unmap()
	if !dest.Is4() {
		return fmt.Errorf("addHostRoute: %s is not an IPv4 address", dest)
	}
	return t.add(ctx, netip.PrefixFrom(dest, 32), gateway, iface, true)
}

// AddPrefix is AddHost for a network route.
func (t *windowsTable) AddPrefix(ctx context.Context, prefix netip.Prefix, gateway netip.Addr, iface string) error {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return fmt.Errorf("addPrefixRoute: %s is not an IPv4 prefix", prefix)
	}
	return t.add(ctx, prefix.Masked(), gateway, iface, true)
}

// AddNet adds a network route from the destination and gateway as the table
// printed them, to restore a route taken away. One that already exists is
// accepted.
func (t *windowsTable) AddNet(ctx context.Context, destRaw, gatewayRaw, iface string) error {
	dst, err := parseRouteDest(destRaw)
	if err != nil {
		return fmt.Errorf("addNetRoute: %w", err)
	}
	var gateway netip.Addr
	if gatewayRaw != "" {
		if gateway, err = netip.ParseAddr(gatewayRaw); err != nil {
			return fmt.Errorf("addNetRoute: gateway %q: %w", gatewayRaw, err)
		}
	}
	return t.add(ctx, dst, gateway, iface, false)
}

// deleteUnicast removes the routes to exactly prefix that are not one the stack
// derived from an address and that leave through iface (or, with no interface,
// reach gateway); with neither, every such route goes. A table keeps one route
// per interface and next hop, so a destination two tunnels share keeps the
// other tunnel's route. A route that is already gone is not an error.
func (t *windowsTable) deleteUnicast(ctx context.Context, prefix netip.Prefix, gateway netip.Addr, iface string) error {
	unlock, err := t.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	rs, err := t.ipv4Routes()
	if err != nil {
		return fmt.Errorf("delete route %s: %w", prefix, err)
	}
	var errs []error
	for _, r := range routesTo(rs, prefix) {
		if r.Protocol == winnet.ProtocolLocal || !routeOwnedBy(r, gateway, iface) {
			continue
		}
		if err := t.ops.remove(r); err != nil && !errors.Is(err, errWinRouteGone) {
			errs = append(errs, fmt.Errorf("delete route %s on %s: %w", prefix, r.Adapter.Alias, err))
			continue
		}
		delete(t.owned, keyOf(r))
		t.noteRemoved(r)
	}
	return errors.Join(errs...)
}

// DeleteHost removes a host route; one that is already gone is not an error.
func (t *windowsTable) DeleteHost(ctx context.Context, dest netip.Addr) error {
	dest = dest.Unmap()
	return t.deleteUnicast(ctx, netip.PrefixFrom(dest, dest.BitLen()), netip.Addr{}, "")
}

// DeleteNet removes a network route given in the table's own notation.
func (t *windowsTable) DeleteNet(ctx context.Context, destRaw, gatewayRaw, iface string) error {
	dst, err := parseRouteDest(destRaw)
	if err != nil {
		return fmt.Errorf("deleteNetRoute: %w", err)
	}
	return t.deleteUnicast(ctx, dst, ownerGateway(gatewayRaw), iface)
}
