package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/quocln/routewise/internal/winnet"
)

// Windows has no unreachable or blackhole route type. The reject route is a
// /128 through the software loopback interface with an on-link next hop: the
// stack hands the packet to the loopback, finds no local address for it and
// drops it, so connections to the address never leave the machine. It is only
// the best available stand-in, and unlike the Linux route it makes a connect
// fail by dropping rather than by an immediate error; applications that try
// IPv6 and IPv4 together still move on to IPv4.
//
// A route of this shape is recognisable as RouteWise's own: nothing else puts
// a global unicast /128 on the loopback interface, so deleting only such
// routes never touches a real route to the same address.

// loopbackAdapter finds the software loopback interface.
func loopbackAdapter(adapters []winnet.Adapter) (winnet.Adapter, bool) {
	for _, a := range adapters {
		if a.IsLoopback() {
			return a, true
		}
	}
	return winnet.Adapter{}, false
}

// AddIPv6Reject adds a host route that makes connections to addr fail. A route
// that already exists is accepted, so a leftover of an earlier process is
// adopted.
func (t *windowsTable) AddIPv6Reject(ctx context.Context, addr netip.Addr) error {
	if err := ValidateBlockableIPv6(addr); err != nil {
		return fmt.Errorf("AddIPv6Reject: %w", err)
	}
	return t.addRejectPrefix(ctx, netip.PrefixFrom(addr, 128))
}

// AddIPv6RejectAll adds the reject route for every global IPv6 address.
func (t *windowsTable) AddIPv6RejectAll(ctx context.Context) error {
	return t.addRejectPrefix(ctx, globalUnicastV6)
}

func (t *windowsTable) addRejectPrefix(ctx context.Context, prefix netip.Prefix) error {
	unlock, err := t.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	adapters, err := t.ops.adapters()
	if err != nil {
		return err
	}
	lo, ok := loopbackAdapter(adapters)
	if !ok {
		return fmt.Errorf("add reject route %s: no loopback interface", prefix)
	}
	err = t.ops.create(newWinRoute{Adapter: lo, Dest: prefix, NextHop: netip.IPv6Unspecified(), Metric: hostMetric})
	if err != nil && !errors.Is(err, errWinRouteExists) {
		return fmt.Errorf("add reject route %s: %w", prefix, err)
	}
	return nil
}

// DeleteIPv6Reject removes the reject route for addr. A route that is already
// gone is not an error, and a real route to addr is never touched.
func (t *windowsTable) DeleteIPv6Reject(ctx context.Context, addr netip.Addr) error {
	if err := ValidateBlockableIPv6(addr); err != nil {
		return fmt.Errorf("DeleteIPv6Reject: %w", err)
	}
	return t.deleteRejectPrefix(ctx, netip.PrefixFrom(addr, 128))
}

// DeleteIPv6RejectAll removes the reject route for every global IPv6 address.
func (t *windowsTable) DeleteIPv6RejectAll(ctx context.Context) error {
	return t.deleteRejectPrefix(ctx, globalUnicastV6)
}

func (t *windowsTable) deleteRejectPrefix(ctx context.Context, prefix netip.Prefix) error {
	unlock, err := t.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	rs, err := t.ops.routes(6)
	if err != nil {
		return err
	}
	for _, r := range routesTo(rs, prefix) {
		if !r.Adapter.IsLoopback() {
			continue
		}
		if err := t.ops.remove(r); err != nil && !errors.Is(err, errWinRouteGone) {
			return fmt.Errorf("delete reject route %s: %w", prefix, err)
		}
	}
	return nil
}
