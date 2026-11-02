package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/quocln/routewise/internal/winnet"
)

// moveDefault makes target the preferred IPv4 default route without ever
// leaving the machine with none: the new route is created (or an existing one
// with the same interface and next hop is re-ranked) ahead of the current
// preferred default before anything is deleted.
//
// Windows keeps one route per interface, destination and next hop and ranks by
// metric, so unlike the Linux table the new default cannot take the old one's
// slot; it is given a metric just ahead of it instead. dropCurrent says
// whether the displaced default is then deleted: it is when RouteWise is
// taking the default away from a tunnel, and only when RouteWise created it
// when it is giving the default back to one.
//
// A route cannot rank better than its interface metric, so a default on an
// adapter whose interface metric is above another LAN's total never becomes
// the preferred one; the post-activation check reports that as degraded rather
// than the table hiding it.
func (t *windowsTable) moveDefault(rs []winnet.Route, a winnet.Adapter, nextHop netip.Addr, dropCurrent func(winnet.Route) bool) error {
	defaults := defaultRoutesOf(rs)
	want := routeKey{index: a.Index, dest: defaultV4, nextHop: nextHop}
	if !nextHop.IsValid() || nextHop.IsUnspecified() {
		want.nextHop = netip.Addr{}
	}
	if len(defaults) > 0 && keyOf(defaults[0]) == want {
		return nil
	}

	var cur *winnet.Route
	if len(defaults) > 0 {
		cur = &defaults[0]
	}
	metric := uint32(hostMetric)
	if cur != nil {
		metric = metricAhead(cur.Effective(), a)
	}

	var existing *winnet.Route
	for i := range defaults {
		if keyOf(defaults[i]) == want {
			existing = &defaults[i]
		}
	}
	switch {
	case existing != nil:
		if err := t.ops.setMetric(*existing, metric); err != nil {
			return fmt.Errorf("re-rank default route on %s: %w", a.Alias, err)
		}
	default:
		err := t.ops.create(newWinRoute{Adapter: a, Dest: defaultV4, NextHop: nextHop, Metric: metric})
		if err != nil {
			return fmt.Errorf("add default route on %s: %w", a.Alias, err)
		}
		t.owned[want] = true
	}

	if cur != nil && dropCurrent(*cur) {
		if err := t.ops.remove(*cur); err != nil && !errors.Is(err, errWinRouteGone) {
			return fmt.Errorf("remove default route on %s: %w", cur.Adapter.Alias, err)
		}
		delete(t.owned, keyOf(*cur))
		if existing != nil {
			t.restoreMetric(defaults, *existing, cur)
		}
	}
	return nil
}

// restoreMetric gives a default route that was re-ranked ahead of the displaced
// default its own metric back, once that default is gone: the LAN's preference
// between Ethernet and Wi-Fi is then what it was, not whatever the swap left. It
// is left ranked ahead when another default would otherwise outrank it.
func (t *windowsTable) restoreMetric(defaults []winnet.Route, route winnet.Route, gone *winnet.Route) {
	restored := route.Adapter.Metric + route.Metric
	for _, d := range defaults {
		if keyOf(d) == keyOf(route) || keyOf(d) == keyOf(*gone) {
			continue
		}
		if d.Effective() <= restored {
			return
		}
	}
	// Failing to put the metric back leaves a working, merely preferred, default.
	_ = t.ops.setMetric(route, route.Metric)
}

func always(winnet.Route) bool { return true }

// replaceDefault points the preferred default route at gateway. addIfMissing
// adds a default when there is none to change.
func (t *windowsTable) replaceDefault(ctx context.Context, gateway netip.Addr, addIfMissing bool) error {
	unlock, err := t.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	rs, err := t.ops.routes(4)
	if err != nil {
		return err
	}
	if !addIfMissing && len(defaultRoutesOf(rs)) == 0 {
		return fmt.Errorf("no default route to change")
	}
	a, ok := adapterForGateway(rs, gateway.Unmap())
	if !ok {
		return fmt.Errorf("%s: %w", gateway, errGatewayNotOnLink)
	}
	return t.moveDefault(rs, a, gateway.Unmap(), always)
}

// ReplaceDefault points the existing default route at gateway without ever
// adding one, returning the failure as is.
func (t *windowsTable) ReplaceDefault(ctx context.Context, gateway netip.Addr) error {
	return t.replaceDefault(ctx, gateway, false)
}

// ChangeDefaultStrict is ReplaceDefault with the failure named.
func (t *windowsTable) ChangeDefaultStrict(ctx context.Context, gateway netip.Addr) error {
	if err := t.replaceDefault(ctx, gateway, false); err != nil {
		return fmt.Errorf("change default route to %s: %w", gateway, err)
	}
	return nil
}

// ChangeDefault points the default route at gateway, adding one only when
// there is none to change.
func (t *windowsTable) ChangeDefault(ctx context.Context, gateway netip.Addr) error {
	if err := t.replaceDefault(ctx, gateway, true); err != nil {
		return fmt.Errorf("set default route to %s: %w", gateway, err)
	}
	return nil
}

// ChangeDefaultToInterface points the default route straight at a tunnel
// interface, restoring a VPN client's own default route. The default it
// displaces is deleted only when RouteWise created it.
func (t *windowsTable) ChangeDefaultToInterface(ctx context.Context, iface string) error {
	unlock, err := t.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	adapters, err := t.ops.adapters()
	if err != nil {
		return fmt.Errorf("restore default route: %w", err)
	}
	a, ok := adapterByAlias(adapters, iface)
	if !ok {
		return fmt.Errorf("restore default route: interface %s: not found", iface)
	}
	rs, err := t.ops.routes(4)
	if err != nil {
		return fmt.Errorf("set default route to interface %s: %w", iface, err)
	}
	if len(defaultRoutesOf(rs)) == 0 {
		return fmt.Errorf("set default route to interface %s: no default route to change", iface)
	}
	err = t.moveDefault(rs, a, netip.IPv4Unspecified(), func(r winnet.Route) bool { return t.owned[keyOf(r)] })
	if err != nil {
		return fmt.Errorf("set default route to interface %s: %w", iface, err)
	}
	return nil
}
