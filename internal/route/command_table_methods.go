package route

import (
	"context"
	"net/netip"
)

// commandTable is the Table that drives the BSD route and netstat tools
// through a CommandRunner. It holds no state, so tests share one fake runner
// between managers.
type commandTable struct {
	runner CommandRunner
}

func newCommandTable(r CommandRunner) *commandTable { return &commandTable{runner: r} }

func (t *commandTable) Snapshot(ctx context.Context) ([]RouteEntry, error) {
	return snapshotRoutes(ctx, t.runner)
}

func (t *commandTable) Default(ctx context.Context) (netip.Addr, string, error) {
	return getDefaultRoute(ctx, t.runner)
}

func (t *commandTable) DefaultGateway(ctx context.Context) (netip.Addr, error) {
	return getDefaultGateway(ctx, t.runner)
}

func (t *commandTable) LocalGateway(ctx context.Context, prefer string) (netip.Addr, string, error) {
	return getLocalGateway(ctx, t.runner, prefer)
}

func (t *commandTable) Lookup(ctx context.Context, dest netip.Addr) (string, netip.Addr, error) {
	return lookupRoute(ctx, t.runner, dest)
}

func (t *commandTable) AddHost(ctx context.Context, dest, gateway netip.Addr, iface string) error {
	return addRoute(ctx, t.runner, dest, gateway, iface)
}

func (t *commandTable) AddPrefix(ctx context.Context, prefix netip.Prefix, gateway netip.Addr, iface string) error {
	return addPrefixRoute(ctx, t.runner, prefix, gateway, iface)
}

func (t *commandTable) AddNet(ctx context.Context, destRaw, gatewayRaw, iface string) error {
	return addNetRoute(ctx, t.runner, destRaw, gatewayRaw, iface)
}

func (t *commandTable) DeleteHost(ctx context.Context, dest netip.Addr) error {
	return deleteRoute(ctx, t.runner, dest)
}

func (t *commandTable) DeleteNet(ctx context.Context, destRaw, _, _ string) error {
	return deleteNetRoute(ctx, t.runner, destRaw)
}

func (t *commandTable) DropClonedLinkLayer(ctx context.Context, dest netip.Addr) {
	dropClonedLinkLayerRoute(ctx, t.runner, dest)
}

func (t *commandTable) ChangeDefault(ctx context.Context, gateway netip.Addr) error {
	return changeDefaultRoute(ctx, t.runner, gateway)
}

func (t *commandTable) ChangeDefaultStrict(ctx context.Context, gateway netip.Addr) error {
	return changeDefaultRouteStrict(ctx, t.runner, gateway)
}

func (t *commandTable) ReplaceDefault(ctx context.Context, gateway netip.Addr) error {
	_, err := t.runner.Run(ctx, toolRoute, "-n", "change", "default", gateway.String())
	return err
}

func (t *commandTable) ChangeDefaultToInterface(ctx context.Context, iface string) error {
	return changeDefaultRouteToInterface(ctx, t.runner, iface)
}

func (t *commandTable) AddIPv6Reject(ctx context.Context, addr netip.Addr) error {
	return AddIPv6Reject(ctx, t.runner, addr)
}

func (t *commandTable) DeleteIPv6Reject(ctx context.Context, addr netip.Addr) error {
	return DeleteIPv6Reject(ctx, t.runner, addr)
}

func (t *commandTable) AddIPv6RejectAll(ctx context.Context) error {
	return addIPv6RejectAll(ctx, t.runner)
}

func (t *commandTable) DeleteIPv6RejectAll(ctx context.Context) error {
	return deleteIPv6RejectAll(ctx, t.runner)
}

func (t *commandTable) IsUnreachable(err error) bool { return isUnreachableErr(err) }
