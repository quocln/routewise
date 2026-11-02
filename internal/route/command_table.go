package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// commandRunner executes a fixed-argv privileged command and returns its
// captured stdout. It is the only path by which this package reaches an
// external process, so every caller can be tested against a fake instead of
// shelling out.
type CommandRunner interface {
	Run(ctx context.Context, tool string, args ...string) (string, error)
}

// commandRunner is the name the rest of this package uses for CommandRunner.
type commandRunner = CommandRunner

const (
	toolRoute   = "route"
	toolNetstat = "netstat"
)

// addRoute adds a host route (/32) via the specified gateway or interface.
// If gateway is valid, it uses that. Otherwise, if iface is valid, it uses -interface.
func addRoute(ctx context.Context, runner commandRunner, dest netip.Addr, gateway netip.Addr, iface string) error {
	var args []string
	if gateway.IsValid() {
		args = []string{"-n", "add", "-host", dest.String(), gateway.String()}
	} else if iface != "" {
		if err := ValidateInterfaceName(iface); err != nil {
			return fmt.Errorf("addRoute: %w", err)
		}
		args = []string{"-n", "add", "-host", dest.String(), "-interface", iface}
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	_, err := runner.Run(ctx, toolRoute, args...)
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "File exists") {
		return err
	}
	return verifyExistingHostRoute(ctx, runner, dest, gateway, iface)
}

// dropClonedLinkLayerRoute deletes a link-layer host entry the kernel cloned
// for dest on a LAN interface (flags L and W, as ARP leaves them). Such an
// entry holds no state RouteWise needs and is recreated on demand; anything
// else for dest is left alone, and errors are ignored because the add that
// follows reports any route that is still in the way.
func dropClonedLinkLayerRoute(ctx context.Context, runner commandRunner, dest netip.Addr) {
	entries, err := snapshotRoutes(ctx, runner)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Destination != dest.String() || isTunnelInterface(e.Interface) {
			continue
		}
		if strings.Contains(e.Flags, "L") && strings.Contains(e.Flags, "W") {
			_, _ = runner.Run(ctx, toolRoute, "-n", "delete", "-host", dest.String())
			return
		}
	}
}

// verifyExistingHostRoute decides whether a destination the kernel says it
// already routes leads through the tunnel being added for. It does only when
// the existing route's interface (or, for a tunnel with no interface name, its
// gateway) is ours: a leftover of this tunnel from an earlier process is
// adopted, but a route through another tunnel or the LAN is a conflict, never
// success, because the kernel holds one route per destination and whoever
// removes theirs would remove the one in use.
func verifyExistingHostRoute(ctx context.Context, runner commandRunner, dest, gateway netip.Addr, iface string) error {
	gotIface, gotGW, err := lookupRoute(ctx, runner, dest)
	if err != nil {
		return fmt.Errorf("%s already has a route that could not be verified (%v): %w", dest, err, ErrRouteOwnedElsewhere)
	}
	switch {
	case iface != "" && gotIface == iface:
		return nil
	case iface == "" && gateway.IsValid() && gotGW == gateway:
		return nil
	}
	return fmt.Errorf("%s is already routed through %s, not this tunnel: %w", dest, gotIface, ErrRouteOwnedElsewhere)
}

// addPrefixRoute adds a network route for prefix via the specified gateway, or
// through iface when the tunnel has no gateway address. A destination the
// kernel already routes is adopted only when it leads through this tunnel (see
// verifyExistingPrefixRoute).
func addPrefixRoute(ctx context.Context, runner commandRunner, prefix netip.Prefix, gateway netip.Addr, iface string) error {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return fmt.Errorf("addPrefixRoute: %s is not an IPv4 prefix", prefix)
	}
	dest := prefix.Masked().String()
	var args []string
	switch {
	case gateway.IsValid():
		args = []string{"-n", "add", "-net", dest, gateway.String()}
	case iface != "":
		if err := ValidateInterfaceName(iface); err != nil {
			return fmt.Errorf("addPrefixRoute: %w", err)
		}
		args = []string{"-n", "add", "-net", dest, "-interface", iface}
	default:
		return fmt.Errorf("either gateway or interface must be specified")
	}

	_, err := runner.Run(ctx, toolRoute, args...)
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "File exists") {
		return err
	}
	return verifyExistingPrefixRoute(ctx, runner, prefix.Masked(), gateway, iface)
}

// verifyExistingPrefixRoute decides whether a network route the kernel says it
// already holds leads through the tunnel being added for. Like
// verifyExistingHostRoute it adopts only a route through this tunnel's
// interface (or, for a tunnel with no interface name, its gateway); a route
// through another tunnel or the LAN is a conflict. The table is read with
// netstat, because `route get` answers with the longest match, not the route
// for exactly this destination and mask.
func verifyExistingPrefixRoute(ctx context.Context, runner commandRunner, prefix netip.Prefix, gateway netip.Addr, iface string) error {
	entries, err := snapshotRoutes(ctx, runner)
	if err != nil {
		return fmt.Errorf("%s already has a route that could not be verified (%v): %w", prefix, err, ErrRouteOwnedElsewhere)
	}
	var otherIface string
	for _, e := range entries {
		got, ok := parseNetstatDest(e.Destination)
		if !ok || got != prefix {
			continue
		}
		switch {
		case iface != "" && e.Interface == iface:
			return nil
		case iface == "" && gateway.IsValid() && sameGateway(e.Gateway, gateway.String()):
			return nil
		}
		otherIface = e.Interface
	}
	if otherIface == "" {
		return fmt.Errorf("%s already has a route that could not be found in the table: %w", prefix, ErrRouteOwnedElsewhere)
	}
	return fmt.Errorf("%s is already routed through %s, not this tunnel: %w", prefix, otherIface, ErrRouteOwnedElsewhere)
}

// addNetRoute adds a network route (used to restore the AWS /1 split-tunnel
// routes on compensation). destRaw is used exactly as read from the kernel
// table (e.g. "0/1", "128.0/1") so the delete/restore pair round-trips
// through the same notation the kernel itself uses.
func addNetRoute(ctx context.Context, runner commandRunner, destRaw, gatewayRaw, iface string) error {
	var args []string
	switch {
	case gatewayRaw != "":
		args = []string{"-n", "add", "-net", destRaw, gatewayRaw}
	case iface != "":
		if err := ValidateInterfaceName(iface); err != nil {
			return fmt.Errorf("addNetRoute: %w", err)
		}
		args = []string{"-n", "add", "-net", destRaw, "-interface", iface}
	default:
		return fmt.Errorf("either gateway or interface must be specified")
	}

	_, err := runner.Run(ctx, toolRoute, args...)
	if err != nil {
		if strings.Contains(err.Error(), "File exists") {
			return nil
		}
		return err
	}
	return nil
}

// deleteRoute removes a host route.
func deleteRoute(ctx context.Context, runner commandRunner, dest netip.Addr) error {
	_, err := runner.Run(ctx, toolRoute, "-n", "delete", "-host", dest.String())
	if err != nil {
		if strings.Contains(err.Error(), "not in table") {
			return nil // Already removed, not an error
		}
		return err
	}
	return nil
}

// deleteNetRoute removes a network route using the destination exactly as
// the kernel table printed it, so no destination-notation guessing is needed.
func deleteNetRoute(ctx context.Context, runner commandRunner, destRaw string) error {
	_, err := runner.Run(ctx, toolRoute, "-n", "delete", "-net", destRaw)
	if err != nil {
		if strings.Contains(err.Error(), "not in table") {
			return nil // Already removed, not an error
		}
		return err
	}
	return nil
}

// changeDefaultRoute changes the default route gateway.
func changeDefaultRoute(ctx context.Context, runner commandRunner, gateway netip.Addr) error {
	_, changeErr := runner.Run(ctx, toolRoute, "-n", "change", "default", gateway.String())
	if changeErr == nil {
		return nil
	}
	// Only add when there is no default to change. The default is never
	// deleted first: if the add then failed, the Mac would be left with no
	// default route at all.
	if _, addErr := runner.Run(ctx, toolRoute, "-n", "add", "default", gateway.String()); addErr != nil {
		return fmt.Errorf("set default route to %s: %w", gateway, changeErr)
	}
	return nil
}

// changeDefaultRouteStrict points the default route at gateway with
// `route change` only. Unlike changeDefaultRoute it never deletes the default
// route, so a failure leaves the existing default in place.
func changeDefaultRouteStrict(ctx context.Context, runner commandRunner, gateway netip.Addr) error {
	if _, err := runner.Run(ctx, toolRoute, "-n", "change", "default", gateway.String()); err != nil {
		return fmt.Errorf("change default route to %s: %w", gateway, err)
	}
	return nil
}

// isUnreachableErr reports whether a route command failed because the target
// gateway is not on any connected network.
func isUnreachableErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unreachable")
}

// getDefaultGateway returns the gateway of the current global default route.
func getDefaultGateway(ctx context.Context, runner commandRunner) (netip.Addr, error) {
	gw, _, err := getDefaultRoute(ctx, runner)
	if err != nil {
		return netip.Addr{}, err
	}
	if !gw.IsValid() {
		return netip.Addr{}, fmt.Errorf("default route has no gateway IP")
	}
	return gw, nil
}

// getDefaultRoute returns the gateway and interface of the current global
// default route. The gateway is invalid when the route points straight at an
// interface, as a NetworkExtension VPN's default route does.
func getDefaultRoute(ctx context.Context, runner commandRunner) (netip.Addr, string, error) {
	output, err := runner.Run(ctx, toolRoute, "-n", "get", "default")
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("get default route: %w", err)
	}

	var gw netip.Addr
	var iface string
	found := false
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "gateway":
			found = true
			if ip, err := netip.ParseAddr(value); err == nil {
				gw = ip
			}
		case "interface":
			found = true
			iface = value
		}
	}
	if !found {
		return netip.Addr{}, "", fmt.Errorf("default route not found in route output")
	}
	return gw, iface, nil
}

// lookupRoute returns the interface and gateway `route -n get` reports for
// dest. The gateway is invalid for a route that points at an interface.
func lookupRoute(ctx context.Context, runner commandRunner, dest netip.Addr) (string, netip.Addr, error) {
	if !dest.IsValid() {
		return "", netip.Addr{}, fmt.Errorf("lookup route: invalid address")
	}
	output, err := runner.Run(ctx, toolRoute, "-n", "get", dest.String())
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("lookup route for %s: %w", dest, err)
	}
	var iface string
	var gw netip.Addr
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "interface":
			iface = value
		case "gateway":
			if ip, perr := netip.ParseAddr(value); perr == nil {
				gw = ip
			}
		}
	}
	if iface == "" {
		return "", netip.Addr{}, fmt.Errorf("lookup route for %s: no interface in route output", dest)
	}
	return iface, gw, nil
}

// getLocalGateway returns the LAN gateway and its interface even while a VPN
// owns the global default route. A NetworkExtension VPN (the WireGuard app,
// for example) moves the global default onto its tunnel and leaves the LAN
// default only as an interface-scoped route, so that scoped route is read from
// the table instead. When several LAN interfaces have one, the scoped default
// on prefer (the interface that last held the global default) wins.
func getLocalGateway(ctx context.Context, runner commandRunner, prefer string) (netip.Addr, string, error) {
	gw, iface, err := getDefaultRoute(ctx, runner)
	if err == nil && gw.IsValid() && !isTunnelInterface(iface) {
		return gw, iface, nil
	}

	entries, snapErr := snapshotRoutes(ctx, runner)
	if snapErr != nil {
		return netip.Addr{}, "", errors.Join(err, snapErr)
	}
	var firstGW netip.Addr
	var firstIface string
	for _, e := range entries {
		if e.Destination != "default" || isTunnelInterface(e.Interface) {
			continue
		}
		ip, perr := netip.ParseAddr(e.Gateway)
		if perr != nil || !ip.Is4() {
			continue
		}
		if prefer != "" && e.Interface == prefer {
			return ip, e.Interface, nil
		}
		if !firstGW.IsValid() {
			firstGW, firstIface = ip, e.Interface
		}
	}
	if firstGW.IsValid() {
		return firstGW, firstIface, nil
	}
	if err != nil {
		return netip.Addr{}, "", err
	}
	return netip.Addr{}, "", fmt.Errorf("no LAN default route found")
}

// changeDefaultRouteToInterface points the default route at a tunnel
// interface, restoring a NetworkExtension VPN's own default route. It only
// changes the route; on failure the existing default stays.
func changeDefaultRouteToInterface(ctx context.Context, runner commandRunner, iface string) error {
	if err := ValidateInterfaceName(iface); err != nil {
		return fmt.Errorf("restore default route: %w", err)
	}
	if _, err := runner.Run(ctx, toolRoute, "-n", "change", "default", "-interface", iface); err != nil {
		return fmt.Errorf("set default route to interface %s: %w", iface, err)
	}
	return nil
}

// routeTableReader is implemented by a runner that can read the routing table
// without running netstat (the production runner on macOS, in process).
type routeTableReader interface {
	ReadRoutes(ctx context.Context) ([]RouteEntry, error)
}

// snapshotRoutes reads the current IPv4 routing table. A runner that can read
// it in process does so, which has no output size limit and forks nothing;
// otherwise, or if that read fails, netstat's output is parsed.
func snapshotRoutes(ctx context.Context, runner commandRunner) ([]RouteEntry, error) {
	if reader, ok := runner.(routeTableReader); ok {
		if entries, err := reader.ReadRoutes(ctx); err == nil {
			return entries, nil
		}
	}
	output, err := runner.Run(ctx, toolNetstat, "-rn", "-f", "inet")
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}
	return parseRouteTable(output), nil
}

// parseRouteTable parses `netstat -rn -f inet` output into RouteEntry
// values. It is a pure function so tests can drive it from fixture text
// without ever running netstat.
func parseRouteTable(output string) []RouteEntry {
	var routes []RouteEntry
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		switch fields[0] {
		case "Destination", "Routing", "Internet:", "Internet6:":
			continue
		}

		routes = append(routes, RouteEntry{
			Destination: fields[0],
			Gateway:     fields[1],
			Flags:       fields[2],
			Interface:   fields[3],
		})
	}
	return routes
}
