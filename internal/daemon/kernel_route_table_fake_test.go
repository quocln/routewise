package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
)

// fakeKernel is a route.CommandRunner that models the parts of the macOS
// routing table the daemon depends on, unlike fakeRouteRunner, which only
// records commands. It enforces the kernel's rules that make overlap bugs
// visible:
//
//   - one route per destination: `route add -host X` for an address already in
//     the table fails with `File exists`;
//   - `route delete` of an address that is not in the table fails with
//     `not in table`;
//   - `route change default` rewrites the one default route, and fails with
//     `Network is unreachable` for a gateway that no connected network reaches;
//   - `route get` and `netstat -rn` read the same table back.
//
// A test therefore sees the real outcome of a sequence of route commands (who
// holds an address, where the default points) instead of inferring it from the
// list of commands that were run.
type fakeKernel struct {
	mu sync.Mutex

	hosts map[string]kernelRoute // destination -> route
	// rejects are the IPv6 host routes added with -reject, by address.
	rejects map[string]bool
	nets    []kernelNetRoute // /1 halves and other network routes

	// The global default route. defaultGW is empty for a route that points
	// straight at an interface, as a NetworkExtension VPN's does.
	defaultGW, defaultIface string
	// scopedLAN is the interface-scoped LAN default macOS keeps while a tunnel
	// holds the global one.
	scopedGW, scopedIface string
	// reachable lists the gateways a connected network reaches. A `change
	// default` to any other gateway fails as unreachable. Empty means every
	// gateway is reachable.
	reachable map[string]bool
	// gatewayIface maps a tunnel gateway to the interface a route through it
	// leaves on. Any other gateway leaves on scopedIface.
	gatewayIface map[string]string

	calls []string
	// failures arm one-shot errors for commands containing the substring.
	failures []kernelFailure
	// beforeRun, when set, is called without the table locked just before a
	// command runs, so a test can pause or observe a command in flight.
	beforeRun func(call string)
}

type kernelRoute struct{ gateway, iface string }

type kernelNetRoute struct{ dest, gateway, iface string }

type kernelFailure struct {
	substr string
	err    error
	// always keeps the failure armed for every matching command.
	always bool
}

// newFakeKernel starts with the default route on the LAN, as it is with no VPN
// connected.
func newFakeKernel() *fakeKernel {
	return &fakeKernel{
		hosts:        make(map[string]kernelRoute),
		rejects:      make(map[string]bool),
		defaultGW:    "192.168.7.1",
		defaultIface: "en0",
		scopedGW:     "192.168.7.1",
		scopedIface:  "en0",
		gatewayIface: map[string]string{wgGW: wgIface, awsGW: awsIface},
	}
}

func (k *fakeKernel) Run(_ context.Context, tool string, args ...string) (string, error) {
	call := tool + " " + strings.Join(args, " ")
	k.mu.Lock()
	hook := k.beforeRun
	k.mu.Unlock()
	if hook != nil {
		hook(call)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, call)
	for i, f := range k.failures {
		if strings.Contains(call, f.substr) {
			if !f.always {
				k.failures = slices.Delete(k.failures, i, i+1)
			}
			return "", f.err
		}
	}

	switch tool {
	case "netstat":
		return k.renderTable(), nil
	case "route":
		if len(args) < 2 || args[0] != "-n" {
			return "", fmt.Errorf("fakeKernel: unexpected route args %v", args)
		}
		switch args[1] {
		case "get":
			return k.get(args[2:])
		case "add":
			return "", k.add(args[2:])
		case "delete":
			return "", k.del(args[2:])
		case "change":
			return "", k.change(args[2:])
		}
	}
	return "", fmt.Errorf("fakeKernel: unsupported command %q", call)
}

func (k *fakeKernel) ifaceVia(gateway string) string {
	if iface, ok := k.gatewayIface[gateway]; ok {
		return iface
	}
	return k.scopedIface
}

func (k *fakeKernel) get(rest []string) (string, error) {
	if len(rest) != 1 {
		return "", fmt.Errorf("fakeKernel: bad get args %v", rest)
	}
	if rest[0] == "default" {
		if k.defaultGW == "" && k.defaultIface == "" {
			return "", errors.New("route: writing to routing socket: not in table")
		}
		out := "   route to: default\ndestination: default\n"
		if k.defaultGW != "" {
			out += fmt.Sprintf("    gateway: %s\n", k.defaultGW)
		}
		return out + fmt.Sprintf("  interface: %s\n", k.defaultIface), nil
	}
	if r, ok := k.hosts[rest[0]]; ok {
		out := fmt.Sprintf("   route to: %s\n", rest[0])
		if r.gateway != "" {
			out += fmt.Sprintf("    gateway: %s\n", r.gateway)
		}
		return out + fmt.Sprintf("  interface: %s\n", r.iface), nil
	}
	// No host route: the longest network route that contains the address wins,
	// as in the kernel. Only destinations written in full ("10.20.0.0/16") take
	// part; the abbreviated /1 halves ("0/1") never match here.
	if ip, err := netip.ParseAddr(rest[0]); err == nil {
		var best *kernelNetRoute
		bestBits := -1
		for i, n := range k.nets {
			p, err := netip.ParsePrefix(n.dest)
			if err == nil && p.Contains(ip) && p.Bits() > bestBits {
				best, bestBits = &k.nets[i], p.Bits()
			}
		}
		if best != nil {
			out := fmt.Sprintf("   route to: %s\n", rest[0])
			if best.gateway != "" {
				out += fmt.Sprintf("    gateway: %s\n", best.gateway)
			}
			return out + fmt.Sprintf("  interface: %s\n", best.iface), nil
		}
	}
	out := fmt.Sprintf("   route to: %s\n", rest[0])
	if k.defaultGW != "" {
		out += fmt.Sprintf("    gateway: %s\n", k.defaultGW)
	}
	return out + fmt.Sprintf("  interface: %s\n", k.defaultIface), nil
}

// addReject handles `-inet6 -host <addr> ::1 -reject`; rest follows -inet6.
func (k *fakeKernel) addReject(rest []string) error {
	if len(rest) != 4 || (rest[0] != "-host" && rest[0] != "-net") || rest[2] != "::1" || rest[3] != "-reject" {
		return fmt.Errorf("fakeKernel: bad inet6 add args %v", rest)
	}
	if k.rejects[rest[1]] {
		return errors.New("route: writing to routing socket: File exists")
	}
	k.rejects[rest[1]] = true
	return nil
}

func (k *fakeKernel) delReject(rest []string) error {
	if len(rest) != 2 || (rest[0] != "-host" && rest[0] != "-net") {
		return fmt.Errorf("fakeKernel: bad inet6 delete args %v", rest)
	}
	if !k.rejects[rest[1]] {
		return errors.New("route: writing to routing socket: not in table")
	}
	delete(k.rejects, rest[1])
	return nil
}

func (k *fakeKernel) add(rest []string) error {
	if len(rest) > 0 && rest[0] == "-inet6" {
		return k.addReject(rest[1:])
	}
	if len(rest) >= 2 && rest[0] == "default" {
		if rest[1] == "-interface" && len(rest) == 3 {
			k.defaultGW, k.defaultIface = "", rest[2]
			return nil
		}
		k.defaultGW, k.defaultIface = rest[1], k.ifaceVia(rest[1])
		return nil
	}
	if len(rest) < 3 {
		return fmt.Errorf("fakeKernel: bad add args %v", rest)
	}
	kind, dest := rest[0], rest[1]
	var gateway, iface string
	if rest[2] == "-interface" && len(rest) == 4 {
		iface = rest[3]
	} else {
		gateway, iface = rest[2], k.ifaceVia(rest[2])
	}
	switch kind {
	case "-host":
		if _, exists := k.hosts[dest]; exists {
			return errors.New("route: writing to routing socket: File exists")
		}
		k.hosts[dest] = kernelRoute{gateway: gateway, iface: iface}
	case "-net":
		for _, n := range k.nets {
			if n.dest == dest {
				return errors.New("route: writing to routing socket: File exists")
			}
		}
		k.nets = append(k.nets, kernelNetRoute{dest: dest, gateway: gateway, iface: iface})
	default:
		return fmt.Errorf("fakeKernel: bad add kind %q", kind)
	}
	return nil
}

func (k *fakeKernel) del(rest []string) error {
	if len(rest) > 0 && rest[0] == "-inet6" {
		return k.delReject(rest[1:])
	}
	if len(rest) == 1 && rest[0] == "default" {
		k.defaultGW, k.defaultIface = "", ""
		return nil
	}
	if len(rest) != 2 {
		return fmt.Errorf("fakeKernel: bad delete args %v", rest)
	}
	switch rest[0] {
	case "-host":
		if _, exists := k.hosts[rest[1]]; !exists {
			return errors.New("route: writing to routing socket: not in table")
		}
		delete(k.hosts, rest[1])
		return nil
	case "-net":
		for i, n := range k.nets {
			if n.dest == rest[1] {
				k.nets = slices.Delete(k.nets, i, i+1)
				return nil
			}
		}
		return errors.New("route: writing to routing socket: not in table")
	}
	return fmt.Errorf("fakeKernel: bad delete kind %q", rest[0])
}

func (k *fakeKernel) change(rest []string) error {
	if len(rest) < 2 || rest[0] != "default" {
		return fmt.Errorf("fakeKernel: unsupported change args %v", rest)
	}
	if k.defaultGW == "" && k.defaultIface == "" {
		return errors.New("route: writing to routing socket: not in table")
	}
	if rest[1] == "-interface" && len(rest) == 3 {
		k.defaultGW, k.defaultIface = "", rest[2]
		return nil
	}
	if len(k.reachable) > 0 && !k.reachable[rest[1]] {
		return errors.New("route: writing to routing socket: Network is unreachable")
	}
	k.defaultGW, k.defaultIface = rest[1], k.ifaceVia(rest[1])
	return nil
}

// renderTable prints the table the way `netstat -rn -f inet` does.
func (k *fakeKernel) renderTable() string {
	var b strings.Builder
	b.WriteString("Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n")
	if k.defaultGW != "" || k.defaultIface != "" {
		gw := k.defaultGW
		if gw == "" {
			gw = "link#" + k.defaultIface
		}
		fmt.Fprintf(&b, "default            %s       UGScg           %s\n", gw, k.defaultIface)
	}
	if k.scopedGW != "" && k.defaultIface != k.scopedIface {
		fmt.Fprintf(&b, "default            %s       UGScIg          %s\n", k.scopedGW, k.scopedIface)
	}
	for _, n := range k.nets {
		gw := n.gateway
		if gw == "" {
			gw = n.iface
		}
		fmt.Fprintf(&b, "%-18s %-18s UGSc            %s\n", n.dest, gw, n.iface)
	}
	dests := make([]string, 0, len(k.hosts))
	for dest := range k.hosts {
		dests = append(dests, dest)
	}
	sort.Strings(dests)
	for _, dest := range dests {
		r := k.hosts[dest]
		gw := r.gateway
		if gw == "" {
			gw = r.iface
		}
		fmt.Fprintf(&b, "%-18s %-18s UGHS            %s\n", dest, gw, r.iface)
	}
	return b.String()
}

// --- test helpers ---

// failNext arms a one-shot error for the next command containing substr.
func (k *fakeKernel) failNext(substr string, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.failures = append(k.failures, kernelFailure{substr: substr, err: err})
}

// failAlways makes every command containing substr fail until clearFailures.
func (k *fakeKernel) failAlways(substr string, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.failures = append(k.failures, kernelFailure{substr: substr, err: err, always: true})
}

func (k *fakeKernel) clearFailures() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.failures = nil
}

// hostRoute reports the interface the table routes an address through.
func (k *fakeKernel) hostRoute(ip string) (iface string, ok bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	r, ok := k.hosts[ip]
	return r.iface, ok
}

// putHost installs a route as something outside RouteWise would.
func (k *fakeKernel) putHost(ip, gateway, iface string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.hosts[ip] = kernelRoute{gateway: gateway, iface: iface}
}

func (k *fakeKernel) setDefault(gateway, iface string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.defaultGW, k.defaultIface = gateway, iface
}

func (k *fakeKernel) defaultRoute() (gateway, iface string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.defaultGW, k.defaultIface
}

// putNet installs a network route, such as a VPN client's /1 half.
func (k *fakeKernel) putNet(dest, gateway, iface string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.nets = append(k.nets, kernelNetRoute{dest: dest, gateway: gateway, iface: iface})
}

func (k *fakeKernel) netRoutes() []kernelNetRoute {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.nets)
}

// hasNet reports whether the table holds a network route to dest through iface.
func (k *fakeKernel) hasNet(dest, iface string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.ContainsFunc(k.nets, func(n kernelNetRoute) bool { return n.dest == dest && n.iface == iface })
}

// hostCount is how many host routes the table holds.
func (k *fakeKernel) hostCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.hosts)
}

// log returns every command run so far, in order.
func (k *fakeKernel) log() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.calls)
}

// has reports whether any command so far contained substr.
func (k *fakeKernel) has(substr string) bool {
	return slices.ContainsFunc(k.log(), func(c string) bool { return strings.Contains(c, substr) })
}

// indexOf returns the position of the first command containing substr at or
// after from, or -1.
func indexOf(calls []string, substr string, from int) int {
	for i := from; i < len(calls); i++ {
		if strings.Contains(calls[i], substr) {
			return i
		}
	}
	return -1
}

// hasReject reports whether an IPv6 reject host route exists for addr.
func (k *fakeKernel) hasReject(addr string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.rejects[addr]
}

// rejectCount is the number of IPv6 reject host routes.
func (k *fakeKernel) rejectCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.rejects)
}

// putReject places an IPv6 reject host route, as a crashed helper leaves it.
func (k *fakeKernel) putReject(addr string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rejects[addr] = true
}
