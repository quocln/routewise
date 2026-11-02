//go:build darwin

package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	xroute "golang.org/x/net/route"
)

// routeSocketRunner carries out the common route(8) commands in process, on a routing
// socket, instead of starting /sbin/route. A process start costs milliseconds, and
// these commands run under the lock DNS answers wait for, so a wildcard lookup's first
// answer waits on them.
//
// Being a CommandRunner, it keeps the command table's logic and its error handling:
// a kernel error that logic knows comes back spelled the way route(8) spells it. Only
// the host and network routes and lookups are handled here. Whatever else is asked,
// and any kernel error the logic does not know, goes to route(8) itself, so the worst
// outcome of a surprise is the old behavior. Changing the default route always does:
// nothing else can cut the machine off so thoroughly, and it is rare.
type routeSocketRunner struct {
	*execRunner
	// write sends a change to the kernel, and get asks it a question; both are fields
	// so tests can stand in for the kernel.
	write func(message []byte) error
	get   func(message []byte, seq int) (*xroute.RouteMessage, error)
	// warned keeps a surprise from being logged at every route change.
	warned atomic.Bool
	// fallbackHook, when set, is told what went to route(8). Tests use it.
	fallbackHook func(args []string)
}

// routeSocketReplyTimeout bounds the wait for an answer to a lookup.
const routeSocketReplyTimeout = 2 * time.Second

// routeSeq numbers requests, so a lookup can pick its own answer out of the socket.
var routeSeq atomic.Int64

func newRouteSocketRunner(fallback *execRunner) *routeSocketRunner {
	return &routeSocketRunner{execRunner: fallback, write: writeRouteSocket, get: askRouteSocket}
}

// Run does what route(8) would for the commands it knows, and hands the rest over.
func (r *routeSocketRunner) Run(ctx context.Context, tool string, args ...string) (string, error) {
	if tool != toolRoute {
		return r.execRunner.Run(ctx, tool, args...)
	}
	request, ok := parseRouteCommand(args)
	if !ok {
		return r.toRouteTool(ctx, args)
	}
	message := xroute.RouteMessage{
		Version: syscall.RTM_VERSION,
		Type:    request.kind,
		Flags:   request.flags,
		ID:      uintptr(os.Getpid()),
		Seq:     int(routeSeq.Add(1)),
		Addrs:   request.addrs,
	}
	wire, err := message.Marshal()
	if err != nil {
		return r.fallBack(ctx, args, err)
	}
	if request.kind == syscall.RTM_GET {
		reply, err := r.get(wire, message.Seq)
		if err != nil {
			if spelled, known := spellRouteError(err); known {
				return "", spelled
			}
			return r.fallBack(ctx, args, err)
		}
		return describeRouteReply(args[len(args)-1], reply), nil
	}
	if err := r.write(wire); err != nil {
		if spelled, known := spellRouteError(err); known {
			return "", spelled
		}
		return r.fallBack(ctx, args, err)
	}
	return "", nil
}

func (r *routeSocketRunner) fallBack(ctx context.Context, args []string, cause error) (string, error) {
	if r.warned.CompareAndSwap(false, true) {
		slog.Warn("routing socket refused a request; using route(8) for it", "command", strings.Join(args, " "), "error", cause)
	}
	return r.toRouteTool(ctx, args)
}

func (r *routeSocketRunner) toRouteTool(ctx context.Context, args []string) (string, error) {
	if r.fallbackHook != nil {
		r.fallbackHook(args)
	}
	return r.execRunner.Run(ctx, toolRoute, args...)
}

// spellRouteError returns err as route(8) prints it, for the errors the command
// table acts on.
func spellRouteError(err error) (error, bool) {
	switch {
	case errors.Is(err, syscall.EEXIST):
		return errors.New("route: writing to routing socket: File exists"), true
	case errors.Is(err, syscall.ESRCH):
		return errors.New("route: writing to routing socket: not in table"), true
	case errors.Is(err, syscall.ENETUNREACH):
		return errors.New("route: writing to routing socket: Network is unreachable"), true
	}
	return nil, false
}

// routeRequest is one route(8) command as a routing message.
type routeRequest struct {
	kind  int
	flags int
	addrs []xroute.Addr
}

// The positions of a routing message's addresses.
const (
	addrDst = iota
	addrGateway
	addrNetmask
	addrGenmask
	addrIFP
	addrCount
)

// parseRouteCommand reads the route(8) arguments this runner handles. ok is false for
// anything else, which then goes to route(8).
func parseRouteCommand(args []string) (request routeRequest, ok bool) {
	if len(args) < 3 || args[0] != "-n" {
		return routeRequest{}, false
	}
	verb, rest := args[1], args[2:]
	switch verb {
	case "get":
		return parseRouteGet(rest)
	case "add", "delete":
	default:
		return routeRequest{}, false
	}
	if verb == "add" {
		request.kind = syscall.RTM_ADD
		request.flags = syscall.RTF_UP | syscall.RTF_STATIC
	} else {
		request.kind = syscall.RTM_DELETE
	}
	if rest[0] == "-inet6" {
		rest = rest[1:]
	}
	if len(rest) < 2 {
		return routeRequest{}, false
	}
	prefix, ok := parseRouteTarget(rest[0], rest[1])
	if !ok {
		return routeRequest{}, false
	}
	request.addrs = make([]xroute.Addr, addrCount)
	request.addrs[addrDst] = routeAddr(prefix.Masked().Addr())
	if rest[0] == "-host" {
		request.flags |= syscall.RTF_HOST
	} else {
		request.addrs[addrNetmask] = routeMask(prefix)
	}
	next := rest[2:]
	if verb == "delete" {
		return request, len(next) == 0
	}
	switch {
	case len(next) == 2 && next[0] == "-interface":
		iface, err := net.InterfaceByName(next[1])
		if err != nil {
			return routeRequest{}, false
		}
		request.addrs[addrGateway] = &xroute.LinkAddr{Index: iface.Index, Name: iface.Name}
	case len(next) == 1 || (len(next) == 2 && next[1] == "-reject"):
		gateway, err := netip.ParseAddr(next[0])
		if err != nil || gateway.Is4() != prefix.Addr().Is4() {
			return routeRequest{}, false
		}
		request.addrs[addrGateway] = routeAddr(gateway)
		request.flags |= syscall.RTF_GATEWAY
		if len(next) == 2 {
			request.flags |= syscall.RTF_REJECT
		}
	default:
		return routeRequest{}, false
	}
	return request, true
}

// parseRouteGet reads `route -n get <address|default>`. The interface slot asks the
// kernel to name the interface in its answer.
func parseRouteGet(rest []string) (routeRequest, bool) {
	if len(rest) != 1 {
		return routeRequest{}, false
	}
	request := routeRequest{kind: syscall.RTM_GET, flags: syscall.RTF_UP, addrs: make([]xroute.Addr, addrCount)}
	request.addrs[addrIFP] = &xroute.LinkAddr{}
	if rest[0] == "default" {
		request.addrs[addrDst] = routeAddr(netip.IPv4Unspecified())
		request.addrs[addrNetmask] = routeMask(netip.PrefixFrom(netip.IPv4Unspecified(), 0))
		return request, true
	}
	addr, err := netip.ParseAddr(rest[0])
	if err != nil || !addr.Is4() {
		return routeRequest{}, false
	}
	request.flags |= syscall.RTF_HOST
	request.addrs[addrDst] = routeAddr(addr)
	return request, true
}

// parseRouteTarget reads a `-host <address>` or `-net <prefix>` pair, in any notation
// the kernel table prints. The default route is deliberately not one of them.
func parseRouteTarget(kind, value string) (netip.Prefix, bool) {
	switch kind {
	case "-host":
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Zone() != "" {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(addr, addr.BitLen()), true
	case "-net":
		if prefix, err := netip.ParsePrefix(value); err == nil {
			return prefix, true
		}
		if value == "default" {
			return netip.Prefix{}, false
		}
		prefix, err := parseRouteDest(value)
		return prefix, err == nil
	}
	return netip.Prefix{}, false
}

func routeAddr(addr netip.Addr) xroute.Addr {
	if addr.Is4() {
		return &xroute.Inet4Addr{IP: addr.As4()}
	}
	return &xroute.Inet6Addr{IP: addr.As16()}
}

func routeMask(prefix netip.Prefix) xroute.Addr {
	mask := net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())
	if prefix.Addr().Is4() {
		return &xroute.Inet4Addr{IP: [4]byte(mask)}
	}
	return &xroute.Inet6Addr{IP: [16]byte(mask)}
}

// describeRouteReply writes a lookup's answer in the lines of `route -n get` that the
// command table reads.
func describeRouteReply(target string, reply *xroute.RouteMessage) string {
	var b strings.Builder
	fmt.Fprintf(&b, "   route to: %s\n", target)
	// As route(8) does: a route with no gateway flag leads straight out an interface,
	// whatever the gateway slot holds.
	if reply.Flags&syscall.RTF_GATEWAY != 0 && len(reply.Addrs) > addrGateway {
		if gateway, ok := reply.Addrs[addrGateway].(*xroute.Inet4Addr); ok {
			fmt.Fprintf(&b, "    gateway: %s\n", netip.AddrFrom4(gateway.IP))
		}
	}
	name := ""
	if len(reply.Addrs) > addrIFP {
		if link, ok := reply.Addrs[addrIFP].(*xroute.LinkAddr); ok {
			name = link.Name
		}
	}
	if name == "" && reply.Index > 0 {
		if iface, err := net.InterfaceByIndex(reply.Index); err == nil {
			name = iface.Name
		}
	}
	if name != "" {
		fmt.Fprintf(&b, "  interface: %s\n", name)
	}
	return b.String()
}

func openRouteSocket() (int, error) {
	return syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
}

// writeRouteSocket sends one change. The kernel reports its verdict on the write.
func writeRouteSocket(message []byte) error {
	fd, err := openRouteSocket()
	if err != nil {
		return fmt.Errorf("open routing socket: %w", err)
	}
	defer syscall.Close(fd)
	// Nothing is read here, so the kernel need not queue what it broadcasts.
	_ = syscall.Shutdown(fd, syscall.SHUT_RD)
	_, err = syscall.Write(fd, message)
	return err
}

// askRouteSocket sends a lookup and returns its answer. The socket also carries what
// other processes do to the table, so the answer is found by process and number.
func askRouteSocket(message []byte, seq int) (*xroute.RouteMessage, error) {
	fd, err := openRouteSocket()
	if err != nil {
		return nil, fmt.Errorf("open routing socket: %w", err)
	}
	defer syscall.Close(fd)
	timeout := syscall.NsecToTimeval(routeSocketReplyTimeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return nil, err
	}
	if _, err := syscall.Write(fd, message); err != nil {
		return nil, err
	}
	pid := uintptr(os.Getpid())
	buf := make([]byte, 4096)
	deadline := time.Now().Add(routeSocketReplyTimeout)
	for time.Now().Before(deadline) {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			return nil, err
		}
		messages, err := xroute.ParseRIB(xroute.RIBTypeRoute, buf[:n])
		if err != nil {
			continue
		}
		for _, m := range messages {
			reply, ok := m.(*xroute.RouteMessage)
			if !ok || reply.ID != pid || reply.Seq != seq {
				continue
			}
			if reply.Err != nil {
				return nil, reply.Err
			}
			return reply, nil
		}
	}
	return nil, errors.New("no answer on the routing socket")
}
