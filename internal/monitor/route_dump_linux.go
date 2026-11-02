//go:build linux

package monitor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// dumpAttempts bounds how often a route dump is repeated when the kernel
// reports the table changed while it was being sent.
const dumpAttempts = 3

var errDumpInterrupted = errors.New("route dump interrupted by a table change")

// dumpDetectorRoutes reads the IPv4 unicast routes VPN detection reads, those
// with a destination of /0 or /1, from every routing table. The kernel sends
// the whole table, which holds RouteWise's own host routes by the thousand, so
// the rows are filtered on the fixed header of each message before any
// attribute is read: a row that is skipped costs no allocation. A dump that the
// kernel flags as interrupted (the table changed under it, as happens while
// RouteWise adds routes in bulk) is read again.
func dumpDetectorRoutes() ([]netlink.Route, error) {
	var lastErr error
	for range dumpAttempts {
		raw, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_INET)
		if err != nil {
			return nil, fmt.Errorf("dump routes: %w", err)
		}
		routes, err := parseRouteDump(raw)
		if err == nil {
			return routes, nil
		}
		if !errors.Is(err, errDumpInterrupted) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func align4(n int) int { return (n + 3) &^ 3 }

// parseRouteDump decodes the RTM_NEWROUTE messages of a route dump, keeping
// the rows detectorRoute accepts.
func parseRouteDump(raw []byte) ([]netlink.Route, error) {
	const (
		hdrLen   = unix.NLMSG_HDRLEN
		rtmLen   = unix.SizeofRtMsg
		attrsOff = hdrLen + rtmLen
	)
	var routes []netlink.Route
	interrupted := false
	for off := 0; off+hdrLen <= len(raw); {
		n := int(binary.NativeEndian.Uint32(raw[off:]))
		if n < hdrLen || off+n > len(raw) {
			return nil, fmt.Errorf("route dump message of %d bytes at %d does not fit", n, off)
		}
		msg := raw[off : off+n]
		off += align4(n)

		flags := binary.NativeEndian.Uint16(msg[6:])
		if flags&unix.NLM_F_DUMP_INTR != 0 {
			interrupted = true
		}
		switch binary.NativeEndian.Uint16(msg[4:]) {
		case unix.NLMSG_DONE:
			if interrupted {
				return nil, errDumpInterrupted
			}
			return routes, nil
		case unix.NLMSG_ERROR:
			return nil, errors.New("kernel refused the route dump")
		case unix.RTM_NEWROUTE:
		default:
			continue
		}
		if len(msg) < attrsOff {
			return nil, errors.New("route message is shorter than its header")
		}
		// rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags.
		dstLen, table, rtype := int(msg[hdrLen+1]), int(msg[hdrLen+4]), msg[hdrLen+7]
		rtmFlags := binary.NativeEndian.Uint32(msg[hdrLen+8:])
		if rtype != unix.RTN_UNICAST || dstLen > 1 || rtmFlags&unix.RTM_F_CLONED != 0 {
			continue
		}
		if r, ok := routeFromAttrs(msg[attrsOff:], dstLen, table); ok {
			routes = append(routes, r)
		}
	}
	if interrupted {
		return nil, errDumpInterrupted
	}
	return routes, nil
}

// routeFromAttrs reads the attributes of a kept route. A route without an
// output interface (a multipath or nexthop-object route) is not usable.
func routeFromAttrs(attrs []byte, dstLen, table int) (netlink.Route, bool) {
	r := netlink.Route{Table: table, Type: unix.RTN_UNICAST, Family: unix.AF_INET}
	var dst net.IP
	for len(attrs) >= unix.SizeofRtAttr {
		l := int(binary.NativeEndian.Uint16(attrs))
		if l < unix.SizeofRtAttr || l > len(attrs) {
			return r, false
		}
		val := attrs[unix.SizeofRtAttr:l]
		switch binary.NativeEndian.Uint16(attrs[2:]) {
		case unix.RTA_DST:
			if len(val) == net.IPv4len {
				dst = net.IP(append([]byte(nil), val...))
			}
		case unix.RTA_GATEWAY:
			if len(val) == net.IPv4len {
				r.Gw = net.IP(append([]byte(nil), val...))
			}
		case unix.RTA_OIF:
			if len(val) == 4 {
				r.LinkIndex = int(binary.NativeEndian.Uint32(val))
			}
		case unix.RTA_PRIORITY:
			if len(val) == 4 {
				r.Priority = int(binary.NativeEndian.Uint32(val))
			}
		case unix.RTA_TABLE:
			if len(val) == 4 {
				r.Table = int(binary.NativeEndian.Uint32(val))
			}
		}
		if align4(l) >= len(attrs) {
			break
		}
		attrs = attrs[align4(l):]
	}
	if r.LinkIndex == 0 {
		return r, false
	}
	if dstLen > 0 {
		if dst == nil {
			return r, false
		}
		r.Dst = &net.IPNet{IP: dst, Mask: net.CIDRMask(dstLen, 32)}
	}
	return r, true
}
