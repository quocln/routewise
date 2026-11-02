//go:build darwin

package monitor

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/net/route"
)

// ribRouteEntries reads the IPv4 routing table in process, from the kernel's
// routing information base, and returns the entries VPN detection reads. It is
// the same table and the same entries as `netstat -rn -f inet` yields through
// parseNetstatRoutes, without forking a process or formatting thousands of
// rows into text: reading is a few hundred microseconds whatever the table's
// size, and read-only.
func ribRouteEntries() ([]routeEntry, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("fetch routing table: %w", err)
	}
	return entriesFromRIB(rib, interfaceNamesByIndex)
}

// interfaceNamesByIndex maps interface indexes to names.
func interfaceNamesByIndex() map[int]string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	names := make(map[int]string, len(ifaces))
	for _, ifc := range ifaces {
		names[ifc.Index] = ifc.Name
	}
	return names
}

// entriesFromRIB turns a routing table dump (route.RIBTypeRoute) into entries.
// names is only called when some row is kept, so a table without a default
// route costs no interface lookup.
func entriesFromRIB(rib []byte, names func() map[int]string) ([]routeEntry, error) {
	rib, err := dropHostRoutes(rib)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("parse routing table: %w", err)
	}

	var entries []routeEntry
	var byIndex map[int]string
	for _, msg := range msgs {
		m, ok := msg.(*route.RouteMessage)
		if !ok || len(m.Addrs) <= syscall.RTAX_NETMASK {
			continue
		}
		dest, ok := ribDest(m.Addrs[syscall.RTAX_DST], m.Addrs[syscall.RTAX_NETMASK])
		if !ok || !detectorDest(dest) {
			continue
		}
		gateway, ok := ribGateway(m.Addrs[syscall.RTAX_GATEWAY])
		if !ok {
			continue
		}
		if byIndex == nil {
			byIndex = names()
		}
		netif := byIndex[m.Index]
		if netif == "" {
			continue
		}
		entries = append(entries, routeEntry{
			Dest:    dest,
			Gateway: gateway,
			Iface:   netif,
			Scoped:  m.Flags&syscall.RTF_IFSCOPE != 0,
			// A managed tunnel's owner is found through its utun control
			// socket, which ipsec, tun and tap lack.
			Tunnel: strings.HasPrefix(netif, "utun"),
		})
	}
	return entries, nil
}

// Offsets in the BSD rt_msghdr that the host-route prefilter reads: the message
// length, then the flags after the 16-bit interface index and its padding.
const (
	ribMsgLenOffset = 0
	ribFlagsOffset  = 8
	ribHeaderMin    = ribFlagsOffset + 4
)

// dropHostRoutes removes the messages of host routes (RTF_HOST) from a routing
// table dump, in place, before they are parsed. A table holds one such route
// per address RouteWise or the ARP table has added, thousands of them, and a
// full-tunnel route is never a host route: parsing each into route.Message
// values would allocate most of a megabyte per read for rows nobody looks at.
func dropHostRoutes(rib []byte) ([]byte, error) {
	kept := 0
	for off := 0; off < len(rib); {
		if len(rib)-off < ribHeaderMin {
			return nil, fmt.Errorf("routing table dump is truncated at byte %d", off)
		}
		n := int(binary.NativeEndian.Uint16(rib[off+ribMsgLenOffset:]))
		if n < ribHeaderMin || off+n > len(rib) {
			return nil, fmt.Errorf("routing table message of %d bytes at %d does not fit", n, off)
		}
		if binary.NativeEndian.Uint32(rib[off+ribFlagsOffset:])&syscall.RTF_HOST == 0 {
			kept += copy(rib[kept:], rib[off:off+n])
		}
		off += n
	}
	return rib[:kept], nil
}

// ribDest builds a route's destination prefix from its destination and netmask
// addresses. A mask that is not a run of leading ones is refused. A missing
// mask is a host route.
func ribDest(dst, mask route.Addr) (netip.Prefix, bool) {
	d, ok := dst.(*route.Inet4Addr)
	if !ok {
		return netip.Prefix{}, false
	}
	ones := 32
	if mask != nil {
		m, ok := mask.(*route.Inet4Addr)
		if !ok {
			return netip.Prefix{}, false
		}
		v := binary.BigEndian.Uint32(m.IP[:])
		ones = bits.LeadingZeros32(^v)
		if ones != bits.OnesCount32(v) {
			return netip.Prefix{}, false
		}
	}
	return netip.PrefixFrom(netip.AddrFrom4(d.IP), ones).Masked(), true
}

// ribGateway reads a route's gateway the way isTunnelGateway reads netstat's
// column: an IPv4 next hop, or a link-level address without a hardware address
// (netstat's "link#N" and interface name), which means the route points at the
// interface and has no next hop. Anything else, such as an ARP entry's hardware
// address, cannot be a tunnel route.
func ribGateway(gw route.Addr) (netip.Addr, bool) {
	switch g := gw.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(g.IP), true
	case *route.LinkAddr:
		return netip.Addr{}, len(g.Addr) == 0
	}
	return netip.Addr{}, false
}
