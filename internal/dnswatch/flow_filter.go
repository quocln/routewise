package dnswatch

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// udpFlowDedup is how long one UDP destination is reported only once. A QUIC
// connection sends several long-header packets while it is set up, and a busy
// one re-handshakes often.
const udpFlowDedup = 60 * time.Second

// maxUDPDedupEntries bounds the dedupe table; expired entries are swept first.
const maxUDPDedupEntries = 4096

// udpKey identifies a UDP destination on one interface.
type udpKey struct {
	iface string
	dst   netip.Addr
	port  uint16
}

// udpDeduper reports each (interface, destination, port) once per window.
type udpDeduper struct {
	now    func() time.Time
	window time.Duration

	mu   sync.Mutex
	seen map[udpKey]time.Time
}

func newUDPDeduper(now func() time.Time, window time.Duration) *udpDeduper {
	return &udpDeduper{now: now, window: window, seen: make(map[udpKey]time.Time)}
}

// first reports whether f is the first flow to its destination within the
// window, and records it.
func (d *udpDeduper) first(f Flow) bool {
	key := udpKey{f.Interface, f.Dst, f.DstPort}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if at, ok := d.seen[key]; ok && now.Sub(at) < d.window {
		return false
	}
	d.seen[key] = now
	if len(d.seen) > maxUDPDedupEntries {
		for k, at := range d.seen {
			if now.Sub(at) >= d.window {
				delete(d.seen, k)
			}
		}
		// Still full of live entries: forget them all rather than grow. The
		// worst outcome is a destination reported once more.
		if len(d.seen) > maxUDPDedupEntries {
			clear(d.seen)
			d.seen[key] = now
		}
	}
	return true
}

// addrSet is a set of this Mac's addresses.
type addrSet map[netip.Addr]struct{}

// localAddresses lists every address assigned to an up interface, so an
// outbound packet (source is ours) can be told from an inbound one.
func localAddresses() addrSet {
	set := make(addrSet)
	ifaces, err := net.Interfaces()
	if err != nil {
		return set
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if addr, ok := netip.AddrFromSlice(ipnet.IP); ok {
					set[addr.Unmap()] = struct{}{}
				}
			}
		}
	}
	return set
}
