package dnswatch

import (
	"net"
	"net/netip"
)

// softFilter is captureFilter run in user space, for platforms whose capture
// source cannot take a BPF program (Windows raw sockets). It decides the same
// packets and keeps the same number of bytes as that program, which a test holds
// it to, but reads the few header bytes directly: an interpreted program per
// packet is a measurable cost when a raw socket delivers everything an
// interface carries.
type softFilter struct{}

// newSoftFilter returns the filter for raw IP packets, which have no link
// header.
func newSoftFilter() (*softFilter, error) { return &softFilter{}, nil }

// apply returns the part of pkt the filter keeps, aliasing pkt, or nil when it
// drops the packet. A packet too short for the filter to read is dropped, as in
// the kernel.
func (f *softFilter) apply(pkt []byte) []byte {
	n := keepLength(pkt)
	if n <= 0 {
		return nil
	}
	if n > len(pkt) {
		n = len(pkt)
	}
	return pkt[:n]
}

// keepLength is captureFilter(0) written out: how many bytes of the raw IP
// packet to keep, 0 to drop it. Every read is bounds-checked the way the BPF
// machine checks it, so a truncated packet is dropped.
func keepLength(p []byte) int {
	if len(p) == 0 {
		return 0
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 10 {
			return 0
		}
		// A later fragment carries no transport header.
		if (uint16(p[6])<<8|uint16(p[7]))&0x1fff != 0 {
			return 0
		}
		ihl := int(p[0]&0x0f) << 2
		switch p[9] {
		case 6:
			return tcpKeep(p, ihl)
		case 17:
			return udpKeep(p, ihl, ihl+8)
		}
	case 6:
		if len(p) < 7 {
			return 0
		}
		switch p[6] {
		case 6:
			return tcpKeep(p, 40)
		case 17:
			return udpKeep(p, 40, 48)
		}
	}
	return 0
}

// tcpKeep keeps a connection-opening segment (SYN set, ACK clear) whose
// transport header starts at off.
func tcpKeep(p []byte, off int) int {
	if len(p) <= off+13 {
		return 0
	}
	if p[off+13]&(tcpSYN|tcpACK) == tcpSYN {
		return flowSnapLen
	}
	return 0
}

// udpKeep keeps a DNS answer (source port 53) whole, and a datagram whose first
// payload byte, at payload, marks a QUIC long header, down to its headers.
func udpKeep(p []byte, off, payload int) int {
	if len(p) < off+2 {
		return 0
	}
	if uint16(p[off])<<8|uint16(p[off+1]) == 53 {
		return snapLen
	}
	if len(p) > payload && p[payload]&quicLongHeader != 0 {
		return flowSnapLen
	}
	return 0
}

// captureAddress picks the IPv4 address a raw socket binds to in order to see
// an interface's traffic: the first global unicast address, else a link-local
// one (an interface that only has an autoconfigured address still carries
// traffic).
func captureAddress(addrs []net.Addr) (netip.Addr, bool) {
	var linkLocal netip.Addr
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok || !addr.Unmap().Is4() {
			continue
		}
		addr = addr.Unmap()
		switch {
		case addr.IsLoopback() || addr.IsUnspecified():
		case addr.IsLinkLocalUnicast():
			if !linkLocal.IsValid() {
				linkLocal = addr
			}
		default:
			return addr, true
		}
	}
	return linkLocal, linkLocal.IsValid()
}
