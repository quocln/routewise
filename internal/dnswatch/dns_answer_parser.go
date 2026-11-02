// Package dnswatch observes the DNS answers this Mac receives and the
// connections it opens, without taking part in either. It reads packets off
// each network interface through BPF: UDP from source port 53 becomes the name
// and addresses of every successful answer, and TCP SYNs and QUIC long-header
// packets become outbound Flows. Answers served from the macOS cache produce
// no packet, and DNS over TCP, HTTPS, or TLS is not seen.
package dnswatch

import (
	"encoding/binary"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Link-layer types, as BIOCGDLT reports them.
const (
	dltNull  = 0   // BSD loopback encapsulation: 4-byte address family
	dltEN10M = 1   // Ethernet
	dltRaw   = 12  // raw IP, no link header
	dltLoop  = 108 // OpenBSD loopback: 4-byte address family in network order
)

// Answer is one DNS response seen on the wire.
type Answer struct {
	// Name is the queried name without the trailing dot.
	Name string
	// Addresses are the A and AAAA records of the answer section.
	Addresses []netip.Addr
	// Server is the address the answer came from.
	Server netip.Addr
	// Interface is the network interface the answer arrived on.
	Interface string
	// TTL is the shortest time-to-live among the address records.
	TTL time.Duration
}

// linkHeaderLen returns how many bytes precede the IP header for a link type,
// or -1 for a link type dnswatch does not read.
func linkHeaderLen(dlt int) int {
	switch dlt {
	case dltNull, dltLoop:
		return 4
	case dltEN10M:
		return 14
	case dltRaw:
		return 0
	default:
		return -1
	}
}

// Proto is the transport protocol of a Flow.
type Proto string

// Transport protocols a Flow can have.
const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

// Flow is the start of one outbound connection: a TCP SYN, or the first QUIC
// long-header packet of a UDP flow.
type Flow struct {
	Time      time.Time
	Interface string
	Src, Dst  netip.Addr
	DstPort   uint16
	Proto     Proto
}

// quicPort is the UDP port QUIC connections are recorded on.
const quicPort = 443

// IP protocol numbers.
const (
	ipProtoTCP = 6
	ipProtoUDP = 17
)

// ipPacket is the transport segment of a captured IP packet.
type ipPacket struct {
	src, dst netip.Addr
	proto    byte
	// transport starts at the TCP or UDP header.
	transport []byte
	// moreFragments is set on the first fragment of a fragmented datagram.
	moreFragments bool
}

// decodeIP locates the transport header in a frame. It reports false for
// anything that is not IPv4 (not a later fragment) or IPv6 without extension
// headers, and for truncated headers.
func decodeIP(frame []byte, dlt int) (ipPacket, bool) {
	offset := linkHeaderLen(dlt)
	if offset < 0 || len(frame) <= offset {
		return ipPacket{}, false
	}
	packet := frame[offset:]

	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return ipPacket{}, false
		}
		headerLen := int(packet[0]&0x0f) * 4
		flagsFrag := binary.BigEndian.Uint16(packet[6:8])
		if headerLen < 20 || len(packet) < headerLen || flagsFrag&0x1fff != 0 {
			return ipPacket{}, false
		}
		return ipPacket{
			src:           netip.AddrFrom4([4]byte(packet[12:16])),
			dst:           netip.AddrFrom4([4]byte(packet[16:20])),
			proto:         packet[9],
			transport:     packet[headerLen:],
			moreFragments: flagsFrag&0x2000 != 0,
		}, true
	case 6:
		if len(packet) < 40 {
			return ipPacket{}, false
		}
		return ipPacket{
			src:       netip.AddrFrom16([16]byte(packet[8:24])),
			dst:       netip.AddrFrom16([16]byte(packet[24:40])),
			proto:     packet[6],
			transport: packet[40:],
		}, true
	default:
		return ipPacket{}, false
	}
}

// parseFrame extracts a DNS answer from one captured frame. It reports false
// for anything that is not a complete, successful DNS response over UDP from
// port 53: queries, errors, fragments, truncated frames, and other traffic.
func parseFrame(frame []byte, dlt int) (Answer, bool) {
	p, ok := decodeIP(frame, dlt)
	if !ok {
		return Answer{}, false
	}
	return answerFromPacket(p)
}

// answerFromPacket is parseFrame for an already decoded packet.
func answerFromPacket(p ipPacket) (Answer, bool) {
	if p.proto != ipProtoUDP || p.moreFragments || len(p.transport) < 8 {
		return Answer{}, false
	}
	return parseDNSAnswer(p.transport, p.src)
}

// parseDNSAnswer reads a DNS answer from a UDP datagram from server.
func parseDNSAnswer(udp []byte, server netip.Addr) (Answer, bool) {
	if binary.BigEndian.Uint16(udp[0:2]) != 53 {
		return Answer{}, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return Answer{}, false
	}

	var msg dns.Msg
	if err := msg.Unpack(udp[8:udpLen]); err != nil {
		return Answer{}, false
	}
	if !msg.Response || msg.Rcode != dns.RcodeSuccess || len(msg.Question) == 0 {
		return Answer{}, false
	}

	answer := Answer{
		Name:   strings.TrimSuffix(strings.ToLower(msg.Question[0].Name), "."),
		Server: server,
	}
	minTTL := uint32(math.MaxUint32)
	for _, rr := range msg.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			if addr, ok := netip.AddrFromSlice(rr.A.To4()); ok {
				answer.Addresses = append(answer.Addresses, addr)
				minTTL = min(minTTL, rr.Hdr.Ttl)
			}
		case *dns.AAAA:
			if addr, ok := netip.AddrFromSlice(rr.AAAA.To16()); ok {
				answer.Addresses = append(answer.Addresses, addr)
				minTTL = min(minTTL, rr.Hdr.Ttl)
			}
		}
	}
	if len(answer.Addresses) == 0 || answer.Name == "" {
		return Answer{}, false
	}
	answer.TTL = time.Duration(minTTL) * time.Second
	return answer, true
}

// parseFlow extracts the start of an outbound connection from one captured
// frame: a TCP SYN without ACK, or a UDP datagram whose first payload byte has
// the QUIC long-header bit. The caller sets Time and Interface and decides
// whether the source is this Mac. UDP datagrams to port 53 are DNS queries,
// not connections, and are ignored.
func parseFlow(frame []byte, dlt int) (Flow, bool) {
	p, ok := decodeIP(frame, dlt)
	if !ok {
		return Flow{}, false
	}
	return flowFromPacket(p)
}

// flowFromPacket is parseFlow for an already decoded packet.
func flowFromPacket(p ipPacket) (Flow, bool) {
	switch p.proto {
	case ipProtoTCP:
		// Ports, then the flags byte at offset 13.
		if len(p.transport) < 14 || p.transport[13]&(tcpSYN|tcpACK) != tcpSYN {
			return Flow{}, false
		}
		return Flow{
			Src: p.src, Dst: p.dst,
			DstPort: binary.BigEndian.Uint16(p.transport[2:4]),
			Proto:   ProtoTCP,
		}, true
	case ipProtoUDP:
		if len(p.transport) < 9 || p.transport[8]&quicLongHeader == 0 {
			return Flow{}, false
		}
		// QUIC (HTTP/3) runs on port 443. Other UDP with the long-header bit
		// set, such as RTP in calls, is media rather than a site visit and
		// would flood the history.
		port := binary.BigEndian.Uint16(p.transport[2:4])
		if port != quicPort {
			return Flow{}, false
		}
		return Flow{Src: p.src, Dst: p.dst, DstPort: port, Proto: ProtoUDP}, true
	}
	return Flow{}, false
}

// splitBPFBuffer returns the captured frames in one read from a BPF device.
// Each record is a bpf_hdr (capture length at byte 8, header length at byte
// 16, host byte order) followed by the frame, padded to a 4-byte boundary.
func splitBPFBuffer(buf []byte) [][]byte {
	return appendBPFFrames(nil, buf)
}

// appendBPFFrames is splitBPFBuffer appending to dst, so a reader can reuse one
// slice across reads. The frames alias buf.
func appendBPFFrames(dst [][]byte, buf []byte) [][]byte {
	for offset := 0; offset+18 <= len(buf); {
		capLen := int(binary.LittleEndian.Uint32(buf[offset+8 : offset+12]))
		hdrLen := int(binary.LittleEndian.Uint16(buf[offset+16 : offset+18]))
		start := offset + hdrLen
		end := start + capLen
		if hdrLen < 18 || end > len(buf) {
			break
		}
		dst = append(dst, buf[start:end])
		offset += (hdrLen + capLen + 3) &^ 3
	}
	return dst
}
