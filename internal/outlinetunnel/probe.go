package outlinetunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"time"
)

// ProbeTimeout bounds one health probe, dial and exchange together.
const ProbeTimeout = 10 * time.Second

// dnsHeaderLen is the fixed size of a DNS message header.
const dnsHeaderLen = 12

// rootNSQuery builds a DNS query for the root zone's NS records with the given
// message ID, in TCP framing (a two-byte length first). Every resolver answers
// it, so a reply proves the path to the resolver works end to end.
func rootNSQuery(id uint16) []byte {
	msg := make([]byte, 0, 2+dnsHeaderLen+5)
	msg = binary.BigEndian.AppendUint16(msg, 0) // length, patched below
	msg = binary.BigEndian.AppendUint16(msg, id)
	msg = binary.BigEndian.AppendUint16(msg, 0x0100) // standard query, recursion desired
	msg = binary.BigEndian.AppendUint16(msg, 1)      // one question
	msg = append(msg, 0, 0, 0, 0, 0, 0)              // no answer, authority, or additional records
	msg = append(msg, 0)                             // the root name
	msg = binary.BigEndian.AppendUint16(msg, 2)      // type NS
	msg = binary.BigEndian.AppendUint16(msg, 1)      // class IN
	binary.BigEndian.PutUint16(msg, uint16(len(msg)-2))
	return msg
}

// checkDNSReply verifies body is a response to the query with the given ID.
// Any response code counts: even SERVFAIL means the resolver answered through
// the tunnel.
func checkDNSReply(body []byte, id uint16) error {
	if len(body) < dnsHeaderLen {
		return errors.New("the DNS reply is shorter than a DNS header")
	}
	if binary.BigEndian.Uint16(body) != id {
		return errors.New("the DNS reply does not answer the query")
	}
	if binary.BigEndian.Uint16(body[2:])&0x8000 == 0 {
		return errors.New("the DNS reply is not a response")
	}
	return nil
}

// Probe proves the tunnel carries traffic: it opens a TCP stream to dns through
// the Shadowsocks server, sends one DNS query for the root zone's NS records,
// and requires a well-formed reply. It does not use the utun or the packet
// stack, so it works whatever the routing table says. The error never contains
// the key or the password.
func (t *Tunnel) Probe(ctx context.Context, dns netip.AddrPort) error {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	// A stopped tunnel must not leave a probe running.
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()

	conn, err := t.dialer.DialStream(ctx, dns.String())
	if err != nil {
		return fmt.Errorf("could not reach the DNS server through the VPN server: %w", err)
	}
	defer conn.Close()
	// Closing the stream is what interrupts a blocked read or write.
	unblock := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer unblock()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	id := uint16(rand.Uint32())
	if _, err := conn.Write(rootNSQuery(id)); err != nil {
		return probeIOError("send the DNS query", ctx, err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return probeIOError("read the DNS reply", ctx, err)
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < dnsHeaderLen {
		return errors.New("the DNS reply is shorter than a DNS header")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return probeIOError("read the DNS reply", ctx, err)
	}
	return checkDNSReply(body, id)
}

func probeIOError(what string, ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("could not %s: %w", what, ctx.Err())
	}
	return fmt.Errorf("could not %s: %w", what, err)
}
