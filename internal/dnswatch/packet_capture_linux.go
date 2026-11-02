package dnswatch

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// htons converts a protocol number to the network byte order AF_PACKET wants.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// openCapture binds an AF_PACKET socket to iface with the DNS filter installed
// in the kernel. A SOCK_DGRAM packet socket hands over each packet starting at
// its IP header whatever the link type (Ethernet, WireGuard, tun), so frames
// are read as raw IP with no link header. Reads return at least once a second,
// so a reader can notice it was asked to stop.
func openCapture(iface string) (*capture, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("capture on %s: %w", iface, err)
	}
	// Protocol 0 keeps the socket from receiving anything until it is bound,
	// so the filter is in place before the first packet can queue.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open packet socket: %w", err)
	}
	c := &capture{fd: fd, iface: iface, dlt: dltRaw, linkLen: linkHeaderLen(dltRaw)}
	if err := c.configure(ifc.Index); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("capture on %s: %w", iface, err)
	}
	return c, nil
}

func (c *capture) configure(ifindex int) error {
	raw, err := bpf.Assemble(captureFilter(uint32(c.linkLen)))
	if err != nil {
		return fmt.Errorf("assemble filter: %w", err)
	}
	insns := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		insns[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	prog := unix.SockFprog{Len: uint16(len(insns)), Filter: &insns[0]}
	if err := unix.SetsockoptSockFprog(c.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return fmt.Errorf("install filter: %w", err)
	}
	if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return fmt.Errorf("read timeout: %w", err)
	}
	addr := unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}
	if err := unix.Bind(c.fd, &addr); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	c.buf = make([]byte, snapLen+1)
	return nil
}

// read waits up to a second for a captured packet. An empty result with a nil
// error is a timeout. The frame aliases the capture's buffer and is valid until
// the next read.
func (c *capture) read() ([][]byte, error) {
	n, err := unix.Read(c.fd, c.buf)
	if err != nil {
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			return nil, nil
		}
		return nil, err
	}
	c.frames = append(c.frames[:0], c.buf[:n])
	return c.frames, nil
}

// kernelDrops returns how many packets the kernel discarded because the socket
// buffer was full since the capture was opened. The kernel resets its counter
// on every read of it, so the totals are accumulated here.
func (c *capture) kernelDrops() (uint64, error) {
	st, err := unix.GetsockoptTpacketStats(c.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return 0, err
	}
	c.drops += uint64(st.Drops)
	return c.drops, nil
}

func (c *capture) close() {
	unix.Close(c.fd)
}
