package dnswatch

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// sioRcvAll is SIO_RCVALL: with rcvallOn it makes a raw socket bound to an
	// interface address receive every IP packet that interface carries, not
	// only those addressed to the socket.
	sioRcvAll = 0x98000001
	rcvallOn  = 1
	// recvBufferBytes is the socket buffer asked for. User-space filtering is
	// slower than a kernel program, so the buffer absorbs bursts.
	recvBufferBytes = 4 << 20
	// readTimeoutMs bounds a read so a reader can notice it was asked to stop.
	readTimeoutMs = 1000
)

var startWinsock sync.Once

// openCapture opens a raw IPv4 socket bound to iface's IPv4 address, with
// SIO_RCVALL on (no driver such as Npcap is needed, but the process must run
// as administrator, which the service does). Packets arrive starting at their
// IP header, so frames are read as raw IP with no link header, and the same
// filter the other platforms run in their kernels runs here in user space
// before a packet is handed on.
//
// Limits: IPv4 only; Windows does not report how many packets the socket
// buffer dropped, so kernelDrops stays zero; and which packets of the two
// directions reach SIO_RCVALL depends on the Windows version, so DNS answers
// (inbound) are reliable while outbound connection starts may be partly missed.
func openCapture(iface string) (*capture, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("capture on %s: %w", iface, err)
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, fmt.Errorf("capture on %s: %w", iface, err)
	}
	local, ok := captureAddress(addrs)
	if !ok {
		return nil, fmt.Errorf("capture on %s: the interface has no IPv4 address", iface)
	}
	filter, err := newSoftFilter()
	if err != nil {
		return nil, fmt.Errorf("capture on %s: %w", iface, err)
	}

	startWinsock.Do(func() {
		var data windows.WSAData
		_ = windows.WSAStartup(0x0202, &data) // a failure shows as the socket call failing
	})
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return nil, fmt.Errorf("open raw socket: %w", err)
	}
	c := &capture{fd: int(fd), iface: iface, dlt: dltRaw, linkLen: linkHeaderLen(dltRaw), filter: filter}
	if err := c.configure(local.As4()); err != nil {
		windows.Closesocket(fd)
		return nil, fmt.Errorf("capture on %s: %w", iface, err)
	}
	return c, nil
}

func (c *capture) handle() windows.Handle { return windows.Handle(c.fd) }

func (c *capture) configure(local [4]byte) error {
	// Not inheritable, so a child process never holds the socket open.
	if err := windows.SetHandleInformation(windows.Handle(c.fd), windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		return fmt.Errorf("set handle information: %w", err)
	}
	if err := windows.SetsockoptInt(c.handle(), windows.SOL_SOCKET, windows.SO_RCVBUF, recvBufferBytes); err != nil {
		return fmt.Errorf("receive buffer: %w", err)
	}
	if err := windows.SetsockoptInt(c.handle(), windows.SOL_SOCKET, windows.SO_RCVTIMEO, readTimeoutMs); err != nil {
		return fmt.Errorf("read timeout: %w", err)
	}
	if err := windows.Bind(c.handle(), &windows.SockaddrInet4{Addr: local}); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	on, returned := uint32(rcvallOn), uint32(0)
	if err := windows.WSAIoctl(c.handle(), sioRcvAll, (*byte)(unsafe.Pointer(&on)), uint32(unsafe.Sizeof(on)), nil, 0, &returned, nil, 0); err != nil {
		return fmt.Errorf("enable receive-all (needs administrator): %w", err)
	}
	c.buf = make([]byte, snapLen+1)
	return nil
}

// read waits up to a second for a packet. An empty result with a nil error is a
// timeout, or a packet the filter dropped. The frame aliases the capture's
// buffer and is valid until the next read.
func (c *capture) read() ([][]byte, error) {
	buf := windows.WSABuf{Len: uint32(len(c.buf)), Buf: &c.buf[0]}
	var received, flags uint32
	if err := windows.WSARecv(c.handle(), &buf, 1, &received, &flags, nil, nil); err != nil {
		if errors.Is(err, windows.WSAETIMEDOUT) || errors.Is(err, windows.WSAEINTR) {
			return nil, nil
		}
		return nil, err
	}
	kept := c.filter.apply(c.buf[:received])
	if kept == nil {
		return nil, nil
	}
	c.frames = append(c.frames[:0], kept)
	return c.frames, nil
}

// kernelDrops is always zero: Windows does not report receive-buffer drops for
// a raw socket.
func (c *capture) kernelDrops() (uint64, error) { return 0, nil }

func (c *capture) close() {
	windows.Closesocket(c.handle())
}
