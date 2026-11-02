package dnswatch

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
)

// The syscall BPF helpers are marked deprecated in favor of x/net/bpf, but
// that package only assembles filters; it has no device ioctls. These calls
// are the stable darwin ioctls and keep the build free of cgo.

// biocgstats is the BIOCGSTATS request: _IOR('B', 111, struct bpf_stat).
const biocgstats = 0x4008426f

// bpfStat mirrors struct bpf_stat. Both counters are cumulative since the
// device was bound.
type bpfStat struct {
	recv uint32
	drop uint32
}

// openCapture binds a free /dev/bpf* device to iface with the DNS filter
// installed in the kernel. Reads return at least once a second, so a reader
// can notice it was asked to stop.
func openCapture(iface string) (*capture, error) {
	fd := -1
	var err error
	for i := range 256 {
		fd, err = syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EBUSY) {
			return nil, fmt.Errorf("open /dev/bpf%d: %w", i, err)
		}
	}
	if fd < 0 {
		return nil, fmt.Errorf("no free BPF device: %w", err)
	}

	c := &capture{fd: fd, iface: iface}
	if err := c.configure(); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("capture on %s: %w", iface, err)
	}
	return c, nil
}

// captureBufferSize is the BPF buffer asked for, before the device is bound.
// The kernel default (debug.bpf_bufsize, 4 KiB here) leaves almost no room
// while the reader is busy; the kernel caps the request at net.bpf.maxbufsize,
// so a lower limit only shrinks what is granted.
const captureBufferSize = 512 * 1024

func (c *capture) configure() error {
	// The size can only be set before BIOCSETIF. A refusal keeps the default
	// buffer: capture still works, it only drops more under load.
	_, _ = syscall.SetBpfBuflen(c.fd, captureBufferSize)
	bufLen, err := syscall.BpfBuflen(c.fd)
	if err != nil {
		return fmt.Errorf("buffer length: %w", err)
	}
	if err := syscall.SetBpfInterface(c.fd, c.iface); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	if err := syscall.SetBpfImmediate(c.fd, 1); err != nil {
		return fmt.Errorf("immediate mode: %w", err)
	}
	if c.dlt, err = syscall.BpfDatalink(c.fd); err != nil {
		return fmt.Errorf("link type: %w", err)
	}
	if c.linkLen = linkHeaderLen(c.dlt); c.linkLen < 0 {
		return fmt.Errorf("unsupported link type %d", c.dlt)
	}

	raw, err := bpf.Assemble(captureFilter(uint32(c.linkLen)))
	if err != nil {
		return fmt.Errorf("assemble filter: %w", err)
	}
	insns := make([]syscall.BpfInsn, len(raw))
	for i, r := range raw {
		insns[i] = syscall.BpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	if err := syscall.SetBpf(c.fd, insns); err != nil {
		return fmt.Errorf("install filter: %w", err)
	}
	if err := syscall.SetBpfTimeout(c.fd, &syscall.Timeval{Sec: 1}); err != nil {
		return fmt.Errorf("read timeout: %w", err)
	}
	c.buf = make([]byte, bufLen)
	return nil
}

// read waits up to a second for captured frames. An empty result with a nil
// error is a timeout. The frames alias the capture's buffers and are valid
// until the next read.
func (c *capture) read() ([][]byte, error) {
	n, err := syscall.Read(c.fd, c.buf)
	if err != nil {
		if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) {
			return nil, nil
		}
		return nil, err
	}
	c.frames = appendBPFFrames(c.frames[:0], c.buf[:n])
	return c.frames, nil
}

// kernelDrops returns how many packets the kernel discarded because the BPF
// buffer was full since the device was bound.
func (c *capture) kernelDrops() (uint64, error) {
	var st bpfStat
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(c.fd), biocgstats, uintptr(unsafe.Pointer(&st))); errno != 0 {
		return 0, errno
	}
	return uint64(st.drop), nil
}

func (c *capture) close() {
	syscall.Close(c.fd)
}
