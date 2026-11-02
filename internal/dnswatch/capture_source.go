package dnswatch

// capture is one packet source bound to one interface, filtered to DNS answers
// and connection starts. The calls live in bpf_capture_darwin.go (a BPF
// device), packet_capture_linux.go (an AF_PACKET socket) and
// packet_capture_windows.go (a raw socket filtered in user space).
type capture struct {
	fd      int
	iface   string
	linkLen int
	dlt     int
	buf     []byte
	// frames is reused by every read, so a read allocates nothing per packet.
	frames [][]byte
	// drops accumulates the kernel's drop counter where reading it resets it
	// (Linux), so kernelDrops stays cumulative.
	drops uint64
	// filter runs the capture filter in user space where the OS cannot filter
	// in the kernel; nil when the kernel does.
	filter *softFilter
}

func (c *capture) ifaceName() string { return c.iface }
func (c *capture) linkType() int     { return c.dlt }

// packetSource is what the watcher reads frames from. The BPF capture is the
// only production implementation; tests supply their own.
type packetSource interface {
	ifaceName() string
	linkType() int
	// read returns the next batch of frames, valid until the next read. An
	// empty batch with a nil error is a timeout.
	read() ([][]byte, error)
	// kernelDrops reports packets the kernel discarded for want of buffer
	// space, cumulative for this source.
	kernelDrops() (uint64, error)
	close()
}
