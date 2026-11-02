package dnswatch

import (
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Watcher captures DNS answers and connection starts on a changing set of
// interfaces and hands each to a callback. It needs root to open BPF devices;
// when it cannot, it logs once per interface and captures nothing there.
type Watcher struct {
	onAnswer func(Answer)
	logger   *slog.Logger

	// onFlow receives outbound connection starts; nil ignores them. It is set
	// before Sync and never changed while capturing.
	onFlow func(Flow)
	// flowsOn turns flow reporting on and off without reopening the devices;
	// the kernel filter keeps passing the packets, userspace skips parsing.
	flowsOn atomic.Bool
	// locals is this Mac's address set, refreshed on every Sync.
	locals atomic.Pointer[addrSet]
	// localAddrs lists this Mac's addresses; tests replace it.
	localAddrs func() addrSet
	udpDedup   *udpDeduper
	now        func() time.Time
	// open binds a packet source to an interface; tests replace it.
	open func(iface string) (packetSource, error)
	// dropped totals the packets the kernel discarded across all captures,
	// including ones since closed.
	dropped atomic.Uint64

	mu       sync.Mutex
	running  map[string]*atomic.Bool // interface -> stop flag
	failed   map[string]bool         // interfaces already reported as failing
	stopping bool
	wg       sync.WaitGroup
}

// NewWatcher returns a watcher that calls onAnswer from capture goroutines.
func NewWatcher(onAnswer func(Answer), logger *slog.Logger) *Watcher {
	w := &Watcher{
		onAnswer:   onAnswer,
		logger:     logger,
		localAddrs: localAddresses,
		open:       func(iface string) (packetSource, error) { return openCapture(iface) },
		now:        time.Now,
		running:    make(map[string]*atomic.Bool),
		failed:     make(map[string]bool),
	}
	w.udpDedup = newUDPDeduper(func() time.Time { return w.now() }, udpFlowDedup)
	return w
}

// SetFlowHandler makes the watcher report outbound connection starts, from
// the next Sync on. Flows are reported while SetFlowsEnabled(true) (the
// default once a handler is set). Call it before Sync.
func (w *Watcher) SetFlowHandler(onFlow func(Flow)) {
	w.onFlow = onFlow
	w.flowsOn.Store(onFlow != nil)
}

// SetFlowsEnabled turns flow reporting on or off. While off, captured
// connection starts are dropped before any parsing.
func (w *Watcher) SetFlowsEnabled(enabled bool) { w.flowsOn.Store(enabled && w.onFlow != nil) }

// refreshLocals re-reads this Mac's addresses.
func (w *Watcher) refreshLocals() {
	set := w.localAddrs()
	w.locals.Store(&set)
}

// isLocal reports whether ip is one of this Mac's addresses.
func (w *Watcher) isLocal(ip netip.Addr) bool {
	set := w.locals.Load()
	if set == nil {
		return false
	}
	_, ok := (*set)[ip.Unmap()]
	return ok
}

// handleFrame reports what one captured frame holds: a DNS answer, or an
// outbound connection start.
func (w *Watcher) handleFrame(frame []byte, dlt int, iface string) {
	p, ok := decodeIP(frame, dlt)
	if !ok {
		return
	}
	if answer, ok := answerFromPacket(p); ok {
		answer.Interface = iface
		w.onAnswer(answer)
		return
	}
	if !w.flowsOn.Load() {
		return
	}
	flow, ok := flowFromPacket(p)
	if !ok || !w.isLocal(flow.Src) {
		return
	}
	flow.Interface = iface
	flow.Time = w.now()
	if flow.Proto == ProtoUDP && !w.udpDedup.first(flow) {
		return
	}
	w.onFlow(flow)
}

// Sync captures on exactly the given interfaces: new ones start, ones no
// longer listed stop.
func (w *Watcher) Sync(ifaces []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopping {
		return
	}
	w.refreshLocals()

	for iface, stop := range w.running {
		if !slices.Contains(ifaces, iface) {
			stop.Store(true)
			delete(w.running, iface)
		}
	}
	for _, iface := range ifaces {
		if _, ok := w.running[iface]; ok {
			continue
		}
		c, err := w.open(iface)
		if err != nil {
			if !w.failed[iface] {
				w.failed[iface] = true
				w.logger.Warn("cannot watch DNS answers on interface", "interface", iface, "error", err)
			}
			continue
		}
		delete(w.failed, iface)
		stop := &atomic.Bool{}
		w.running[iface] = stop
		w.wg.Add(1)
		go w.readLoop(c, stop)
	}
}

// dropPollInterval is how often a reader asks the kernel for its drop count.
// The count is cumulative, so polling rarely loses nothing and keeps a
// syscall off the per-packet path.
const dropPollInterval = 5 * time.Second

// Dropped returns how many packets the kernel discarded because a capture
// buffer was full. Those answers and connections were never seen, so a rising
// count means history and attribution are incomplete.
func (w *Watcher) Dropped() uint64 { return w.dropped.Load() }

func (w *Watcher) readLoop(c packetSource, stop *atomic.Bool) {
	defer w.wg.Done()
	defer c.close()
	iface, dlt := c.ifaceName(), c.linkType()
	var seenDrops uint64
	nextPoll := w.now().Add(dropPollInterval)
	pollDrops := func() {
		total, err := c.kernelDrops()
		if err != nil || total < seenDrops {
			return
		}
		if delta := total - seenDrops; delta > 0 {
			w.dropped.Add(delta)
			w.logger.Warn("packets dropped by the capture buffer", "interface", iface, "dropped", delta)
		}
		seenDrops = total
	}
	defer pollDrops()
	for !stop.Load() {
		frames, err := c.read()
		if err != nil {
			// The interface went away or the device failed; the next Sync
			// starts a fresh capture if the interface comes back.
			w.logger.Debug("DNS capture ended", "interface", iface, "error", err)
			w.mu.Lock()
			if w.running[iface] == stop {
				delete(w.running, iface)
			}
			w.mu.Unlock()
			return
		}
		for _, frame := range frames {
			w.handleFrame(frame, dlt, iface)
		}
		if now := w.now(); !now.Before(nextPoll) {
			pollDrops()
			nextPoll = now.Add(dropPollInterval)
		}
	}
}

// Stop ends every capture and waits for the readers, at most about a second.
func (w *Watcher) Stop() {
	w.mu.Lock()
	w.stopping = true
	for iface, stop := range w.running {
		stop.Store(true)
		delete(w.running, iface)
	}
	w.mu.Unlock()
	w.wg.Wait()
}

// WatchableInterfaces lists the interfaces DNS answers can arrive on: up,
// not loopback, and holding a routable address. That covers the LAN and the
// VPN tunnel while leaving out link-local-only interfaces such as AWDL.
func WatchableInterfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if ok && !ipnet.IP.IsLinkLocalUnicast() && !ipnet.IP.IsLoopback() {
				out = append(out, iface.Name)
				break
			}
		}
	}
	return out
}
