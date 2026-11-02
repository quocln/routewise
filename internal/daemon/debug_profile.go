package daemon

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"runtime/pprof"
	"sync/atomic"
	"time"

	"github.com/quocln/routewise/internal/api"
)

// mutexProfileRate samples one in this many mutex contention events while a mutex
// profile runs. It is off the rest of the time, so a helper nobody is profiling
// pays nothing.
const mutexProfileRate = 5

var profileRunning atomic.Bool

// Profile records a runtime profile of this process. It holds function names and
// counts only, never the contents of memory, so no key or address is in it. A
// timed profile waits out its duration; one runs at a time.
func (d *Daemon) Profile(kind api.ProfileKind, seconds int) ([]byte, error) {
	if seconds < 1 || seconds > api.MaxProfileSeconds {
		return nil, fmt.Errorf("%w: seconds must be 1 to %d", api.ErrRejected, api.MaxProfileSeconds)
	}
	if !profileRunning.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("%w: a profile is already running", api.ErrRejected)
	}
	defer profileRunning.Store(false)

	ctx, cancel := context.WithTimeout(d.baseCtx, time.Duration(seconds)*time.Second)
	defer cancel()
	var buf bytes.Buffer
	switch kind {
	case api.ProfileCPU:
		if err := pprof.StartCPUProfile(&buf); err != nil {
			return nil, fmt.Errorf("start CPU profile: %w", err)
		}
		<-ctx.Done()
		pprof.StopCPUProfile()
	case api.ProfileHeap:
		if err := pprof.Lookup("heap").WriteTo(&buf, 0); err != nil {
			return nil, fmt.Errorf("write heap profile: %w", err)
		}
	case api.ProfileMutex:
		previous := runtime.SetMutexProfileFraction(mutexProfileRate)
		defer runtime.SetMutexProfileFraction(previous)
		<-ctx.Done()
		if err := pprof.Lookup("mutex").WriteTo(&buf, 0); err != nil {
			return nil, fmt.Errorf("write mutex profile: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: unknown profile kind %q", api.ErrRejected, kind)
	}
	return buf.Bytes(), nil
}
