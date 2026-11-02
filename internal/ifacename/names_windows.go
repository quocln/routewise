//go:build windows

package ifacename

import (
	"regexp"
	"sync"
	"time"

	"github.com/quocln/routewise/internal/winnet"
)

// validName and nameHint feed the shared Validate; the alias rules and the
// tunnel name hints are in windows_rules.go.
var validName = regexp.MustCompile(`^.+$`)

const nameHint = windowsNameHint

func validateOS(name string) error { return validateWindowsAlias(name) }

// isTunnel trusts the adapter's driver and type, and the alias only as a hint
// for adapters the lookup cannot place (or one the driver check passes over,
// such as the helper's own tunnels).
func isTunnel(name string) bool {
	if tunnel, found := adapterIsVPNTunnel(cachedAdapters(), name); found && tunnel {
		return true
	}
	return isWindowsTunnel(name)
}

func isVPNDevice(name string) bool { return isTunnel(name) }

// adapterCacheTTL keeps one interface table read serving the many name checks a
// single route operation makes.
const adapterCacheTTL = time.Second

var adapterCache struct {
	sync.Mutex
	at       time.Time
	adapters []winnet.Adapter
}

// cachedAdapters returns the interface table, re-read once the cached copy is
// older than adapterCacheTTL. A failed read yields nil, which leaves the name
// rules to decide.
func cachedAdapters() []winnet.Adapter {
	adapterCache.Lock()
	defer adapterCache.Unlock()
	if time.Since(adapterCache.at) < adapterCacheTTL {
		return adapterCache.adapters
	}
	adapters, err := winnet.Adapters()
	if err != nil {
		adapters = nil
	}
	adapterCache.adapters, adapterCache.at = adapters, time.Now()
	return adapterCache.adapters
}
