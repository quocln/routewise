//go:build darwin

package monitor

import (
	"log/slog"
	"os/exec"
	"sync/atomic"
)

// netstatPath is the absolute path of netstat. The daemon runs as root, so it
// never resolves the tool through PATH.
const netstatPath = "/usr/sbin/netstat"

// ribFallbackLogged limits the log to the first time the routing table could
// not be read in process.
var ribFallbackLogged atomic.Bool

// fetchRouteTable is the production routeTable default. It reads the routing
// table in process (ribRouteEntries); only if that fails does it fall back to
// forking netstat and parsing its `netstat -rn` text.
func fetchRouteTable() ([]routeEntry, error) {
	entries, err := ribRouteEntries()
	if err == nil {
		return entries, nil
	}
	if ribFallbackLogged.CompareAndSwap(false, true) {
		slog.Warn("could not read the routing table in process, falling back to netstat", "error", err)
	}
	cmd := exec.Command(netstatPath, "-rn", "-f", "inet")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseNetstatRoutes(out), nil
}
