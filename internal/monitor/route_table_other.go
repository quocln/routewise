//go:build !darwin && !linux && !windows

package monitor

import "github.com/quocln/routewise/internal/platform"

// fetchRouteTable reports that reading the route table is not implemented for
// this OS, so no VPN is ever detected.
func fetchRouteTable() ([]routeEntry, error) {
	return nil, platform.Unsupported("route table access")
}
