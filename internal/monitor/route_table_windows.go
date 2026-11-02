package monitor

import (
	"golang.org/x/sys/windows"

	"github.com/quocln/routewise/internal/winnet"
)

// fetchRouteTable is the production routeTable default: the IPv4 routes read
// with GetIpForwardTable2, each with its adapter.
func fetchRouteTable() ([]routeEntry, error) {
	routes, err := winnet.Routes(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	return windowsRouteEntries(routes), nil
}
