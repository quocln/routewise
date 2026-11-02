package route

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/quocln/routewise/internal/winnet"
)

// systemTable is the table the daemon drives on Windows: the IP Helper route
// table, read and written through the same calls the WireGuard client uses.
func systemTable() Table { return newWindowsTable(iphlpOps{}) }

// iphlpOps is windowsOps over iphlpapi.dll (GetIpForwardTable2,
// CreateIpForwardEntry2, SetIpForwardEntry2, DeleteIpForwardEntry2).
type iphlpOps struct{}

func (iphlpOps) adapters() ([]winnet.Adapter, error) { return winnet.Adapters() }

func (iphlpOps) routes(family int) ([]winnet.Route, error) {
	if family == 6 {
		return winnet.Routes(windows.AF_INET6)
	}
	return winnet.Routes(windows.AF_INET)
}

// onLinkOr returns hop, or the unspecified address of dest's family when hop
// is not set, the next hop Windows uses for an on-link route.
func onLinkOr(hop netip.Addr, dest netip.Prefix) netip.Addr {
	if hop.IsValid() {
		return hop
	}
	if dest.Addr().Is6() {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

func (iphlpOps) create(r newWinRoute) error {
	err := winipcfg.LUID(r.Adapter.LUID).AddRoute(r.Dest, onLinkOr(r.NextHop, r.Dest), r.Metric)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return errWinRouteExists
	}
	return err
}

func (iphlpOps) setMetric(r winnet.Route, metric uint32) error {
	row, err := winipcfg.LUID(r.Adapter.LUID).Route(r.Dest, onLinkOr(r.NextHop, r.Dest))
	if err != nil {
		return fmt.Errorf("read route: %w", err)
	}
	row.Metric = metric
	return row.Set()
}

func (iphlpOps) remove(r winnet.Route) error {
	err := winipcfg.LUID(r.Adapter.LUID).DeleteRoute(r.Dest, onLinkOr(r.NextHop, r.Dest))
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return errWinRouteGone
	}
	return err
}
