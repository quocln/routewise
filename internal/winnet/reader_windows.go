//go:build windows

package winnet

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Adapters lists every interface with its IPv4 interface metric.
func Adapters() ([]Adapter, error) { return adaptersFor(windows.AF_INET) }

// adaptersFor lists every interface with the interface metric of one address
// family, which is what a route of that family adds to its own metric.
func adaptersFor(family winipcfg.AddressFamily) ([]Adapter, error) {
	rows, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormalWithoutStatistics)
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	ipifs, err := winipcfg.GetIPInterfaceTable(family)
	if err != nil {
		return nil, fmt.Errorf("list interface metrics: %w", err)
	}
	metrics := make(map[winipcfg.LUID]uint32, len(ipifs))
	for _, r := range ipifs {
		metrics[r.InterfaceLUID] = r.Metric
	}
	out := make([]Adapter, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, Adapter{
			Index:       r.InterfaceIndex,
			LUID:        uint64(r.InterfaceLUID),
			GUID:        r.InterfaceGUID.String(),
			Alias:       r.Alias(),
			Description: r.Description(),
			IfType:      uint32(r.Type),
			TunnelType:  uint32(r.TunnelType),
			Up:          r.OperStatus == winipcfg.IfOperStatusUp,
			Metric:      metrics[r.InterfaceLUID],
		})
	}
	return out, nil
}

// AdapterByAlias finds the interface whose friendly name is alias, ignoring
// case as Windows does.
func AdapterByAlias(alias string) (Adapter, error) {
	adapters, err := Adapters()
	if err != nil {
		return Adapter{}, err
	}
	for _, a := range adapters {
		if strings.EqualFold(a.Alias, alias) {
			return a, nil
		}
	}
	return Adapter{}, fmt.Errorf("interface %q not found", alias)
}

// Routes reads the routing table of one address family (windows.AF_INET or
// windows.AF_INET6), each route with its adapter. Routes whose adapter has
// vanished since the table was read are dropped.
func Routes(family winipcfg.AddressFamily) ([]Route, error) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil, fmt.Errorf("read route table: %w", err)
	}
	adapters, err := adaptersFor(family)
	if err != nil {
		return nil, err
	}
	byLUID := make(map[uint64]Adapter, len(adapters))
	for _, a := range adapters {
		byLUID[a.LUID] = a
	}
	out := make([]Route, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		a, ok := byLUID[uint64(r.InterfaceLUID)]
		if !ok {
			continue
		}
		out = append(out, Route{
			Adapter:  a,
			Dest:     r.DestinationPrefix.Prefix(),
			NextHop:  r.NextHop.Addr(),
			Metric:   r.Metric,
			Protocol: uint32(r.Protocol),
		})
	}
	return out, nil
}
