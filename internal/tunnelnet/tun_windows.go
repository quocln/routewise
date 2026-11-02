package tunnelnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/quocln/routewise/internal/winnet"
)

// wintunTunnelType is the tunnel type Wintun files the helper's adapters under,
// so they are listed apart from WireGuard's own.
const wintunTunnelType = "RouteWise"

func init() { tun.WintunTunnelType = wintunTunnelType }

// createMu keeps two tunnels from choosing the same free name.
var createMu sync.Mutex

// ifaceUpTimeout bounds how long Up waits for a new adapter to report up.
const ifaceUpTimeout = 5 * time.Second

// CreateTUN opens a new Wintun adapter named rwtunN with the given MTU. Wintun
// needs wintun.dll beside the helper's executable and administrator rights. The
// adapter has no packet header, so the packet offsets of the other platforms
// need no change. Read the name back with Name.
func CreateTUN(mtu int) (tun.Device, error) {
	createMu.Lock()
	defer createMu.Unlock()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	names := make([]string, len(ifaces))
	for i, ifc := range ifaces {
		names[i] = ifc.Name
	}
	name := freeTunName(names)
	d1, d2, d3, d4 := tunGUID(name)
	guid := windows.GUID{Data1: d1, Data2: d2, Data3: d3, Data4: d4}

	dev, err := tun.CreateTUNWithRequestedGUID(name, &guid, mtu)
	if err != nil {
		return nil, fmt.Errorf("create Wintun adapter %s (needs wintun.dll beside the helper and administrator rights): %w", name, err)
	}
	native, ok := dev.(*tun.NativeTun)
	if !ok {
		_ = dev.Close()
		return nil, fmt.Errorf("create Wintun adapter %s: unexpected device type %T", name, dev)
	}
	if err := applyMTU(winipcfg.LUID(native.LUID()), mtu); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("set MTU of %s: %w", name, err)
	}
	return dev, nil
}

// applyMTU sets the adapter's IP MTU, which Wintun leaves at its maximum; the
// device's own MTU (the ForceMTU of wireguard-go) is not the interface's. The
// IPv4 interface row can appear a moment after the adapter, so it is retried;
// IPv6 may be unbound, so its failure is ignored.
func applyMTU(luid winipcfg.LUID, mtu int) error {
	if mtu <= 0 {
		return nil
	}
	var err error
	for range 20 {
		var row *winipcfg.MibIPInterfaceRow
		if row, err = luid.IPInterface(windows.AF_INET); err == nil {
			row.NLMTU = uint32(mtu)
			if err = row.Set(); err == nil {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	if row, err := luid.IPInterface(windows.AF_INET6); err == nil {
		row.NLMTU = uint32(mtu)
		_ = row.Set()
	}
	return nil
}

// AddAlias gives the adapter named iface the address local, over the IP Helper
// API. A peer that is not local's own address gets an on-link host route, the
// route a point-to-point address implies elsewhere; see planWindowsAddress. The
// command runner is unused.
func AddAlias(_ context.Context, _ CommandRunner, iface, local, peer string) error {
	a, err := winnet.AdapterByAlias(iface)
	if err != nil {
		return fmt.Errorf("look up %s: %w", iface, err)
	}
	plan, err := planWindowsAddress(local, peer)
	if err != nil {
		return fmt.Errorf("address %s on %s: %w", local, iface, err)
	}
	luid := winipcfg.LUID(a.LUID)
	if err := luid.AddIPAddress(plan.Local); err != nil {
		return fmt.Errorf("add address %s to %s: %w", local, iface, err)
	}
	if plan.Peer.IsValid() {
		peerRoute := netPrefix32(plan.Peer)
		if err := luid.AddRoute(peerRoute, netUnspecified, 0); err != nil {
			return fmt.Errorf("add route to peer %s on %s: %w", peer, iface, err)
		}
	}
	return nil
}

// Up waits until the adapter named iface reports up. A Wintun adapter is up as
// soon as its session starts, which CreateTUN does, so this confirms the
// interface exists and is carrying traffic before routes are pointed at it.
func Up(ctx context.Context, _ CommandRunner, iface string) error {
	deadline := time.NewTimer(ifaceUpTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		a, err := winnet.AdapterByAlias(iface)
		if err != nil {
			return fmt.Errorf("look up %s: %w", iface, err)
		}
		if a.Up {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("bring %s up: %w", iface, ctx.Err())
		case <-deadline.C:
			return fmt.Errorf("bring %s up: the interface did not report up within %s", iface, ifaceUpTimeout)
		case <-tick.C:
		}
	}
}

// netUnspecified is the on-link next hop of an IPv4 route.
var netUnspecified = netip.IPv4Unspecified()

// netPrefix32 is the host prefix of an IPv4 address.
func netPrefix32(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, 32) }
