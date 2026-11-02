package dns

import (
	"context"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// systemDNSConfig returns the DNS servers every adapter holds, in the `scutil
// --dns` format parseResolverBlocks reads. VPN clients publish their servers on
// their own adapter: the AWS VPN Client and OpenVPN on the TAP or DCO adapter,
// WireGuard on its tunnel adapter.
func systemDNSConfig(context.Context) (string, error) {
	adapters, err := adaptersDNS()
	if err != nil {
		return "", err
	}
	return renderAdapterConfig(adapters), nil
}

// adaptersDNS reads the IPv4 DNS servers of every adapter.
func adaptersDNS() ([]adapterDNS, error) {
	flags := winipcfg.GAAFlagSkipUnicast | winipcfg.GAAFlagSkipAnycast | winipcfg.GAAFlagSkipMulticast
	addrs, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, flags)
	if err != nil {
		return nil, fmt.Errorf("read adapter DNS servers: %w", err)
	}
	out := make([]adapterDNS, 0, len(addrs))
	for _, a := range addrs {
		if a.IfType == winipcfg.IfTypeSoftwareLoopback {
			continue
		}
		adapter := adapterDNS{
			index: int(a.IfIndex),
			alias: a.FriendlyName(),
			up:    a.OperStatus == winipcfg.IfOperStatusUp,
		}
		for s := a.FirstDNSServerAddress; s != nil; s = s.Next {
			if addr, ok := netip.AddrFromSlice(s.Address.IP()); ok {
				adapter.servers = append(adapter.servers, addr.Unmap())
			}
		}
		out = append(out, adapter)
	}
	return out, nil
}
