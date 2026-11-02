package dns

import (
	"net/netip"
	"reflect"
	"testing"
)

func ips(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func windowsAdapters() []adapterDNS {
	return []adapterDNS{
		{index: 12, alias: "Ethernet", up: true, servers: ips("192.168.1.1", "8.8.8.8")},
		{index: 31, alias: "OpenVPN Data Channel Offload (2)", up: true, servers: ips("10.8.0.1", "10.8.0.2")},
		{index: 7, alias: "Wi-Fi", up: false, servers: ips("172.20.0.1")}, // disconnected
		{index: 9, alias: "vEthernet (Default Switch)", up: true},         // no servers
		{index: 40, alias: "Local: Loopback", up: true, servers: ips("127.0.0.1", "127.0.0.53")},
	}
}

func TestRenderAdapterConfigParsesIntoBlocks(t *testing.T) {
	blocks := parseResolverBlocks(renderAdapterConfig(windowsAdapters()))
	want := []resolverBlock{
		{iface: "Ethernet", servers: ips("192.168.1.1", "8.8.8.8")},
		{iface: "OpenVPN Data Channel Offload (2)", servers: ips("10.8.0.1", "10.8.0.2")},
		{iface: "Local: Loopback"}, // loopback servers never survive the parser
	}
	if !reflect.DeepEqual(blocks, want) {
		t.Errorf("blocks = %+v\nwant %+v", blocks, want)
	}
}

func TestAdapterConfigSelectsVPNServersByAlias(t *testing.T) {
	out := renderAdapterConfig(windowsAdapters())
	got, bound := SelectVPNNameservers(out, "OpenVPN Data Channel Offload (2)", FallbackOptions{})
	if !bound || !reflect.DeepEqual(got, ips("10.8.0.1", "10.8.0.2")) {
		t.Errorf("VPN servers = %v bound=%v", got, bound)
	}
	if got := ParseScutilNameservers(out, "Ethernet"); !reflect.DeepEqual(got, ips("192.168.1.1", "8.8.8.8")) {
		t.Errorf("Ethernet servers = %v", got)
	}
	if got, bound := SelectVPNNameservers(out, "Wi-Fi", FallbackOptions{}); got != nil || bound {
		t.Errorf("a disconnected adapter's servers were offered: %v", got)
	}
}

func TestAdapterConfigGuessSkipsKnownAndLocalServers(t *testing.T) {
	adapters := []adapterDNS{
		{index: 12, alias: "Ethernet", up: true, servers: ips("192.168.1.1", "10.50.0.2")},
	}
	got, bound := SelectVPNNameservers(renderAdapterConfig(adapters), "wg0", FallbackOptions{
		Enabled: true,
		IsLocal: func(a netip.Addr) bool { return a == netip.MustParseAddr("192.168.1.1") },
	})
	if bound || !reflect.DeepEqual(got, ips("10.50.0.2")) {
		t.Errorf("guess = %v bound=%v, want only the server off the local network", got, bound)
	}
}

func TestRenderAdapterConfigKeepsAnAliasOnOneLine(t *testing.T) {
	out := renderAdapterConfig([]adapterDNS{
		{index: 3, alias: "Eth\nnameserver[0] : 6.6.6.6", up: true, servers: ips("10.0.0.1")},
	})
	blocks := parseResolverBlocks(out)
	if len(blocks) != 1 || !reflect.DeepEqual(blocks[0].servers, ips("10.0.0.1")) {
		t.Errorf("an alias injected a server: %+v", blocks)
	}
}
