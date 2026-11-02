//go:build linux

package ifacename

import (
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

// IsTunnelLinkType reports whether a netlink link type is a tunnel a VPN client
// owns: a tun or tap device (OpenVPN, AWS VPN Client, wireguard-go) or a kernel
// WireGuard link (wg-quick, NetworkManager). Bridge, veth, dummy and physical
// links are never VPN tunnels. The monitor and the route table classify links
// they already hold with this, so every package agrees on the kinds.
func IsTunnelLinkType(linkType string) bool {
	switch linkType {
	case "tuntap", "wireguard":
		return true
	}
	return false
}

// linkKindTTL keeps one link lookup serving the many name checks a single
// route or DNS operation makes, while a tunnel that appears or goes away is
// noticed within a second.
const linkKindTTL = time.Second

// linkKindCacheMax bounds the cache; interface names come from the kernel, but
// a host that churns containers could otherwise grow it for the life of the
// process.
const linkKindCacheMax = 256

type linkKindEntry struct {
	tunnel bool
	at     time.Time
}

var linkKindCache struct {
	sync.Mutex
	entries map[string]linkKindEntry
}

// linkIsTunnel asks the kernel (in the helper's own network namespace) whether
// the link called name is a tunnel by type. A name that is not a link, or a
// failed lookup, is not a tunnel: the name prefixes still decide.
func linkIsTunnel(name string) bool {
	now := time.Now()
	linkKindCache.Lock()
	if e, ok := linkKindCache.entries[name]; ok && now.Sub(e.at) < linkKindTTL {
		linkKindCache.Unlock()
		return e.tunnel
	}
	linkKindCache.Unlock()

	tunnel := false
	if link, err := netlink.LinkByName(name); err == nil {
		tunnel = IsTunnelLinkType(link.Type())
	}

	linkKindCache.Lock()
	if linkKindCache.entries == nil || len(linkKindCache.entries) >= linkKindCacheMax {
		linkKindCache.entries = make(map[string]linkKindEntry)
	}
	linkKindCache.entries[name] = linkKindEntry{tunnel: tunnel, at: now}
	linkKindCache.Unlock()
	return tunnel
}
