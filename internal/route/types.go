// Package route manages macOS routing table for selective VPN routing.
package route

import (
	"net/netip"
	"time"
)

// RouteInfo stores information about a managed route.
type RouteInfo struct {
	Destination  netip.Addr
	Gateway      netip.Addr
	Interface    string
	SourceDomain string // Domain that resolved to this IP
	AddedAt      time.Time
	IsProtected  bool // Routes domain sync must not remove (VPN DNS servers)
}

// PrefixRouteInfo stores information about a managed network route, one a
// CIDR list entry asked for.
type PrefixRouteInfo struct {
	Prefix  netip.Prefix
	Gateway netip.Addr
	// Interface is the tunnel the route goes through.
	Interface string
	// SourceEntry is the list entry (the CIDR as configured) the route serves.
	SourceEntry string
	AddedAt     time.Time
}

// RouteState tracks the current routing state for restoration.
type RouteState struct {
	OriginalLocalGateway netip.Addr // Gateway before VPN connected
	VPNGateway           netip.Addr // Gateway for VPN traffic (utun)
	VPNInterface         string     // Interface name for VPN traffic (utunX)
	DefaultRouteModified bool       // Whether we replaced default route
	// Activated is true from the moment an activation journals its first
	// step until the journal is compensated, so deactivation undoes the
	// tunnel routes it removed even when the default was never touched.
	Activated bool
	// LocalInterface is the LAN interface that last held the global default
	// while no VPN owned it. With Wi-Fi and Ethernet both up under a VPN,
	// its interface-scoped default is the one RouteWise returns traffic to.
	LocalInterface string
}

// RouteChange represents a route modification operation.
type RouteChange struct {
	Type RouteChangeType
	// Destination is the address of a host route. It is the zero Addr for a
	// network route, which sets Prefix instead.
	Destination netip.Addr
	// Prefix is the destination of a network route, and invalid for a host
	// route.
	Prefix  netip.Prefix
	Gateway netip.Addr
	// Domain is the pattern or label the route serves, such as a configured
	// domain or CIDR entry, or "VPN DNS".
	Domain string
	// Interface is the tunnel the route goes through.
	Interface string
	Timestamp time.Time
}

// RouteChangeType indicates the type of route change.
type RouteChangeType int

const (
	RouteAdded RouteChangeType = iota
	RouteRemoved
	RouteUpdated
)

func (t RouteChangeType) String() string {
	switch t {
	case RouteAdded:
		return "added"
	case RouteRemoved:
		return "removed"
	case RouteUpdated:
		return "updated"
	default:
		return "unknown"
	}
}

// RouteEntry represents a route as read from the kernel routing table via
// netstat. Fields are kept as the kernel prints them (not parsed into
// netip.Addr) because destinations like "default" or "0/1" are not always
// valid addresses.
type RouteEntry struct {
	Destination string
	Gateway     string
	Flags       string
	Interface   string
}

// PendingCleanup records a route mutation or verification that RouteWise
// could not complete or confirm. Ownership of the affected route is never
// discarded: the item stays visible via Manager.Degraded until a retry
// resolves it or an operator intervenes.
type PendingCleanup struct {
	// Kind identifies what kind of remediation is outstanding, e.g.
	// "delete_route", "restore_route", "restore_default", "verify", or
	// "journal" for a journal that could not be read at all.
	Kind        string
	Destination string
	Gateway     string
	Interface   string
	Reason      string
	FailedAt    time.Time
}
