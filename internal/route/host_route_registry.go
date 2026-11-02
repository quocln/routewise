package route

import (
	"errors"
	"net/netip"
	"sync"
)

// ErrRouteOwnedElsewhere reports that a host route cannot be added because
// something else already holds the destination: another RouteWise manager, or
// a route in the kernel table that does not lead through this manager's
// tunnel. The kernel keeps one route per destination, so adopting it would
// let one tunnel delete the route another one relies on.
var ErrRouteOwnedElsewhere = errors.New("host route is held by something else")

// HostRouteRegistry records which manager owns each host route and each network
// route (CIDR list entry) RouteWise has added, across every manager that shares
// it. It is how one tunnel's manager
// learns that an address is already routed through another tunnel, even when
// the kernel answers `File exists` for both.
//
// Lock order: a Manager's lock, then the registry's. The registry calls
// nothing back, so it can never take part in a cycle.
type HostRouteRegistry struct {
	mu     sync.Mutex
	owners map[netip.Addr]hostRouteOwner
	// prefixOwners is the same registry for network routes: the kernel keeps
	// one route per destination and mask, so two tunnels can never both hold
	// the identical CIDR.
	prefixOwners map[netip.Prefix]hostRouteOwner
}

type hostRouteOwner struct {
	manager *Manager
	// label names the owner for error messages, captured when it claimed.
	label string
}

// NewHostRouteRegistry returns an empty registry.
func NewHostRouteRegistry() *HostRouteRegistry {
	return &HostRouteRegistry{
		owners:       make(map[netip.Addr]hostRouteOwner),
		prefixOwners: make(map[netip.Prefix]hostRouteOwner),
	}
}

// claim records m as the owner of dest. It succeeds when nobody owns dest or m
// already does; otherwise it returns the current owner's label.
func (r *HostRouteRegistry) claim(dest netip.Addr, m *Manager, label string) (heldBy string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if owner, held := r.owners[dest]; held && owner.manager != m {
		return owner.label, false
	}
	r.owners[dest] = hostRouteOwner{manager: m, label: label}
	return "", true
}

// release forgets m's claim on dest. A claim another manager holds is left
// alone.
func (r *HostRouteRegistry) release(dest netip.Addr, m *Manager) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if owner, held := r.owners[dest]; held && owner.manager == m {
		delete(r.owners, dest)
	}
}

// Owner reports the label of the manager that owns dest.
func (r *HostRouteRegistry) Owner(dest netip.Addr) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner, held := r.owners[dest]
	return owner.label, held
}

// claimPrefix records m as the owner of the network route to p, like claim.
func (r *HostRouteRegistry) claimPrefix(p netip.Prefix, m *Manager, label string) (heldBy string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if owner, held := r.prefixOwners[p]; held && owner.manager != m {
		return owner.label, false
	}
	r.prefixOwners[p] = hostRouteOwner{manager: m, label: label}
	return "", true
}

// releasePrefix forgets m's claim on p. A claim another manager holds is left
// alone.
func (r *HostRouteRegistry) releasePrefix(p netip.Prefix, m *Manager) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if owner, held := r.prefixOwners[p]; held && owner.manager == m {
		delete(r.prefixOwners, p)
	}
}

// PrefixOwner reports the label of the manager that owns the network route to p.
func (r *HostRouteRegistry) PrefixOwner(p netip.Prefix) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner, held := r.prefixOwners[p]
	return owner.label, held
}
