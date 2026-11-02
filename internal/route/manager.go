package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Manager handles route table manipulation for selective VPN routing.
// Implements "Inverted Split Tunnel" strategy:
// 1. Capture original local gateway before VPN connects
// 2. After VPN connects: replace default route with local gateway
// 3. Add /32 routes for target domains via VPN gateway
//
// The tunnel itself survives the default-route change because the VPN client
// installs its own host route to the VPN server through the local gateway.
type Manager struct {
	mu           sync.RWMutex
	state        RouteState
	activeRoutes map[netip.Addr]RouteInfo
	// netRoutes are the network routes (CIDR list entries) RouteWise holds,
	// kept apart from the host routes. Single IPs always use activeRoutes.
	netRoutes map[netip.Prefix]PrefixRouteInfo
	changes   []RouteChange
	additive  bool // additive mode: don't remove VPN catch-all routes
	// catchAll means this tunnel holds, or may still hold, the default VPN's
	// routes (see catch_all_routes.go).
	catchAll bool

	table      Table
	journal    *transactionStore
	generation func() string
	// onChange, when set, is told about every route added or removed. It runs
	// with mu held, so it must be quick and must not call back into Manager.
	onChange func(RouteChange)

	// interfaceUp reports whether a network interface exists and is up. Tests
	// replace it so compensation does not depend on the host's interfaces.
	interfaceUp func(string) bool

	// registry, when set, is shared by every manager of one daemon. A host
	// route is added only after this manager claims its destination there, so
	// two managers never both record the same /32.
	registry *HostRouteRegistry

	// pendingCleanup holds every mutation or verification RouteWise could
	// not complete or confirm. Its presence is the sole source of degraded
	// state: ownership of a route is never dropped just because a command
	// failed once.
	pendingCleanup []PendingCleanup
}

// NewManager creates a new route manager.
func NewManager() *Manager {
	return &Manager{
		activeRoutes: make(map[netip.Addr]RouteInfo),
		netRoutes:    make(map[netip.Prefix]PrefixRouteInfo),
		changes:      make([]RouteChange, 0),
		table:        systemTable(),
		journal:      &transactionStore{path: defaultJournalPath},
		generation:   defaultGenerationID,
		interfaceUp:  interfaceIsUp,
	}
}

// SetAdditiveMode configures the manager to preserve existing VPN routes.
func (m *Manager) SetAdditiveMode(additive bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.additive = additive
}

// SetHostRouteRegistry makes the manager claim every host route in r before it
// adds it. Managers that share a registry never adopt each other's routes.
func (m *Manager) SetHostRouteRegistry(r *HostRouteRegistry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry = r
}

// claimHostLocked reserves dest for this manager. The caller must hold m.mu.
func (m *Manager) claimHostLocked(dest netip.Addr) error {
	if m.registry == nil {
		return nil
	}
	if holder, ok := m.registry.claim(dest, m, m.state.VPNInterface); !ok {
		return fmt.Errorf("%s is already routed through %s: %w", dest, holder, ErrRouteOwnedElsewhere)
	}
	return nil
}

// releaseHostLocked gives up this manager's claim on dest. The caller must
// hold m.mu.
func (m *Manager) releaseHostLocked(dest netip.Addr) {
	if m.registry != nil {
		m.registry.release(dest, m)
	}
}

// claimPrefixLocked reserves the network route to p for this manager. The
// caller must hold m.mu.
func (m *Manager) claimPrefixLocked(p netip.Prefix) error {
	if m.registry == nil {
		return nil
	}
	if holder, ok := m.registry.claimPrefix(p, m, m.state.VPNInterface); !ok {
		return fmt.Errorf("%s is already routed through %s: %w", p, holder, ErrRouteOwnedElsewhere)
	}
	return nil
}

// forgetPrefixLocked drops a network route whose kernel entry is gone and
// releases its claim. The caller must hold m.mu.
func (m *Manager) forgetPrefixLocked(p netip.Prefix) {
	delete(m.netRoutes, p)
	if m.registry != nil {
		m.registry.releasePrefix(p, m)
	}
}

// forgetRouteLocked drops a route whose kernel entry is gone. The caller must
// hold m.mu.
func (m *Manager) forgetRouteLocked(dest netip.Addr) {
	delete(m.activeRoutes, dest)
	m.releaseHostLocked(dest)
}

// SetInterfaceProbe replaces how the manager asks whether a tunnel interface
// exists and is up, which compensation checks before it restores a route to
// that tunnel. Only tests use it, so results do not depend on the host's
// interfaces.
func (m *Manager) SetInterfaceProbe(up func(string) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interfaceUp = up
}

// SetTable replaces the routing table the manager reads and mutates, so a
// per-tunnel manager can share its parent's.
func (m *Manager) SetTable(t Table) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.table = t
}

// Table returns the routing table the manager uses.
func (m *Manager) Table() Table {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.table
}

// Additive reports whether the manager preserves existing VPN routes.
func (m *Manager) Additive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.additive
}

// JournalPath returns where the manager persists its transition journal.
func (m *Manager) JournalPath() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.journal.path
}

// SetOriginalGateway seeds the LAN gateway and interface that traffic returns
// to when the tunnel's catch-all routes are taken away. A manager that serves
// one tunnel of several takes these from the manager that captured them
// before any VPN connected.
func (m *Manager) SetOriginalGateway(gateway netip.Addr, iface string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.OriginalLocalGateway = gateway
	m.state.LocalInterface = iface
}

// GetRoute returns the route RouteWise holds for dest, if any.
func (m *Manager) GetRoute(dest netip.Addr) (RouteInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, ok := m.activeRoutes[dest]
	return info, ok
}

// RoutedFor reports whether RouteWise routes dest through the tunnel, and
// for which domain or list entry: its host route, or failing that the longest
// network route that contains it.
func (m *Manager) RoutedFor(dest netip.Addr) (string, bool) {
	source, _, ok := m.RouteMatch(dest)
	return source, ok
}

// RouteMatch is RoutedFor with the length of the matching route: 32 for a host
// route, the prefix length for a network route. Across tunnels the longest
// match is the one the kernel uses.
func (m *Manager) RouteMatch(dest netip.Addr) (source string, bits int, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if info, held := m.activeRoutes[dest]; held {
		return info.SourceDomain, dest.BitLen(), true
	}
	bits = -1
	for p, info := range m.netRoutes {
		if p.Contains(dest) && p.Bits() > bits {
			source, bits = info.SourceEntry, p.Bits()
		}
	}
	return source, bits, bits >= 0
}

// SetChangeObserver registers fn to be told about every route RouteWise adds
// or removes. fn runs with the manager's lock held, so it must be quick and
// must not call back into the manager.
func (m *Manager) SetChangeObserver(fn func(RouteChange)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = fn
}

// LookupRoute asks the kernel which interface and gateway traffic to dest
// leaves through right now.
func (m *Manager) LookupRoute(dest netip.Addr) (iface string, gateway netip.Addr, err error) {
	m.mu.RLock()
	table := m.table
	m.mu.RUnlock()
	return table.Lookup(context.Background(), dest)
}

// SetJournalPath overrides where the transition journal is persisted.
// Production always uses defaultJournalPath, which requires root; callers
// that need to exercise journaling and recovery without root (or without
// touching /var/run) point this at a temporary path instead.
func (m *Manager) SetJournalPath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.journal = &transactionStore{path: path}
}

// CaptureOriginalGateway saves the LAN gateway that traffic returns to when
// the tunnel's catch-all routes are taken away. It also works while a VPN that
// owns the global default route is already connected.
func (m *Manager) CaptureOriginalGateway() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	gw, iface, err := m.table.LocalGateway(context.Background(), m.state.LocalInterface)
	if err != nil {
		return fmt.Errorf("capture original gateway: %w", err)
	}

	m.state.OriginalLocalGateway = gw
	m.state.LocalInterface = iface
	return nil
}

// SetVPNState records the gateway and interface of the tunnel routes go through.
func (m *Manager) SetVPNState(vpnGateway netip.Addr, vpnInterface string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.state.VPNGateway = vpnGateway
	m.state.VPNInterface = vpnInterface
}

// GetOriginalGateway returns the captured original local gateway.
func (m *Manager) GetOriginalGateway() netip.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.OriginalLocalGateway
}

// GetLocalInterface returns the LAN interface traffic returns to.
func (m *Manager) GetLocalInterface() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.LocalInterface
}

// GetVPNGateway returns the VPN gateway address.
func (m *Manager) GetVPNGateway() netip.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.VPNGateway
}

// GetVPNInterface returns the configured VPN interface.
func (m *Manager) GetVPNInterface() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.VPNInterface
}

// Degraded reports whether any route mutation or verification is
// outstanding, along with a human-readable summary. Phase 5 surfaces this
// over RPC; today it is the only way to observe a partially failed
// activation, deactivation, cleanup, or recovery.
func (m *Manager) Degraded() (bool, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.degradedLocked()
}

func (m *Manager) degradedLocked() (bool, string) {
	if len(m.pendingCleanup) == 0 {
		return false, ""
	}
	reason := fmt.Sprintf("%d route action(s) require attention:", len(m.pendingCleanup))
	for _, p := range m.pendingCleanup {
		reason += fmt.Sprintf(" [%s dest=%s gw=%s iface=%s at=%s: %s]",
			p.Kind, p.Destination, p.Gateway, p.Interface, p.FailedAt.Format(time.RFC3339), p.Reason)
	}
	return true, reason
}

// PendingCleanup returns a copy of every outstanding remediation item.
func (m *Manager) PendingCleanup() []PendingCleanup {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]PendingCleanup, len(m.pendingCleanup))
	copy(out, m.pendingCleanup)
	return out
}

// addPendingOnceLocked records item unless the same kind of action on the same
// destination is already outstanding, so a failure repeated at every sync does
// not pile up copies.
func (m *Manager) addPendingOnceLocked(item PendingCleanup) {
	for _, p := range m.pendingCleanup {
		if p.Kind == item.Kind && p.Destination == item.Destination {
			return
		}
	}
	m.addPendingLocked(item)
}

func (m *Manager) addPendingLocked(item PendingCleanup) {
	if item.FailedAt.IsZero() {
		item.FailedAt = time.Now()
	}
	m.pendingCleanup = append(m.pendingCleanup, item)
}

// RetryPendingCleanup re-attempts every outstanding item and drops the ones
// that now succeed. It returns an aggregated error describing whatever is
// still pending after the attempt, or nil if the manager is fully healthy.
func (m *Manager) RetryPendingCleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.pendingCleanup) == 0 {
		return nil
	}

	ctx := context.Background()
	var remaining []PendingCleanup
	var errs []error
	for _, item := range m.pendingCleanup {
		if err := m.retryPendingItemLocked(ctx, item); err != nil {
			item.Reason = err.Error()
			item.FailedAt = time.Now()
			remaining = append(remaining, item)
			errs = append(errs, fmt.Errorf("%s %s: %w", item.Kind, item.Destination, err))
		}
	}
	m.pendingCleanup = remaining
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (m *Manager) retryPendingItemLocked(ctx context.Context, item PendingCleanup) error {
	switch item.Kind {
	case "delete_route":
		dest, err := netip.ParseAddr(item.Destination)
		if err != nil {
			return m.table.DeleteNet(ctx, item.Destination, item.Gateway, item.Interface)
		}
		return m.table.DeleteHost(ctx, dest)
	case "restore_route":
		return m.restoreSplitRouteLocked(ctx, item.Destination, item.Gateway, item.Interface)
	case "restore_default":
		return m.restoreDefaultLocked(ctx, item.Gateway, item.Interface)
	case "delete_rule":
		priority, err := strconv.Atoi(item.Destination)
		if err != nil {
			return fmt.Errorf("parse rule priority %q: %w", item.Destination, err)
		}
		return m.deleteMainLookupRuleLocked(ctx, priority)
	case "verify", "journal", "generation_mismatch":
		// Purely informational; nothing to replay. Clearing requires
		// investigation, so leave it recorded until an operator resolves it
		// through other means (e.g. a fresh activation).
		return fmt.Errorf("requires manual resolution")
	default:
		return fmt.Errorf("unknown pending cleanup kind %q", item.Kind)
	}
}

// ActivateInvertedSplitTunnel implements the inverted split tunnel logic.
// This replaces the VPN's default route with the original local gateway,
// effectively making all traffic go direct except for explicitly routed IPs.
//
// Every mutation is journaled before it is applied and after it completes,
// so a crash mid-activation leaves a transition that RecoverTransition can
// compensate on the next start.
func (m *Manager) ActivateInvertedSplitTunnel() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.state.OriginalLocalGateway.IsValid() {
		return fmt.Errorf("original gateway not captured, call CaptureOriginalGateway first")
	}
	if m.state.VPNInterface != "" {
		if err := ValidateInterfaceName(m.state.VPNInterface); err != nil {
			return fmt.Errorf("activate: %w", err)
		}
	}

	ctx := context.Background()
	entries, err := m.table.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshot route table before activation: %w", err)
	}

	tx := &transaction{
		SchemaVersion: transactionSchemaVersion,
		GenerationID:  m.generation(),
		Phase:         phaseActivating,
		PreState:      buildPreState(entries, m.state),
		CreatedAt:     time.Now().UTC(),
	}
	if err := m.journal.save(tx); err != nil {
		return fmt.Errorf("persist transition journal: %w", err)
	}
	m.state.Activated = true

	// Step 1: remove only the VPN's 0/1 and 128/1 routes that are
	// actually owned by the interface/gateway we are activating.
	deleted, delErr := m.removeOwnedSplitTunnelRoutesLocked(ctx, entries)
	for _, d := range deleted {
		tx.Steps = append(tx.Steps, journalStep{
			Kind:        stepDeleteRoute,
			Destination: d.Destination,
			Gateway:     d.Gateway,
			Interface:   d.Interface,
			Existed:     true,
		})
	}
	if len(deleted) > 0 {
		if err := m.journal.save(tx); err != nil {
			return m.failActivationLocked(fmt.Errorf("persist transition journal: %w", err))
		}
	}
	if delErr != nil {
		return m.failActivationLocked(fmt.Errorf("remove VPN split tunnel routes: %w", delErr))
	}

	// Step 2: replace default route with original local gateway. A VPN
	// client that owns the global default (NetworkExtension, or OpenVPN
	// without def1) loses it here; one using the /1 pair never had it.
	//
	// The default is changed, and the change journaled, only while it leads
	// into the tunnel being activated. A default that already points at the
	// LAN needs no change, and one held by a different tunnel belongs to
	// another VPN, which RouteWise must not move. Journaling a change that
	// moved nothing would make compensation order-dependent when several
	// tunnels are managed: a later restore could take the default back from a
	// VPN whose own journal gave it back correctly.
	priorGW, priorIface, priorErr := m.table.Default(ctx)
	if priorErr == nil && m.ownsDefaultLocked(priorGW, priorIface) {
		if err := m.table.ChangeDefault(ctx, m.state.OriginalLocalGateway); err != nil {
			return m.failActivationLocked(fmt.Errorf("replace default route: %w", err))
		}
		m.state.DefaultRouteModified = true
		step := journalStep{
			Kind:           stepChangeDefault,
			Gateway:        m.state.OriginalLocalGateway.String(),
			PriorInterface: priorIface,
		}
		if priorGW.IsValid() {
			step.PriorGateway = priorGW.String()
		}
		tx.Steps = append(tx.Steps, step)
	}

	// Step 3: a VPN that policy-routes all traffic into a table of its own
	// ignores the main default, so unlisted traffic needs a rule ahead of the
	// VPN's to reach it.
	if err := m.addMainLookupRuleLocked(ctx, tx); err != nil {
		return m.failActivationLocked(err)
	}
	tx.Phase = phaseActive
	if err := m.journal.save(tx); err != nil {
		return m.failActivationLocked(fmt.Errorf("persist transition journal: %w", err))
	}

	if err := m.verifyActivatedLocked(ctx); err != nil {
		return err
	}
	return nil
}

// addMainLookupRuleLocked adds the main-table lookup rule when the tunnel's
// traffic is policy-routed (see policyRuleTable). The step is journaled before
// the rule is added, because deleting a rule that was never added is harmless
// and a crash in between must not leave one behind that nothing records.
func (m *Manager) addMainLookupRuleLocked(ctx context.Context, tx *transaction) error {
	rules, ok := m.table.(policyRuleTable)
	if !ok || m.state.VPNInterface == "" {
		return nil
	}
	priority, found, err := rules.MainLookupPriority(ctx, m.state.VPNInterface)
	if err != nil {
		return fmt.Errorf("find the tunnel's policy rule: %w", err)
	}
	if !found {
		return nil
	}
	tx.Steps = append(tx.Steps, journalStep{Kind: stepAddRule, Priority: priority, Interface: m.state.VPNInterface})
	if err := m.journal.save(tx); err != nil {
		return fmt.Errorf("persist transition journal: %w", err)
	}
	if err := rules.AddMainLookupRule(ctx, priority); err != nil {
		return fmt.Errorf("route unlisted traffic past the tunnel's policy rule: %w", err)
	}
	return nil
}

func (m *Manager) failActivationLocked(err error) error {
	m.addPendingLocked(PendingCleanup{Kind: "verify", Reason: fmt.Sprintf("activation failed: %v", err)})
	return err
}

// verifyActivatedLocked re-reads the kernel route table after activation and
// confirms it matches intent, recording a degraded pending-cleanup item
// (rather than assuming success) on any mismatch.
func (m *Manager) verifyActivatedLocked(ctx context.Context) error {
	entries, err := m.table.Snapshot(ctx)
	if err != nil {
		m.addPendingLocked(PendingCleanup{Kind: "verify", Reason: fmt.Sprintf("post-activation snapshot failed: %v", err)})
		return fmt.Errorf("verify activation: %w", err)
	}

	var problems []string

	if m.state.DefaultRouteModified {
		currentGW, err := m.table.DefaultGateway(ctx)
		if err != nil || currentGW != m.state.OriginalLocalGateway {
			problems = append(problems, fmt.Sprintf("default gateway is %s, want %s", currentGW, m.state.OriginalLocalGateway))
		}
	}

	for _, e := range findSplitTunnelRoutes(entries) {
		if m.ownsSplitTunnelRoute(e) {
			problems = append(problems, fmt.Sprintf("split tunnel route %s still owned by our interface/gateway after activation", e.Destination))
		}
	}

	if len(problems) == 0 {
		return nil
	}
	reason := fmt.Sprintf("post-activation verification failed: %v", problems)
	m.addPendingLocked(PendingCleanup{Kind: "verify", Reason: reason})
	return fmt.Errorf("%s", reason)
}

// ownsSplitTunnelRoute reports whether entry (a 0/1 or 128/1 route) matches
// the interface and gateway RouteWise is activating for.
func (m *Manager) ownsSplitTunnelRoute(entry RouteEntry) bool {
	if m.state.VPNInterface != "" && entry.Interface == m.state.VPNInterface {
		return true
	}
	if m.state.VPNGateway.IsValid() && sameGateway(entry.Gateway, m.state.VPNGateway.String()) {
		return true
	}
	return false
}

// removeOwnedSplitTunnelRoutesLocked deletes only the 0/1 and 128/1 routes
// that belong to the AWS interface/gateway being activated. Any split
// tunnel route belonging to a different interface or gateway (e.g. another
// VPN client's own catch-all routes) is left untouched and never even
// attempted.
func (m *Manager) removeOwnedSplitTunnelRoutesLocked(ctx context.Context, entries []RouteEntry) ([]RouteEntry, error) {
	var deleted []RouteEntry
	var errs []error
	for _, e := range findSplitTunnelRoutes(entries) {
		if !m.ownsSplitTunnelRoute(e) {
			continue
		}
		if err := m.table.DeleteNet(ctx, e.Destination, e.Gateway, e.Interface); err != nil {
			m.addPendingLocked(PendingCleanup{
				Kind:        "delete_route",
				Destination: e.Destination,
				Gateway:     e.Gateway,
				Interface:   e.Interface,
				Reason:      err.Error(),
			})
			errs = append(errs, fmt.Errorf("delete %s: %w", e.Destination, err))
			continue
		}
		deleted = append(deleted, e)
	}
	if len(errs) > 0 {
		return deleted, errors.Join(errs...)
	}
	return deleted, nil
}

// buildPreState captures the exact state of every route RouteWise is about
// to touch, for audit independent of the step log.
func buildPreState(entries []RouteEntry, state RouteState) []routeSnapshot {
	var out []routeSnapshot
	for _, dest := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		for _, e := range entries {
			if canon, ok := canonicalSplitTunnelDest(e.Destination); ok && canon == dest {
				out = append(out, routeSnapshot{
					Destination: e.Destination,
					Gateway:     e.Gateway,
					Interface:   e.Interface,
					Flags:       e.Flags,
					Existed:     true,
				})
			}
		}
	}
	out = append(out, snapshotOf(entries, "default"))
	return out
}

func snapshotOf(entries []RouteEntry, dest string) routeSnapshot {
	if e, ok := findRoute(entries, dest); ok {
		return routeSnapshot{Destination: e.Destination, Gateway: e.Gateway, Interface: e.Interface, Flags: e.Flags, Existed: true}
	}
	return routeSnapshot{Destination: dest, Existed: false}
}

// EnforceSplitTunnel removes any VPN catch-all routes that might have been
// re-added, scoped to the interface/gateway RouteWise owns, and moves the
// default route back to the LAN if the VPN client took it again.
func (m *Manager) EnforceSplitTunnel() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx := context.Background()
	entries, err := m.table.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshot route table: %w", err)
	}
	_, removeErr := m.removeOwnedSplitTunnelRoutesLocked(ctx, entries)
	return errors.Join(removeErr, m.reclaimDefaultRouteLocked(ctx))
}

// ReclaimDefaultRoute moves the default route back to the LAN if the managed
// VPN took it again, for example after a network change or wake from sleep.
// The daemon calls it for as long as the VPN stays connected.
func (m *Manager) ReclaimDefaultRoute() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reclaimDefaultRouteLocked(context.Background())
}

// ownsDefaultLocked reports whether a default route with this gateway and
// interface leads into the tunnel the manager serves.
func (m *Manager) ownsDefaultLocked(gw netip.Addr, iface string) bool {
	return (m.state.VPNInterface != "" && iface == m.state.VPNInterface) ||
		(m.state.VPNGateway.IsValid() && gw == m.state.VPNGateway)
}

// reclaimDefaultRouteLocked points the default route back at the LAN gateway
// when, after activation, it leads into the tunnel RouteWise manages again.
// The LAN gateway is read afresh, because the user may have changed networks
// since activation. Only `route change` is used: deleting the VPN's default
// and then failing to add the LAN one would leave no default route at all.
func (m *Manager) reclaimDefaultRouteLocked(ctx context.Context) error {
	if !m.state.DefaultRouteModified {
		return nil
	}
	gw, iface, err := m.table.Default(ctx)
	if err != nil {
		return nil // no global default to reclaim
	}
	if !m.ownsDefaultLocked(gw, iface) {
		return nil
	}
	lanGW, lanIface, err := m.table.LocalGateway(ctx, m.state.LocalInterface)
	if err != nil {
		return fmt.Errorf("reclaim default route: %w", err)
	}
	if err := m.table.ReplaceDefault(ctx, lanGW); err != nil {
		return fmt.Errorf("reclaim default route: %w", err)
	}
	m.state.OriginalLocalGateway = lanGW
	m.state.LocalInterface = lanIface
	return nil
}

// DeactivateInvertedSplitTunnel restores the original routing state by
// compensating the journaled activation transaction in reverse. If the active
// journal is missing or unreadable, exact restoration cannot be proven and the
// manager fails closed without guessing at kernel state.
func (m *Manager) DeactivateInvertedSplitTunnel() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.state.Activated {
		return nil // Nothing to restore
	}

	ctx := context.Background()
	tx, ok, err := m.journal.load()
	if err != nil {
		reason := fmt.Sprintf("transition journal unreadable during deactivation: %v", err)
		m.addPendingLocked(PendingCleanup{Kind: "journal", Reason: reason})
		return fmt.Errorf("%s", reason)
	}
	if !ok {
		reason := "active route mutation has no transition journal; exact restoration cannot be proven"
		m.addPendingLocked(PendingCleanup{Kind: "journal", Reason: reason})
		// Preserve the fail-closed state across process restart. This sentinel
		// deliberately contains no guessed compensation steps: recovery must
		// keep the daemon degraded until an operator restores and verifies the
		// route table.
		sentinel := &transaction{
			SchemaVersion: transactionSchemaVersion,
			GenerationID:  m.generation(),
			Phase:         phaseUnrecoverable,
			FailureReason: reason,
			CreatedAt:     time.Now().UTC(),
		}
		if saveErr := m.journal.save(sentinel); saveErr != nil {
			return fmt.Errorf("%s; persist degraded sentinel: %w", reason, saveErr)
		}
		return fmt.Errorf("%s", reason)
	}

	tx.Phase = phaseCompensating
	if err := m.journal.save(tx); err != nil {
		m.addPendingLocked(PendingCleanup{
			Kind:   "journal",
			Reason: fmt.Sprintf("could not persist compensating journal: %v", err),
		})
		return fmt.Errorf("persist transition journal: %w", err)
	}

	if err := m.compensateLocked(ctx, tx); err != nil {
		return err
	}

	m.state.DefaultRouteModified = false
	m.state.Activated = false
	return nil
}

// compensateLocked replays tx.Steps in reverse. Steps that fail to
// compensate are kept in tx (so a retry only replays what is still
// outstanding) and recorded as pending cleanup; steps that succeed are
// dropped from the journal. Compensation is idempotent: every underlying
// route operation treats "already in the desired state" as success, so
// running it twice is safe.
func (m *Manager) compensateLocked(ctx context.Context, tx *transaction) error {
	var remaining []journalStep
	var errs []error
	for i := len(tx.Steps) - 1; i >= 0; i-- {
		step := tx.Steps[i]
		if err := m.compensateStepLocked(ctx, step); err != nil {
			remaining = append([]journalStep{step}, remaining...)
			errs = append(errs, err)
			m.addPendingLocked(pendingFromStep(step, err))
			continue
		}
	}
	tx.Steps = remaining

	if len(remaining) == 0 {
		tx.Phase = phaseComplete
		if err := m.journal.remove(); err != nil {
			errs = append(errs, fmt.Errorf("remove transition journal: %w", err))
		}
	} else if err := m.journal.save(tx); err != nil {
		errs = append(errs, fmt.Errorf("persist transition journal: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("compensation incomplete: %w", errors.Join(errs...))
	}
	return nil
}

func (m *Manager) compensateStepLocked(ctx context.Context, step journalStep) error {
	switch step.Kind {
	case stepChangeDefault:
		return m.restoreDefaultLocked(ctx, step.PriorGateway, step.PriorInterface)

	case stepDeleteRoute:
		return m.restoreSplitRouteLocked(ctx, step.Destination, step.Gateway, step.Interface)

	case stepAddRoute:
		if step.Existed {
			return nil // predates RouteWise; not ours to remove
		}
		dest, err := netip.ParseAddr(step.Destination)
		if err != nil {
			return fmt.Errorf("remove added route: parse destination %q: %w", step.Destination, err)
		}
		if err := m.table.DeleteHost(ctx, dest); err != nil {
			return fmt.Errorf("remove added route %s: %w", step.Destination, err)
		}
		m.forgetRouteLocked(dest)
		return nil

	case stepAddRule:
		return m.deleteMainLookupRuleLocked(ctx, step.Priority)

	default:
		return fmt.Errorf("unknown journal step kind %q", step.Kind)
	}
}

// isTunnelLocked reports whether iface is a tunnel: the one the manager serves
// is by definition, whatever it is called, and any other by the interface's
// kind (its name alone misses `dev corp0` or a connection-named device).
func (m *Manager) isTunnelLocked(iface string) bool {
	return (iface != "" && iface == m.state.VPNInterface) || isTunnelInterface(iface)
}

// deleteMainLookupRuleLocked removes the rule addMainLookupRuleLocked added.
func (m *Manager) deleteMainLookupRuleLocked(ctx context.Context, priority int) error {
	rules, ok := m.table.(policyRuleTable)
	if !ok {
		return nil
	}
	return rules.DeleteMainLookupRule(ctx, priority)
}

// restoreDefaultLocked gives the default route back to what held it before
// activation, and never leaves the system without one: it only ever uses
// `route change`, never delete-then-add, so a failure keeps whatever default
// exists.
//
// Compensation is conservative about whose default it moves:
//   - A default that belonged to a tunnel is returned only while that tunnel
//     exists, and only when the default is not already there or held by a
//     different tunnel (which belongs to another VPN).
//   - A LAN default is restored only while the current default leads into a
//     tunnel. When it is already a LAN default there is nothing to give back,
//     and a gateway recorded on another network is not forced onto the table.
func (m *Manager) restoreDefaultLocked(ctx context.Context, priorGateway, priorIface string) error {
	if priorGateway == (netip.Addr{}).String() {
		priorGateway = "" // older journals wrote an unknown gateway as "invalid IP"
	}
	_, curIface, curErr := m.table.Default(ctx)
	if m.isTunnelLocked(priorIface) {
		if !m.interfaceUp(priorIface) {
			return nil
		}
		if curErr == nil && m.isTunnelLocked(curIface) {
			return nil // already on this tunnel, or held by another VPN's tunnel
		}
		if priorGateway == "" {
			if err := m.table.ChangeDefaultToInterface(ctx, priorIface); err != nil {
				return fmt.Errorf("restore default route to %s: %w", priorIface, err)
			}
			return nil
		}
	} else if curErr == nil && !m.isTunnelLocked(curIface) {
		return nil // the default already leads to a LAN
	}
	if priorGateway == "" {
		return nil
	}
	gw, err := netip.ParseAddr(priorGateway)
	if err != nil {
		return fmt.Errorf("restore default route: parse prior gateway %q: %w", priorGateway, err)
	}
	if err := m.table.ChangeDefaultStrict(ctx, gw); err != nil {
		if m.table.IsUnreachable(err) {
			// The gateway belongs to a network this machine has left. Keep the
			// default macOS chose rather than fail a restore nothing can honor.
			return nil
		}
		return fmt.Errorf("restore default route to %s: %w", gw, err)
	}
	return nil
}

// restoreSplitRouteLocked gives a removed 0/1 or 128/1 route back to its
// tunnel. A tunnel that is gone needs nothing back. wg-quick's routes point at
// the interface, and the kernel prints that gateway as the interface name or
// link#N, which `route add` rejects, so such routes go back with -interface.
func (m *Manager) restoreSplitRouteLocked(ctx context.Context, dest, gateway, iface string) error {
	if m.isTunnelLocked(iface) && !m.interfaceUp(iface) {
		return nil
	}
	if _, err := netip.ParseAddr(gateway); err != nil {
		gateway = ""
	}
	if err := m.table.AddNet(ctx, dest, gateway, iface); err != nil {
		return fmt.Errorf("restore split tunnel route %s: %w", dest, err)
	}
	return nil
}

func pendingFromStep(step journalStep, err error) PendingCleanup {
	switch step.Kind {
	case stepChangeDefault:
		return PendingCleanup{Kind: "restore_default", Gateway: step.PriorGateway, Interface: step.PriorInterface, Reason: err.Error()}
	case stepDeleteRoute:
		return PendingCleanup{Kind: "restore_route", Destination: step.Destination, Gateway: step.Gateway, Interface: step.Interface, Reason: err.Error()}
	case stepAddRoute:
		return PendingCleanup{Kind: "delete_route", Destination: step.Destination, Gateway: step.Gateway, Reason: err.Error()}
	case stepAddRule:
		return PendingCleanup{Kind: "delete_rule", Destination: strconv.Itoa(step.Priority), Interface: step.Interface, Reason: err.Error()}
	default:
		return PendingCleanup{Kind: "unknown", Destination: step.Destination, Reason: err.Error()}
	}
}

// RecoverTransition compensates any transition journal left behind by a
// previous process (crash, kill, or unclean shutdown) before the monitor or any
// route loop starts. The journal is always compensated, never resumed:
// resuming would require re-validating kernel state a crashed process last
// observed, which cannot be done safely from a cold start.
func (m *Manager) RecoverTransition() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tx, ok, err := m.journal.load()
	if err != nil {
		m.addPendingLocked(PendingCleanup{Kind: "journal", Reason: fmt.Sprintf("could not read transition journal: %v", err)})
		return fmt.Errorf("recover transition: %w", err)
	}
	if !ok {
		return nil
	}
	if tx.Phase == phaseUnrecoverable {
		reason := tx.FailureReason
		if reason == "" {
			reason = "route ownership was marked unrecoverable by a previous process"
		}
		m.addPendingLocked(PendingCleanup{Kind: "journal", Reason: reason})
		return fmt.Errorf("recover transition: %s", reason)
	}

	ctx := context.Background()
	tx.Phase = phaseCompensating
	if err := m.journal.save(tx); err != nil {
		return fmt.Errorf("persist transition journal: %w", err)
	}

	if err := m.compensateLocked(ctx, tx); err != nil {
		return fmt.Errorf("recover transition: %w", err)
	}

	m.state.DefaultRouteModified = false
	m.state.Activated = false
	return nil
}

// isRoutableIP returns false for IPs that should never be routed via VPN.
func isRoutableIP(addr netip.Addr) bool {
	if addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return false
	}
	if addr.IsUnspecified() {
		return false
	}
	return true
}

// AddRoute adds a /32 route for a specific IP via the VPN gateway and records
// the domain it was resolved from. A protected route (such as one to a VPN DNS
// server) is kept by SyncRoutes even when no configured domain resolves to it;
// only Cleanup removes it.
func (m *Manager) AddRoute(dest netip.Addr, sourceDomain string, protected bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.state.VPNGateway.IsValid() && m.state.VPNInterface == "" {
		return fmt.Errorf("VPN gateway or interface not set")
	}

	// Some VPNs (Outline) serve DNS on a link-local address that is answered
	// inside the tunnel. Only such a protected VPN DNS route may be link-local;
	// a domain's answer never is.
	linkLocalDNS := protected && dest.Is4() && dest.IsLinkLocalUnicast()
	if !isRoutableIP(dest) && !linkLocalDNS {
		return fmt.Errorf("refusing to route non-routable IP: %s", dest)
	}

	if info, exists := m.activeRoutes[dest]; exists {
		// Already routed; a protected request upgrades the existing entry so
		// a later domain sync cannot remove a route a DNS server depends on.
		if protected && !info.IsProtected {
			info.IsProtected = true
			m.activeRoutes[dest] = info
		}
		return nil
	}

	if err := m.claimHostLocked(dest); err != nil {
		return err
	}
	if linkLocalDNS {
		// The LAN's 169.254/16 route sends these queries out the Wi-Fi or
		// Ethernet interface, and the kernel may already hold a link-layer
		// entry cloned from it for this address, which blocks the host route.
		m.table.DropClonedLinkLayer(context.Background(), dest)
	}
	if err := m.table.AddHost(context.Background(), dest, m.state.VPNGateway, m.state.VPNInterface); err != nil {
		m.releaseHostLocked(dest)
		return err
	}

	m.activeRoutes[dest] = RouteInfo{
		Destination:  dest,
		Gateway:      m.state.VPNGateway,
		Interface:    m.state.VPNInterface,
		SourceDomain: sourceDomain,
		AddedAt:      time.Now(),
		IsProtected:  protected,
	}
	m.recordChange(RouteAdded, dest, m.state.VPNGateway, sourceDomain)

	return nil
}

// RemoveRoute removes a previously added route.
func (m *Manager) RemoveRoute(dest netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, exists := m.activeRoutes[dest]
	if !exists {
		return nil // Already removed
	}

	if info.IsProtected {
		return fmt.Errorf("cannot remove protected route %s", dest)
	}

	if err := m.table.DeleteHost(context.Background(), dest); err != nil {
		return err
	}

	m.forgetRouteLocked(dest)
	m.recordChange(RouteRemoved, dest, netip.Addr{}, info.SourceDomain)

	return nil
}

// RemoveRouteIfSource removes the route to dest only while it is still the
// unprotected route recorded for sourceDomain. A route another domain or a VPN
// DNS server now relies on is left in place.
func (m *Manager) RemoveRouteIfSource(dest netip.Addr, sourceDomain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, exists := m.activeRoutes[dest]
	if !exists || info.IsProtected || info.SourceDomain != sourceDomain {
		return nil
	}
	if err := m.table.DeleteHost(context.Background(), dest); err != nil {
		m.addPendingLocked(PendingCleanup{Kind: "delete_route", Destination: dest.String(), Gateway: info.Gateway.String(), Reason: err.Error()})
		return err
	}
	m.forgetRouteLocked(dest)
	m.recordChange(RouteRemoved, dest, netip.Addr{}, info.SourceDomain)
	return nil
}

// RemoveProtectedRoute removes a protected route while it is still recorded
// for sourceDomain. It retires VPN DNS servers that were only guessed once the
// VPN publishes its real ones.
func (m *Manager) RemoveProtectedRoute(dest netip.Addr, sourceDomain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, exists := m.activeRoutes[dest]
	if !exists || !info.IsProtected || info.SourceDomain != sourceDomain {
		return nil
	}
	if err := m.table.DeleteHost(context.Background(), dest); err != nil {
		m.addPendingLocked(PendingCleanup{Kind: "delete_route", Destination: dest.String(), Gateway: info.Gateway.String(), Reason: err.Error()})
		return err
	}
	m.forgetRouteLocked(dest)
	m.recordChange(RouteRemoved, dest, netip.Addr{}, info.SourceDomain)
	return nil
}

// SyncRoutes synchronizes the routing table with the desired set of IPs.
// Takes a map of IP -> SourceDomain.
func (m *Manager) SyncRoutes(desired map[netip.Addr]string) error {
	_, err := m.SyncRoutesWithin(desired, 0)
	return err
}

// SyncRoutesWithin is SyncRoutes that gives up the manager's lock after budget:
// once it has run for that long it starts no further route change and reports
// more, and the caller calls it again with the same set to continue. Where a
// change is one process start (macOS), a first sync of hundreds of routes would
// otherwise hold the lock for seconds, and every DNS answer that needs a route
// would wait behind it. Each call makes at least one change, and more is only
// reported when the call changed something: changes that keep failing are not
// retried in a loop. A budget of zero or less means no limit, and more is then
// always false.
func (m *Manager) SyncRoutesWithin(desired map[netip.Addr]string, budget time.Duration) (more bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.state.VPNGateway.IsValid() && m.state.VPNInterface == "" {
		return false, fmt.Errorf("VPN gateway or interface not set")
	}

	ctx := context.Background()
	defer m.BeginRouteBatch()()
	var deadline time.Time
	if budget > 0 {
		deadline = time.Now().Add(budget)
	}
	attempts, changed := 0, 0
	// outOfTime is asked before each route change; the first one always runs.
	outOfTime := func() bool {
		attempts++
		return attempts > 1 && !deadline.IsZero() && time.Now().After(deadline)
	}

	// In inverted mode, continuously remove owned VPN catch-all routes (the
	// VPN client may re-add them). In additive mode, preserve them so other
	// VPN clients can handle their own routing.
	if !m.additive {
		entries, err := m.table.Snapshot(ctx)
		if err != nil {
			// A failed read is transient and the sweep repeats at every sync
			// and enforcer pass, so it is not a pending item: one would never
			// clear and would stop all routing for the session.
			slog.Warn("route sync could not read the routing table; skipping the catch-all route sweep", "error", err)
		} else if _, err := m.removeOwnedSplitTunnelRoutesLocked(ctx, entries); err != nil {
			// Already recorded per-route in removeOwnedSplitTunnelRoutesLocked.
			_ = err
		}
	}

	// Remove routes not in desired set (skip protected routes). A route whose
	// delete failed stays recorded: the kernel entry is still there, so no
	// other manager may take the address until the delete is retried.
	for ip, info := range m.activeRoutes {
		if info.IsProtected {
			continue
		}
		if _, keep := desired[ip]; !keep {
			if outOfTime() {
				return changed > 0, nil
			}
			if err := m.table.DeleteHost(ctx, ip); err != nil {
				m.addPendingOnceLocked(PendingCleanup{Kind: "delete_route", Destination: ip.String(), Gateway: info.Gateway.String(), Reason: err.Error()})
				continue
			}
			changed++
			m.forgetRouteLocked(ip)
			m.recordChange(RouteRemoved, ip, netip.Addr{}, info.SourceDomain)
		}
	}

	// Add missing routes. An address another manager or the kernel already
	// holds for a different tunnel is reported, not adopted, and does not
	// degrade this manager: the route is intact, just not ours.
	var conflicts []error
	for ip, domain := range desired {
		if !isRoutableIP(ip) {
			continue
		}
		if info, exists := m.activeRoutes[ip]; exists {
			if info.SourceDomain != domain {
				info.SourceDomain = domain
				m.activeRoutes[ip] = info
			}
			continue
		}
		if outOfTime() {
			more = changed > 0
			break
		}
		if err := m.claimHostLocked(ip); err != nil {
			conflicts = append(conflicts, err)
			continue
		}
		if err := m.table.AddHost(ctx, ip, m.state.VPNGateway, m.state.VPNInterface); err != nil {
			m.releaseHostLocked(ip)
			if errors.Is(err, ErrRouteOwnedElsewhere) {
				conflicts = append(conflicts, err)
				continue
			}
			m.addPendingOnceLocked(PendingCleanup{Kind: "restore_route", Destination: ip.String(), Gateway: m.state.VPNGateway.String(), Interface: m.state.VPNInterface, Reason: err.Error()})
			continue
		}
		changed++
		m.activeRoutes[ip] = RouteInfo{
			Destination:  ip,
			Gateway:      m.state.VPNGateway,
			Interface:    m.state.VPNInterface,
			SourceDomain: domain,
			AddedAt:      time.Now(),
			IsProtected:  false,
		}
		m.recordChange(RouteAdded, ip, m.state.VPNGateway, domain)
	}

	return more, errors.Join(conflicts...)
}

// Cleanup removes all managed routes and restores original state. Routes
// that fail to delete are kept in activeRoutes and recorded as pending
// cleanup, never silently dropped from RouteWise's ownership.
func (m *Manager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx := context.Background()
	var errs []error
	defer m.BeginRouteBatch()()

	deleteAll := func(protected bool) {
		for ip, info := range m.activeRoutes {
			if info.IsProtected != protected {
				continue
			}
			if err := m.table.DeleteHost(ctx, ip); err != nil {
				m.addPendingLocked(PendingCleanup{Kind: "delete_route", Destination: ip.String(), Gateway: info.Gateway.String(), Reason: err.Error()})
				errs = append(errs, fmt.Errorf("remove %s: %w", ip, err))
				continue
			}
			m.forgetRouteLocked(ip)
		}
	}
	deleteAll(false)
	deleteAll(true)
	for p, info := range m.netRoutes {
		if err := m.table.DeleteNet(ctx, p.String(), info.Gateway.String(), info.Interface); err != nil {
			m.addPendingOnceLocked(PendingCleanup{Kind: "delete_route", Destination: p.String(), Gateway: info.Gateway.String(), Interface: info.Interface, Reason: err.Error()})
			errs = append(errs, fmt.Errorf("remove %s: %w", p, err))
			continue
		}
		m.forgetPrefixLocked(p)
		m.recordPrefixChange(RouteRemoved, p, netip.Addr{}, info.SourceEntry)
	}

	m.state.DefaultRouteModified = false
	m.state.Activated = false

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %w", errors.Join(errs...))
	}
	return nil
}

// GetActiveRoutes returns a copy of currently managed routes.
func (m *Manager) GetActiveRoutes() map[netip.Addr]RouteInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	routes := make(map[netip.Addr]RouteInfo, len(m.activeRoutes))
	for k, v := range m.activeRoutes {
		routes[k] = v
	}
	return routes
}

// GetNetRoutes returns a copy of the managed network routes.
func (m *Manager) GetNetRoutes() map[netip.Prefix]PrefixRouteInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	routes := make(map[netip.Prefix]PrefixRouteInfo, len(m.netRoutes))
	for k, v := range m.netRoutes {
		routes[k] = v
	}
	return routes
}

// GetRouteCount returns the number of managed routes, host and network.
func (m *Manager) GetRouteCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.activeRoutes) + len(m.netRoutes)
}

// HasGatewayChanged checks if the current default gateway differs from stored.
// Returns true if gateway changed, false otherwise.
func (m *Manager) HasGatewayChanged() bool {
	m.mu.RLock()
	storedGW := m.state.OriginalLocalGateway
	table := m.table
	m.mu.RUnlock()

	if !storedGW.IsValid() {
		return false // No stored gateway to compare
	}

	currentGW, _, err := table.LocalGateway(context.Background(), m.GetLocalInterface())
	if err != nil {
		return false // Can't determine, assume no change
	}

	return currentGW != storedGW
}

// RefreshGateway updates the stored gateway if it has changed.
// Returns true if gateway was refreshed, false if unchanged.
func (m *Manager) RefreshGateway() (bool, error) {
	m.mu.RLock()
	table := m.table
	m.mu.RUnlock()

	currentGW, currentIface, err := table.LocalGateway(context.Background(), m.GetLocalInterface())
	if err != nil {
		return false, fmt.Errorf("get current gateway: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.LocalInterface = currentIface

	if currentGW == m.state.OriginalLocalGateway {
		return false, nil // No change
	}

	oldGW := m.state.OriginalLocalGateway
	m.state.OriginalLocalGateway = currentGW

	if m.state.DefaultRouteModified {
		if err := m.table.ChangeDefault(context.Background(), currentGW); err != nil {
			m.state.OriginalLocalGateway = oldGW
			return false, fmt.Errorf("update default route: %w", err)
		}
	}

	return true, nil
}

// GetRecentChanges returns recent route changes for logging/audit.
func (m *Manager) GetRecentChanges(limit int) []RouteChange {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.changes) {
		limit = len(m.changes)
	}

	start := len(m.changes) - limit
	if start < 0 {
		start = 0
	}

	result := make([]RouteChange, limit)
	copy(result, m.changes[start:])
	return result
}

func (m *Manager) recordChange(typ RouteChangeType, dest, gateway netip.Addr, domain string) {
	change := RouteChange{
		Type:        typ,
		Destination: dest,
		Gateway:     gateway,
		Domain:      domain,
		Interface:   m.state.VPNInterface,
		Timestamp:   time.Now(),
	}
	m.changes = append(m.changes, change)
	if m.onChange != nil {
		m.onChange(change)
	}

	if len(m.changes) > 100 {
		m.changes = m.changes[len(m.changes)-100:]
	}
}

// recordPrefixChange is recordChange for a network route.
func (m *Manager) recordPrefixChange(typ RouteChangeType, prefix netip.Prefix, gateway netip.Addr, entry string) {
	change := RouteChange{
		Type:      typ,
		Prefix:    prefix,
		Gateway:   gateway,
		Domain:    entry,
		Interface: m.state.VPNInterface,
		Timestamp: time.Now(),
	}
	m.changes = append(m.changes, change)
	if m.onChange != nil {
		m.onChange(change)
	}

	if len(m.changes) > 100 {
		m.changes = m.changes[len(m.changes)-100:]
	}
}
