package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/quocln/routewise/internal/dnswatch"
	"github.com/quocln/routewise/internal/ledger"
	"github.com/quocln/routewise/internal/route"
)

const (
	// ipv6BlockMinTTL is the shortest time a blocked address is kept, whatever
	// the answer's TTL says: a browser that was refused once must not find the
	// address open again a few seconds later.
	ipv6BlockMinTTL = 5 * time.Minute
	// ipv6BlockCap bounds the reject routes RouteWise holds at once. Past it the
	// address that went longest without an answer is released.
	ipv6BlockCap = 1024
	// ipv6BlockSweep is how often expired blocks are looked for.
	ipv6BlockSweep = 30 * time.Second

	ipv6BlockJournalName    = "ipv6-blocked.json"
	ipv6BlockJournalVersion = 1
	ipv6BlockCommandTimeout = 15 * time.Second
)

// ipv6Journal is the on-disk record of the addresses that hold a reject route,
// so a crashed helper's leftovers are deleted at the next start.
type ipv6Journal struct {
	SchemaVersion int      `json:"schema_version"`
	Addresses     []string `json:"addresses"`
}

type blockedAddress struct {
	expires time.Time
	// seq orders addresses by how recently an answer named them; the lowest
	// is released first when the cap is reached.
	seq uint64
}

// ipv6Blocker holds the reject routes that make IPv6 unreachable for the
// addresses of listed names, so apps fall back to the IPv4 routes RouteWise
// manages. Its lock is a leaf: it is held across route commands but never
// while taking another daemon lock.
type ipv6Blocker struct {
	// allowed reports routing.allow_ipv6; nothing is blocked while it is true.
	allowed func() bool
	// table and journalPath are read at each use, because the route manager's
	// table and journal directory are settled after construction.
	table       func() route.Table
	journalPath func() string
	journal     *ledger.Ledger[ipv6Journal]
	now         func() time.Time
	logger      *slog.Logger
	// capacity is ipv6BlockCap; a field so tests can use a small one.
	capacity int

	mu      sync.Mutex
	entries map[netip.Addr]*blockedAddress
	counter uint64
	closed  bool
}

func newIPv6Blocker(allowed func() bool, table func() route.Table, journalPath func() string, logger *slog.Logger) *ipv6Blocker {
	b := &ipv6Blocker{
		allowed:     allowed,
		table:       table,
		journalPath: journalPath,
		now:         time.Now,
		logger:      logger,
		capacity:    ipv6BlockCap,
		entries:     make(map[netip.Addr]*blockedAddress),
	}
	b.journal = ledger.New[ipv6Journal](func() string { return b.journalPath() })
	return b
}

// block makes addr unreachable for ttl (at least ipv6BlockMinTTL), or extends a
// block it already holds. It does nothing while IPv6 is allowed or after
// shutdown, and refuses an address a reject route may not name.
func (b *ipv6Blocker) block(addr netip.Addr, ttl time.Duration) error {
	return b.blockAll([]netip.Addr{addr}, ttl)
}

// blockAll blocks every address of one answer like block, but writes the
// journal once for all the new ones instead of once per address: the answer is
// handled on the capture goroutine, and each write is a file replace. An
// address that cannot be blocked does not stop the others; the errors are
// joined.
func (b *ipv6Blocker) blockAll(addrs []netip.Addr, ttl time.Duration) error {
	if ttl < ipv6BlockMinTTL {
		ttl = ipv6BlockMinTTL
	}

	var errs []error
	var fresh []netip.Addr
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.allowed() {
		// Still refuse what could never be blocked, as a caller expects.
		for _, addr := range addrs {
			if err := route.ValidateBlockableIPv6(addr); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	for _, addr := range addrs {
		if err := route.ValidateBlockableIPv6(addr); err != nil {
			errs = append(errs, err)
			continue
		}
		expires := b.now().Add(ttl)
		b.counter++
		if held, ok := b.entries[addr]; ok {
			if expires.After(held.expires) {
				held.expires = expires
			}
			held.seq = b.counter
			continue
		}
		if len(b.entries) >= b.capacity {
			b.evictOldestLocked()
		}
		b.entries[addr] = &blockedAddress{expires: expires, seq: b.counter}
		fresh = append(fresh, addr)
	}
	if len(fresh) == 0 {
		return errors.Join(errs...)
	}

	// The journal names the addresses before their routes exist, so a crash
	// between the two leaves nothing the next start cannot find.
	if err := b.saveJournalLocked(); err != nil {
		for _, addr := range fresh {
			delete(b.entries, addr)
		}
		return errors.Join(append(errs, fmt.Errorf("record blocked IPv6 address: %w", err))...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipv6BlockCommandTimeout)
	defer cancel()
	failed := false
	for _, addr := range fresh {
		if err := b.table().AddIPv6Reject(ctx, addr); err != nil {
			delete(b.entries, addr)
			failed = true
			errs = append(errs, fmt.Errorf("block IPv6 address %s: %w", addr, err))
			continue
		}
		b.logger.Debug("IPv6 address blocked", "address", addr, "ttl", ttl)
	}
	if failed {
		if jerr := b.saveJournalLocked(); jerr != nil {
			b.logger.Error("IPv6 block journal not updated", "error", jerr)
		}
	}
	return errors.Join(errs...)
}

// isBlocked reports whether addr holds a reject route right now.
func (b *ipv6Blocker) isBlocked(addr netip.Addr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.entries[addr]
	return ok
}

// count returns how many addresses are blocked.
func (b *ipv6Blocker) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}

// sweep removes the blocks whose time has run out.
func (b *ipv6Blocker) sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	changed := false
	for addr, e := range b.entries {
		if now.Before(e.expires) {
			continue
		}
		if b.deleteLocked(addr) {
			changed = true
		}
	}
	if changed {
		b.persistAfterRemovalLocked()
	}
}

// removeAll deletes every reject route, when IPv6 is allowed again.
func (b *ipv6Blocker) removeAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.removeAllLocked()
}

// shutdown deletes every reject route and refuses new ones.
func (b *ipv6Blocker) shutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.removeAllLocked()
}

func (b *ipv6Blocker) removeAllLocked() {
	changed := false
	for addr := range b.entries {
		if b.deleteLocked(addr) {
			changed = true
		}
	}
	if changed {
		b.persistAfterRemovalLocked()
	}
}

// deleteLocked deletes addr's route and forgets it. A route that cannot be
// deleted stays recorded, so the journal still names it; it reports whether
// the address was forgotten.
func (b *ipv6Blocker) deleteLocked(addr netip.Addr) bool {
	ctx, cancel := context.WithTimeout(context.Background(), ipv6BlockCommandTimeout)
	defer cancel()
	if err := b.table().DeleteIPv6Reject(ctx, addr); err != nil {
		b.logger.Error("IPv6 reject route not removed", "address", addr, "error", err)
		return false
	}
	delete(b.entries, addr)
	return true
}

func (b *ipv6Blocker) evictOldestLocked() {
	var oldest netip.Addr
	var oldestSeq uint64
	for addr, e := range b.entries {
		if !oldest.IsValid() || e.seq < oldestSeq {
			oldest, oldestSeq = addr, e.seq
		}
	}
	if oldest.IsValid() && b.deleteLocked(oldest) {
		b.logger.Debug("IPv6 block released to stay under the cap", "address", oldest)
	}
}

func (b *ipv6Blocker) persistAfterRemovalLocked() {
	if err := b.saveJournalLocked(); err != nil {
		b.logger.Error("IPv6 block journal not updated", "error", err)
	}
}

// saveJournalLocked writes the blocked addresses atomically, or removes the
// journal when there are none.
func (b *ipv6Blocker) saveJournalLocked() error {
	if len(b.entries) == 0 {
		return b.journal.Remove()
	}
	j := ipv6Journal{SchemaVersion: ipv6BlockJournalVersion, Addresses: make([]string, 0, len(b.entries))}
	for addr := range b.entries {
		j.Addresses = append(j.Addresses, addr.String())
	}
	// No fsync: reject routes do not survive a reboot, so the journal only has to
	// outlive a crashed process. A forced flush costs tens of milliseconds per write,
	// on the DNS capture path.
	return b.journal.Save(j)
}

// recoverLeftovers deletes the reject routes a previous process journaled and
// did not remove, then clears the journal. A journal that cannot be trusted is
// reported and left in place; an address in it that is not blockable is skipped.
func (b *ipv6Blocker) recoverLeftovers() {
	b.mu.Lock()
	defer b.mu.Unlock()
	j, found, err := b.journal.Load()
	if err != nil || (found && j.SchemaVersion != ipv6BlockJournalVersion) {
		b.logger.Error("IPv6 block journal is not usable", "path", b.journalPath(), "error", err)
		return
	}
	if !found {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), ipv6BlockCommandTimeout)
	defer cancel()
	failed := false
	for _, text := range j.Addresses {
		addr, err := netip.ParseAddr(text)
		if err != nil || route.ValidateBlockableIPv6(addr) != nil {
			b.logger.Warn("IPv6 block journal names an address RouteWise would not block; skipped", "entry", text)
			continue
		}
		if err := b.table().DeleteIPv6Reject(ctx, addr); err != nil {
			b.logger.Error("leftover IPv6 reject route not removed", "address", addr, "error", err)
			failed = true
		}
	}
	if failed {
		return
	}
	if err := b.journal.Remove(); err != nil {
		b.logger.Error("IPv6 block journal not cleared", "path", b.journalPath(), "error", err)
	}
}

// run sweeps expired blocks until ctx ends.
func (b *ipv6Blocker) run(ctx context.Context) {
	ticker := time.NewTicker(ipv6BlockSweep)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.sweep()
		}
	}
}

// blockListedIPv6 blocks the IPv6 addresses of an answer for a name that any
// list holds, whichever client owns the list and whatever its tunnel is doing.
func (d *Daemon) blockListedIPv6(a dnswatch.Answer) {
	if d.allowIPv6.Load() || d.store == nil {
		return
	}
	var v6 []netip.Addr
	for _, ip := range a.Addresses {
		if ip.Is6() && !ip.Is4In6() {
			v6 = append(v6, ip)
		}
	}
	if len(v6) == 0 {
		return
	}
	if _, ok := d.store.Policy().matchingEntry(a.Name, netip.Addr{}); !ok {
		return
	}
	if err := d.ipv6Block.blockAll(v6, a.TTL); err != nil {
		d.logger.Warn("IPv6 addresses not blocked", "name", a.Name, "error", err)
	}
}

// applyAllowIPv6Locked switches routing.allow_ipv6 for the running daemon:
// allowing IPv6 releases every reject route at once. Blocking resumes with the
// next answer for a listed name.
func (d *Daemon) applyAllowIPv6Locked(allowed bool) {
	d.allowIPv6.Store(allowed)
	if allowed {
		d.ipv6Block.removeAll()
	}
}

// SetAllowIPv6 turns routing.allow_ipv6 on or off, saves it, and applies it
// now.
func (d *Daemon) SetAllowIPv6(allowed bool) error {
	d.mutationMu.Lock()
	defer d.mutationMu.Unlock()

	if _, err := d.store.SetAllowIPv6(allowed); err != nil {
		return classifyConfigError(err)
	}
	d.applyAllowIPv6Locked(allowed)
	d.logger.Info("routing.allow_ipv6 changed", "enabled", allowed)
	// The default VPN blocks all of IPv6 by this same setting.
	d.TriggerSync()
	return nil
}
