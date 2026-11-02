package daemon

import (
	"cmp"
	"slices"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/quocln/routewise/internal/route"
)

// sessionRegistry holds the connected managed tunnels and the managers whose
// teardown could not be completed. Its lock is a leaf: hold it only to read or
// change the registry itself, release it before calling into a manager, the
// store, or anything else. Adding and removing a session is also serialized by
// the daemon's mutationMu, which the registry does not know about.
type sessionRegistry struct {
	mu sync.RWMutex
	// sessions are the connected tunnels, keyed by interface.
	sessions map[string]*tunnelSession
	// retired holds managers whose teardown could not be completed or
	// confirmed, and managers whose leftover journal could not be recovered at
	// start. They keep ownership of what they could not undo, count as degraded,
	// and are retried once more at Stop.
	retired []*route.Manager
	// seq numbers sessions in registration order, the order their split tunnels
	// were activated.
	seq uint64
	// version changes whenever the set of sessions does.
	version atomic.Uint64
	// view is the priority-ordered list of sessions as of one registry version
	// and one allowlist order; it is rebuilt only when either changes.
	view atomic.Pointer[orderedSessions]
}

// orderedSessions is an immutable priority-ordered view of the sessions.
type orderedSessions struct {
	version   uint64
	rankEpoch uint64
	sessions  []*tunnelSession
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{sessions: make(map[string]*tunnelSession)}
}

// get returns the session for iface, or nil.
func (r *sessionRegistry) get(iface string) *tunnelSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[iface]
}

// isRegistered reports whether s is still a live session.
func (r *sessionRegistry) isRegistered(s *tunnelSession) bool {
	return s != nil && r.get(s.iface) == s
}

// has reports whether any tunnel is being managed.
func (r *sessionRegistry) has() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions) > 0
}

// hasDetected reports whether any session belongs to a tunnel RouteWise
// detected, as opposed to one it owns.
func (r *sessionRegistry) hasDetected() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sessions {
		if !s.owned {
			return true
		}
	}
	return false
}

// add registers s and numbers it. The caller must hold mutationMu.
func (r *sessionRegistry) add(s *tunnelSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	s.seq = r.seq
	r.sessions[s.iface] = s
	r.version.Add(1)
}

// remove unregisters s. The caller must hold mutationMu.
func (r *sessionRegistry) remove(s *tunnelSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[s.iface] == s {
		delete(r.sessions, s.iface)
		r.version.Add(1)
	}
}

// takeAll unregisters every session and returns them newest first: the reverse
// of the order their split tunnels were activated, which is the order
// compensation must run in so each restore sees the state its own activation
// left. The caller must hold mutationMu.
func (r *sessionRegistry) takeAll() []*tunnelSession {
	r.mu.Lock()
	out := make([]*tunnelSession, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	r.sessions = make(map[string]*tunnelSession)
	r.version.Add(1)
	r.mu.Unlock()
	slices.SortFunc(out, func(a, b *tunnelSession) int { return cmp.Compare(b.seq, a.seq) })
	return out
}

// ordered returns the connected sessions, highest priority first. Priority is
// the order of the allowlist; a tunnel whose client is not on it (only possible
// when the allowlist changed under a live tunnel) ranks last, and ties break by
// interface name. The result is shared and must not be modified; it is rebuilt
// only when a session is added or removed or the allowlist order changes.
func (r *sessionRegistry) ordered(pol *routingPolicy) []*tunnelSession {
	// The version is read before the sessions, so a view built from newer
	// sessions is at worst rebuilt once more, never served for a stale version.
	version := r.version.Load()
	if v := r.view.Load(); v != nil && v.version == version && v.rankEpoch == pol.rankEpoch {
		return v.sessions
	}

	r.mu.RLock()
	out := make([]*tunnelSession, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	r.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		ri, rj := pol.clientRank(out[i].client.ID), pol.clientRank(out[j].client.ID)
		if ri != rj {
			return ri < rj
		}
		return out[i].iface < out[j].iface
	})
	// Capacity is capped so an append by a caller copies instead of writing into
	// the shared view.
	out = out[:len(out):len(out)]
	r.view.Store(&orderedSessions{version: version, rankEpoch: pol.rankEpoch, sessions: out})
	return out
}

// retire keeps m so what it could not undo stays visible and is retried.
func (r *sessionRegistry) retire(m *route.Manager) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.retired = append(r.retired, m)
}

// takeRetired hands over and forgets the retired managers.
func (r *sessionRegistry) takeRetired() []*route.Manager {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.retired
	r.retired = nil
	return out
}

// retiredManagers returns the retired managers without forgetting them.
func (r *sessionRegistry) retiredManagers() []*route.Manager {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.retired)
}
