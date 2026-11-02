package vpnclient

import (
	"sync"
	"time"

	"github.com/quocln/routewise/internal/winnet"
)

// identityCacheTTL bounds how long an owner is trusted without a fresh process
// scan. The daemon asks about every unmanaged tunnel every few seconds, and a
// scan opens every client process; an adapter keeps its owner for as long as
// the same adapter stays up, so the answer is reused until the adapter changes
// or this much time passes (a different client may take over a persistent
// adapter).
const identityCacheTTL = 30 * time.Second

type identityEntry struct {
	index  uint32
	alias  string
	client Client
	at     time.Time
}

var (
	identityMu    sync.Mutex
	identityCache = map[uint64]identityEntry{} // by interface LUID
)

// cachedIdentity returns the owner remembered for a while it is still the same
// adapter: same LUID, interface index and name, and still up.
func cachedIdentity(a winnet.Adapter) (Client, bool) {
	identityMu.Lock()
	defer identityMu.Unlock()
	e, ok := identityCache[a.LUID]
	if !ok || !a.Up || e.index != a.Index || e.alias != a.Alias || time.Since(e.at) >= identityCacheTTL {
		delete(identityCache, a.LUID)
		return Client{}, false
	}
	return e.client, true
}

// rememberIdentity records a successful identification of a.
func rememberIdentity(a winnet.Adapter, c Client) {
	identityMu.Lock()
	defer identityMu.Unlock()
	identityCache[a.LUID] = identityEntry{index: a.Index, alias: a.Alias, client: c, at: time.Now()}
}
