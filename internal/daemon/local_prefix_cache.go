package daemon

import (
	"net/netip"
	"sync"
	"time"
)

// localPrefixTTL is how long the interface subnets are reused. Every wildcard
// answer builds a LAN guard, and enumerating interfaces costs one OS query per
// interface (several milliseconds on a machine with many virtual adapters),
// all of it on the DNS reply path. A subnet change takes this long to show up
// in the guard.
const localPrefixTTL = 2 * time.Second

// localPrefixCache memoises an interface subnet reader for localPrefixTTL.
type localPrefixCache struct {
	read func() []netip.Prefix
	now  func() time.Time

	mu       sync.Mutex
	at       time.Time
	prefixes []netip.Prefix
}

// get returns the cached subnets, reading them again when they are older than
// localPrefixTTL. The returned slice is shared and must not be modified.
func (c *localPrefixCache) get() []netip.Prefix {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !c.at.IsZero() && now.Sub(c.at) < localPrefixTTL {
		return c.prefixes
	}
	c.prefixes = c.read()
	c.at = now
	return c.prefixes
}

// lanPrefixes is the production reader behind the daemon's localPrefixes hook.
var lanPrefixes = &localPrefixCache{read: localInterfacePrefixes, now: time.Now}
