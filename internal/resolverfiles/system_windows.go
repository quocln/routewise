//go:build windows

package resolverfiles

import "context"

// FlushSystemCache empties the DNS client's cache, as `ipconfig /flushdns`.
func FlushSystemCache(context.Context) error {
	return flushResolverCache()
}

// DefaultDir is empty: the Name Resolution Policy Table lives in the registry,
// not in a directory of per-domain files.
const DefaultDir = ""

// NewSystem returns the split-DNS configuration of this Windows host: one
// Name Resolution Policy Table rule per forwarded domain that sends it to
// nameserver. The table carries no port, so port must be 53; any other port
// makes Apply report that.
func NewSystem(nameserver string, port int) Configurator {
	return newNRPT(registryNRPT{}, nameserver, port)
}
