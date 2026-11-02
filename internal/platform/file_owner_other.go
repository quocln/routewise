//go:build !unix

package platform

import "os"

// FileOwnerUID reports false: this platform has no numeric file owner.
func FileOwnerUID(os.FileInfo) (uint32, bool) { return 0, false }
