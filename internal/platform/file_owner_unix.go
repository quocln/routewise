//go:build unix

package platform

import (
	"os"
	"syscall"
)

// FileOwnerUID returns the uid that owns the file info describes. It reports
// false when the platform does not expose an owner.
func FileOwnerUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
