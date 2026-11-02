//go:build !darwin && !linux

package vpnclient

// Neither Windows nor other systems record an owning process: Windows names a
// client through its adapter and caches that itself.
func ownerStamp(int) (int64, bool) { return 0, false }

func ownerStillHolds(int, int64, string) bool { return false }
