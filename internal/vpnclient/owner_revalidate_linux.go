//go:build linux

package vpnclient

import "strconv"

// ownerStamp is unused on Linux: the tun descriptor itself proves ownership.
// It reports ok for any pid.
func ownerStamp(int) (int64, bool) { return 0, true }

// ownerStillHolds reports whether pid still has a descriptor of iface's tun
// device; it reads one process's descriptors rather than every process's.
func ownerStillHolds(pid int, _ int64, iface string) bool {
	return holdsTun("/proc/"+strconv.Itoa(pid), iface)
}
