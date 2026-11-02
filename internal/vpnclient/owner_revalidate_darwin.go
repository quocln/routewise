//go:build darwin

package vpnclient

import "golang.org/x/sys/unix"

// ownerStamp is the process's start time in microseconds: a pid reused by
// another process has a different one. The control socket cannot be read
// without scanning descriptors, so the process being the same one that held
// it is what Revalidate can prove cheaply.
func ownerStamp(pid int) (int64, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(kp.Proc.P_pid) != pid {
		return 0, false
	}
	start := kp.Proc.P_starttime
	return start.Sec*1_000_000 + int64(start.Usec), true
}

// ownerStillHolds reports whether pid is still the process that was recorded.
func ownerStillHolds(pid int, stamp int64, _ string) bool {
	now, ok := ownerStamp(pid)
	return ok && now == stamp
}
