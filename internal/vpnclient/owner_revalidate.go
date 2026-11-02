package vpnclient

import "sync"

// OwnerState is the answer of Revalidate.
type OwnerState int

const (
	// OwnerUnknown means no owning process was recorded for the interface, or
	// this OS cannot re-check one: the caller has to identify again.
	OwnerUnknown OwnerState = iota
	// OwnerHolds means the process Identify found still owns the interface.
	OwnerHolds
	// OwnerGone means that process ended or no longer holds the interface.
	OwnerGone
)

// ownerRecord is the process Identify last found for an interface. stamp tells
// that process apart from a later one that reuses its pid; its meaning is
// per-OS (see ownerStamp).
type ownerRecord struct {
	pid   int
	stamp int64
}

var (
	ownersMu sync.Mutex
	owners   = map[string]ownerRecord{} // by interface name
)

// rememberOwner records the process that owns iface so Revalidate can confirm
// it later without scanning every process. One entry per interface name
// exists, so the map stays as small as the machine's tunnel list.
func rememberOwner(iface string, pid int) {
	stamp, ok := ownerStamp(pid)
	ownersMu.Lock()
	defer ownersMu.Unlock()
	if !ok {
		delete(owners, iface)
		return
	}
	owners[iface] = ownerRecord{pid: pid, stamp: stamp}
}

// Revalidate checks the single process Identify last found for iface instead of
// scanning every process: a scan costs seconds of CPU on macOS and hundreds of
// milliseconds on a busy Linux host, while this reads one process. A process
// that is gone is forgotten, so the next call reports OwnerUnknown.
func Revalidate(iface string) OwnerState {
	ownersMu.Lock()
	rec, ok := owners[iface]
	ownersMu.Unlock()
	if !ok {
		return OwnerUnknown
	}
	if ownerStillHolds(rec.pid, rec.stamp, iface) {
		return OwnerHolds
	}
	ownersMu.Lock()
	if owners[iface] == rec {
		delete(owners, iface)
	}
	ownersMu.Unlock()
	return OwnerGone
}
