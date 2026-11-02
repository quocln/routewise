package vpnclient

import (
	"os"
	"runtime"
	"testing"
)

func TestRevalidateWithoutARecordedOwnerIsUnknown(t *testing.T) {
	if got := Revalidate("utun-never-seen"); got != OwnerUnknown {
		t.Fatalf("Revalidate = %v, want OwnerUnknown", got)
	}
}

func TestRevalidateKnowsARecordedProcessAndForgetsADeadOne(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("a process is proven by its start time on macOS only")
	}
	const iface = "utun-revalidate-test"
	t.Cleanup(func() { ownersMu.Lock(); delete(owners, iface); ownersMu.Unlock() })

	rememberOwner(iface, os.Getpid())
	if got := Revalidate(iface); got != OwnerHolds {
		t.Fatalf("live owner: Revalidate = %v, want OwnerHolds", got)
	}

	// A different start time stands for a pid that another process reused.
	ownersMu.Lock()
	rec := owners[iface]
	rec.stamp++
	owners[iface] = rec
	ownersMu.Unlock()
	if got := Revalidate(iface); got != OwnerGone {
		t.Fatalf("reused pid: Revalidate = %v, want OwnerGone", got)
	}
	if got := Revalidate(iface); got != OwnerUnknown {
		t.Fatalf("after OwnerGone the record must be dropped; Revalidate = %v", got)
	}
}

func TestRememberOwnerIgnoresAProcessThatDoesNotExist(t *testing.T) {
	const iface = "utun-missing-pid"
	rememberOwner(iface, 1<<22+12345)
	if runtime.GOOS == "darwin" {
		if got := Revalidate(iface); got != OwnerUnknown {
			t.Fatalf("Revalidate = %v, want OwnerUnknown for a pid that does not exist", got)
		}
	}
	ownersMu.Lock()
	delete(owners, iface)
	ownersMu.Unlock()
}
