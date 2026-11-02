package vpnclient

import (
	"context"
	"os"
	"os/exec"
	"testing"
)

// lsofSample is `lsof -nP -F pn` output trimmed to the interesting records,
// in the shape captured on a Mac running the WireGuard app.
const lsofSample = `p562
f6
n[ctl com.apple.net.utun_control id 5 unit 1]
p577
f8
n[ctl com.apple.net.utun_control id 5 unit 2]
f22
n/private/var/db/something
p87151
f3
n/dev/null
f6
n[ctl com.apple.net.utun_control id 5 unit 7]
p9001
f4
n[ctl com.apple.network.statistics id 3 unit 12]
`

func TestUtunOwnersMapsControlSocketUnitsToInterfaces(t *testing.T) {
	owners := utunOwners(lsofSample)

	if owners["utun6"] != 87151 {
		t.Errorf("utun6 owner = %d, want 87151 (unit 7 is utun6)", owners["utun6"])
	}
	if owners["utun0"] != 562 || owners["utun1"] != 577 {
		t.Errorf("owners = %v, want utun0->562 and utun1->577", owners)
	}
	if _, ok := owners["utun11"]; ok {
		t.Error("a non-utun control socket must not be taken for a tunnel")
	}
}

// TestIdentifyLive identifies whatever owns the tunnels on this machine. It
// asserts nothing about which VPN is up; it only proves the tools run.
func TestIdentifyLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live identification in short mode")
	}
	client, err := Identify(context.Background(), "utun0")
	t.Logf("utun0 owner: %+v, err: %v", client, err)
}

// TestFilteredLsofFindsTheSameOwnersAsAFullScan guards the descriptor filter:
// narrowing the scan must not drop any utun control socket.
func TestFilteredLsofFindsTheSameOwnersAsAFullScan(t *testing.T) {
	if _, err := os.Stat(lsofPath); err != nil {
		t.Skip("lsof not available")
	}
	run := func(args ...string) map[string]int {
		// lsof exits non-zero when some file cannot be inspected; its output is
		// still complete for everything it could read.
		out, _ := exec.Command(lsofPath, args...).Output()
		return utunOwners(string(out))
	}
	full := run("-nP", "-F", "pn")
	filtered := run(lsofArgs...)
	for iface, pid := range full {
		if filtered[iface] != pid {
			t.Errorf("%s: filtered scan has pid %d, full scan %d", iface, filtered[iface], pid)
		}
	}
	if len(filtered) < len(full) {
		t.Errorf("filtered scan found %d owners, full scan %d", len(filtered), len(full))
	}
}
