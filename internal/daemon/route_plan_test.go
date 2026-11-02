package daemon

import (
	"maps"
	"net/netip"
	"testing"
)

var (
	planHigh = &tunnelSession{iface: "utun1"}
	planLow  = &tunnelSession{iface: "utun2"}
	planIP   = netip.MustParseAddr("10.0.0.1")
	planNet  = netip.MustParsePrefix("10.20.0.0/16")
)

func wantHost(domain string) map[netip.Addr]string { return map[netip.Addr]string{planIP: domain} }

func TestAnAddressNobodyHoldsGoesToTheSessionThatWantsIt(t *testing.T) {
	plans, deferred := planRoutes([]sessionRouteState{{session: planHigh, live: true, wantHosts: wantHost("a")}})
	if deferred || !maps.Equal(plans[0].firstHosts, wantHost("a")) || !maps.Equal(plans[0].hosts, wantHost("a")) {
		t.Errorf("deferred=%v plan=%+v", deferred, plans[0])
	}
}

func TestHigherPriorityWinsAndTheOtherRecordsAConflict(t *testing.T) {
	plans, _ := planRoutes([]sessionRouteState{
		{session: planHigh, live: true, wantHosts: wantHost("a"), wantNets: []netip.Prefix{planNet}},
		{session: planLow, live: true, wantHosts: wantHost("b"), wantNets: []netip.Prefix{planNet}},
	})
	if len(plans[0].hosts) != 1 || len(plans[0].nets) != 1 {
		t.Errorf("winner = %+v", plans[0])
	}
	if len(plans[1].hosts) != 0 || plans[1].hostConflicts[planIP] != planHigh {
		t.Errorf("loser hosts = %+v", plans[1])
	}
	if len(plans[1].nets) != 0 || plans[1].netConflicts[planNet] != planHigh {
		t.Errorf("loser nets = %+v", plans[1])
	}
}

func TestAnAddressAnotherSessionHoldsWaitsForTheSecondRound(t *testing.T) {
	plans, deferred := planRoutes([]sessionRouteState{
		{session: planHigh, live: true, wantHosts: wantHost("a"), wantNets: []netip.Prefix{planNet}},
		{session: planLow, live: true, heldHosts: map[netip.Addr]bool{planIP: false}, heldNets: []netip.Prefix{planNet}},
	})
	if !deferred {
		t.Error("the holder must let go first")
	}
	if len(plans[0].firstHosts) != 0 || len(plans[0].firstNets) != 0 {
		t.Errorf("first round adds what another still holds: %+v", plans[0])
	}
	if len(plans[0].hosts) != 1 || len(plans[0].nets) != 1 {
		t.Errorf("second round must add them: %+v", plans[0])
	}
	if len(plans[1].hosts) != 0 {
		t.Errorf("the holder should end up without it: %+v", plans[1])
	}
}

func TestAProtectedRouteStaysWithItsHolderEvenAgainstHigherPriority(t *testing.T) {
	plans, deferred := planRoutes([]sessionRouteState{
		{session: planHigh, live: true, wantHosts: wantHost("a")},
		{session: planLow, live: true, heldHosts: map[netip.Addr]bool{planIP: true}},
	})
	if deferred || plans[0].hostConflicts[planIP] != planLow {
		t.Errorf("deferred=%v plan=%+v, want a conflict with the holder", deferred, plans[0])
	}
}

func TestASessionThatCannotSyncKeepsWhatItHoldsAndGetsNoPlan(t *testing.T) {
	plans, _ := planRoutes([]sessionRouteState{
		{session: planHigh, live: true, wantHosts: wantHost("a"), wantNets: []netip.Prefix{planNet}},
		{session: planLow, live: false, heldHosts: map[netip.Addr]bool{planIP: false}, heldNets: []netip.Prefix{planNet}},
	})
	if len(plans) != 1 || plans[0].session != planHigh {
		t.Fatalf("plans = %+v", plans)
	}
	if plans[0].hostConflicts[planIP] != planLow || plans[0].netConflicts[planNet] != planLow {
		t.Errorf("nothing it holds may be taken: %+v", plans[0])
	}
}

func TestASessionKeepsWhatItAlreadyHolds(t *testing.T) {
	plans, deferred := planRoutes([]sessionRouteState{{
		session: planHigh, live: true, wantHosts: wantHost("a"), wantNets: []netip.Prefix{planNet},
		heldHosts: map[netip.Addr]bool{planIP: false}, heldNets: []netip.Prefix{planNet},
	}})
	if deferred || len(plans[0].firstHosts) != 1 || len(plans[0].firstNets) != 1 {
		t.Errorf("deferred=%v plan=%+v", deferred, plans[0])
	}
}
