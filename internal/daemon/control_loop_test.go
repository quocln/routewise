package daemon

import (
	"testing"
	"time"
)

// manualControl is inverted with the control loop's timer out of the way, so a test
// decides when checks run.
func manualControl(k *fakeKernel) func(*Daemon) {
	return func(d *Daemon) {
		inverted(k)(d)
		d.hooks.controlEvery = time.Hour
	}
}

func addClientPair(t *testing.T, k *fakeKernel, gateway, iface string) {
	t.Helper()
	k.putNet("0/1", gateway, iface)
	k.putNet("128.0/1", gateway, iface)
}

// A client that re-adds its routes loses them at the next check that is due, and not
// before: right after connecting that is soon, later on less often.
func TestEnforcementPacesItselfAndSweepsWhatAClientReAdds(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, manualControl(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectAWS()
	s := waitForSession(t, d, awsIface)
	waitFor(t, "enforcement to begin", func() bool { return s.enforcingSince.Load() != nil })
	gen := d.currentGeneration()

	since := time.Now()
	s.enforcingSince.Store(&since)
	s.nextEnforce = since

	addClientPair(t, k, awsGW, awsIface)
	d.enforceDueSessions(gen, since)
	if len(k.netRoutes()) != 0 {
		t.Fatalf("routes = %v, want the client's pair swept", k.netRoutes())
	}

	addClientPair(t, k, awsGW, awsIface)
	d.enforceDueSessions(gen, since.Add(enforceBurstEvery-time.Millisecond))
	if len(k.netRoutes()) != 2 {
		t.Fatal("a check ran before it was due")
	}
	d.enforceDueSessions(gen, since.Add(enforceBurstEvery))
	if len(k.netRoutes()) != 0 {
		t.Fatalf("routes = %v, want the burst check to sweep them", k.netRoutes())
	}

	// Past the burst it slows down.
	late := since.Add(enforceBurst)
	s.nextEnforce = late
	d.enforceDueSessions(gen, late)
	addClientPair(t, k, awsGW, awsIface)
	d.enforceDueSessions(gen, late.Add(enforceBurstEvery))
	if len(k.netRoutes()) != 2 {
		t.Fatal("past the burst, a check ran at the burst's pace")
	}
	d.enforceDueSessions(gen, late.Add(enforceEvery))
	if len(k.netRoutes()) != 0 {
		t.Fatalf("routes = %v, want the slow check to sweep them", k.netRoutes())
	}
}

// A built-in tunnel has no catch-all routes to enforce.
func TestASessionWithoutEnforcementIsLeftAlone(t *testing.T) {
	k := lanDefaultKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	id := e.importOutline(t, "Travel", "198.51.100.7")
	iface := e.connect(t, id)
	s := waitForSession(t, e.d, iface)
	if s.enforcingSince.Load() != nil {
		t.Fatal("a built-in tunnel must not be enforced")
	}
	mark := len(k.log())
	e.d.enforceDueSessions(e.d.currentGeneration(), time.Now())
	if calls := k.log()[mark:]; len(calls) != 0 {
		t.Errorf("ran %v for a tunnel with no enforcement", calls)
	}
}

// A tunnel gone from the monitor is not touched: its routes may already belong to
// whatever reused the interface name.
func TestATunnelTheMonitorNoLongerSeesIsNotEnforced(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, manualControl(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectAWS()
	s := waitForSession(t, d, awsIface)
	waitFor(t, "enforcement to begin", func() bool { return s.enforcingSince.Load() != nil })
	gen := d.currentGeneration()

	env.w.setDisconnected(awsIface)
	addClientPair(t, k, awsGW, awsIface)
	d.enforceSession(gen, s, time.Minute)
	if len(k.netRoutes()) != 2 {
		t.Errorf("routes = %v, a tunnel that is gone must be left alone", k.netRoutes())
	}
}
