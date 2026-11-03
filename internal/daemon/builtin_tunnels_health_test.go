package daemon

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/proxyclient"
)

// --- the health rules, without a daemon ---

func TestHandshakeCheckStaysHealthyUpTo180SecondsOld(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := []struct {
		name    string
		last    time.Time
		ok      bool
		wantErr bool
		pending bool
	}{
		{"no handshake yet", time.Time{}, false, true, true},
		{"just now", now, true, false, false},
		{"rekey window", now.Add(-120 * time.Second), true, false, false},
		{"exactly 180 s", now.Add(-180 * time.Second), true, false, false},
		{"181 s", now.Add(-181 * time.Second), true, true, false},
		{"an hour", now.Add(-time.Hour), true, true, false},
	}
	for _, c := range cases {
		err := checkHandshake(c.last, c.ok, now)
		if (err != nil) != c.wantErr || errors.Is(err, errNotProvenYet) != c.pending {
			t.Errorf("%s: err = %v, want error %v, not-proven-yet %v", c.name, err, c.wantErr, c.pending)
		}
	}
}

func TestHealthTrackerBelievesAProxysRefusalAtOnce(t *testing.T) {
	for _, kind := range []string{config.ProfileKindSOCKS5, config.ProfileKindHTTP} {
		tr := newHealthTracker(healthPolicyFor(kind))
		if !tr.observe(proxyclient.ErrAuthRefused) || tr.state != healthDown {
			t.Errorf("%s: a refused login must show on the first check", kind)
		}
		// Silence may be a blip, so it still takes the policy's count.
		quiet := newHealthTracker(healthPolicyFor(kind))
		if quiet.observe(errors.New("the proxy did not answer")) || quiet.state != healthConnecting {
			t.Errorf("%s: one silent check must not change a connecting tunnel", kind)
		}
	}
}

func TestHealthTrackerAppliesHysteresis(t *testing.T) {
	probeFail := errors.New("no answer")
	tr := newHealthTracker(healthPolicyFor("outline"))
	if tr.state != healthConnecting {
		t.Fatal("a new tracker is connecting")
	}
	// Two failures from connecting are not enough; the third is.
	if tr.observe(probeFail) || tr.observe(probeFail) || tr.state != healthConnecting {
		t.Fatal("two failures must not change a connecting tunnel")
	}
	if !tr.observe(probeFail) || tr.state != healthDown {
		t.Fatal("the third consecutive failure must make it unhealthy")
	}
	if tr.observe(probeFail) {
		t.Error("further failures are not a change")
	}
	// One success makes it healthy at once.
	if !tr.observe(nil) || tr.state != healthUp {
		t.Fatal("one success must make it healthy")
	}
	// A success resets the count: fail, fail, ok, fail, fail stays up.
	for _, err := range []error{probeFail, probeFail, nil, probeFail, probeFail} {
		if tr.observe(err) {
			t.Fatal("a healthy tunnel must ride out short blips")
		}
	}
	if !tr.observe(probeFail) || tr.state != healthDown {
		t.Error("three in a row after the reset must go down")
	}

	// WireGuard: the 180 s window is the hysteresis, so one stale check is enough,
	// but "no handshake yet" is not a failure and keeps it connecting.
	wg := newHealthTracker(healthPolicyFor("wireguard"))
	pending := fmt.Errorf("%w: waiting", errNotProvenYet)
	if wg.observe(pending) || wg.observe(pending) || wg.state != healthConnecting {
		t.Error("no handshake yet must keep WireGuard connecting, however long")
	}
	if !wg.observe(nil) || wg.state != healthUp {
		t.Error("a handshake makes it healthy")
	}
	if !wg.observe(errors.New("stale")) || wg.state != healthDown {
		t.Error("a stale handshake must go unhealthy at once")
	}
	if got := healthPolicyFor("outline"); got.interval != 30*time.Second || got.failures != 3 {
		t.Errorf("outline policy = %+v, want every 30 s and 3 failures", got)
	}
}

// --- health drives routing ---

func TestWireGuardHoldsItsListWhileConnectingThenGoesDirectUntilItsFirstHandshake(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.starter.onStart = func(_ tunnelStartRequest, tn *fakeTunnel) { tn.setHandshake(time.Time{}, false) }
	d := e.d

	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	e.setList(t, id, "10.60.0.5")
	iface := e.connect(t, id)
	e.armed(t, 1)

	// Connecting: the list already routes into the tunnel, so a connection
	// made now waits for the handshake instead of going direct for good.
	if st := e.profileState(id); st.State != api.ProfileConnecting {
		t.Fatalf("state before the first handshake = %q, want connecting", st.State)
	}
	waitHost(t, k, "10.60.0.5", iface)
	if s := d.sessions.get(iface); s == nil || !s.healthy() || s.proven.Load() {
		t.Error("a connecting owned session takes routes while it holds, unproven")
	}
	if got := e.health.waited(); len(got) == 0 || got[0] != connectingCheckInterval {
		t.Errorf("WireGuard health waits = %v, want %v while waiting for the first handshake", got, connectingCheckInterval)
	}

	// No handshake by the end of the hold: still connecting, but direct.
	e.clock.advance(connectHoldLimit)
	e.tick(t, 1)
	waitNoHost(t, k, "10.60.0.5")
	if st := e.profileState(id); st.State != api.ProfileConnecting {
		t.Errorf("state after the hold without a handshake = %q", st.State)
	}
	if !e.hasActivity(activity.KindVPN, "Office", "still connecting") {
		t.Errorf("the end of the hold must be recorded: %v", e.activityDetails(activity.KindVPN, "Office"))
	}

	e.armed(t, 1)
	e.starter.tunnel(id).setHandshake(e.clock.Now(), true)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileConnected)
	waitHost(t, k, "10.60.0.5", iface)
	if !e.hasActivity(activity.KindVPN, "Office", "connected") {
		t.Errorf("the first healthy check must be recorded: %v", e.activityDetails(activity.KindVPN, "Office"))
	}
	if got := e.health.waited(); got[len(got)-1] != wgCheckInterval {
		t.Errorf("WireGuard health waits = %v, want %v once connected", got, wgCheckInterval)
	}
}

func TestWireGuardThatHandshakesDuringTheHoldKeepsItsRoutes(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.starter.onStart = func(_ tunnelStartRequest, tn *fakeTunnel) { tn.setHandshake(time.Time{}, false) }

	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	e.setList(t, id, "10.60.0.5")
	iface := e.connect(t, id)
	e.armed(t, 1)
	waitHost(t, k, "10.60.0.5", iface)

	e.clock.advance(connectingCheckInterval)
	e.starter.tunnel(id).setHandshake(e.clock.Now(), true)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileConnected)
	waitHost(t, k, "10.60.0.5", iface)
	if e.hasActivity(activity.KindVPN, "Office", "still connecting") {
		t.Error("a tunnel proven during its hold must not end the hold as unproven")
	}
}

func TestNextHealthCheck(t *testing.T) {
	wg := healthPolicyFor("wireguard")
	outline := healthPolicyFor("outline")
	pending := fmt.Errorf("%w: waiting", errNotProvenYet)
	cases := []struct {
		name    string
		policy  healthPolicy
		state   healthState
		err     error
		holding bool
		elapsed time.Duration
		want    time.Duration
	}{
		{"waiting for the first handshake", wg, healthConnecting, pending, true, 0, connectingCheckInterval},
		{"after the fast window, until the hold ends", wg, healthConnecting, pending, true, 6 * time.Second, 4 * time.Second},
		{"after the hold", wg, healthConnecting, pending, false, 12 * time.Second, wgCheckInterval},
		{"connected", wg, healthUp, nil, false, time.Minute, wgCheckInterval},
		{"outline probe failed while holding", outline, healthConnecting, errors.New("probe"), true, time.Second, 9 * time.Second},
		{"outline connected", outline, healthUp, nil, false, time.Minute, outlineProbeInterval},
		{"hold already overdue", wg, healthConnecting, pending, true, 11 * time.Second, connectingCheckInterval},
	}
	for _, c := range cases {
		if got := nextHealthCheck(c.policy, c.state, c.err, c.holding, c.elapsed); got != c.want {
			t.Errorf("%s: wait %v, want %v", c.name, got, c.want)
		}
	}
}

func TestWireGuardWithoutAFirstHandshakeShowsAnErrorAfter30SecondsAndStillConnectsLater(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.starter.onStart = func(_ tunnelStartRequest, tn *fakeTunnel) { tn.setHandshake(time.Time{}, false) }

	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	e.setList(t, id, "10.60.0.5")
	iface := e.connect(t, id)
	e.armed(t, 1)

	e.clock.advance(wgFirstHandshakeTimeout - time.Second)
	e.tick(t, 1)
	if st := e.profileState(id); st.State != api.ProfileConnecting {
		t.Fatalf("state just before the timeout = %q, want connecting", st.State)
	}

	e.clock.advance(time.Second)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileError)
	if st := e.profileState(id); !strings.Contains(st.Error, "no handshake") {
		t.Errorf("error = %q, want it to say no handshake arrived", st.Error)
	}
	if _, ok := k.hostRoute("10.60.0.5"); ok {
		t.Error("a profile that never handshook must not route")
	}

	e.starter.tunnel(id).setHandshake(e.clock.Now(), true)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileConnected)
	waitHost(t, k, "10.60.0.5", iface)
}

func TestWireGuardGoesUnhealthyWhenTheHandshakeIsOlderThan180SecondsAndRecovers(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.starter.onStart = func(_ tunnelStartRequest, tn *fakeTunnel) { tn.setHandshake(e.clock.Now(), true) }
	d := e.d

	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	e.setList(t, id, "10.60.0.5")
	iface := e.connect(t, id)
	e.waitState(t, id, api.ProfileConnected)
	waitHost(t, k, "10.60.0.5", iface)

	// Exactly 180 s old is still healthy.
	e.clock.advance(180 * time.Second)
	e.tick(t, 1)
	if st := e.profileState(id); st.State != api.ProfileConnected {
		t.Fatalf("a 180 s old handshake must be healthy, state %q", st.State)
	}
	if _, ok := k.hostRoute("10.60.0.5"); !ok {
		t.Fatal("the route must stay while the handshake is fresh enough")
	}

	// One second more and the entries go direct. No other tunnel takes them.
	e.clock.advance(time.Second)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileError)
	waitNoHost(t, k, "10.60.0.5")
	st := e.profileState(id)
	if !strings.Contains(st.Error, "no WireGuard handshake") {
		t.Errorf("profiles.list error = %q, want the reason", st.Error)
	}
	if s := d.sessions.get(iface); s == nil || s.healthy() {
		t.Error("the session stays registered but unhealthy")
	}
	if !e.hasActivity(activity.KindVPN, "Office", "unhealthy") {
		t.Errorf("the change must be recorded in the activity log: %v", e.activityDetails(activity.KindVPN, "Office"))
	}
	if !strings.Contains(e.logs.String(), "built-in VPN is unhealthy") {
		t.Error("the change must be logged")
	}
	if st.Stats == nil {
		t.Error("an unhealthy profile still reports its stats, they explain why")
	}

	// A new handshake brings the routes back on the next sync.
	e.starter.tunnel(id).setHandshake(e.clock.Now(), true)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileConnected)
	waitHost(t, k, "10.60.0.5", iface)
	if !e.hasActivity(activity.KindVPN, "Office", "healthy again") {
		t.Errorf("the recovery must be recorded: %v", e.activityDetails(activity.KindVPN, "Office"))
	}
}

func TestOutlineNeedsThreeFailedProbesToGoUnhealthyAndOneSuccessToRecover(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	probeFail := errors.New("could not reach the DNS server through the VPN server")
	e.starter.onStart = func(_ tunnelStartRequest, tn *fakeTunnel) { tn.setProbe(nil) }

	id := e.importOutline(t, "Travel", "198.51.100.7")
	e.setList(t, id, "10.61.0.7")
	iface := e.connect(t, id)
	e.waitState(t, id, api.ProfileConnected)
	waitHost(t, k, "10.61.0.7", iface)
	tn := e.starter.tunnel(id)

	stillRouted := func(step string) {
		t.Helper()
		if st := e.profileState(id); st.State != api.ProfileConnected {
			t.Fatalf("%s: state = %q, want connected (hysteresis)", step, st.State)
		}
		if _, ok := k.hostRoute("10.61.0.7"); !ok {
			t.Fatalf("%s: the route must stay through a short blip", step)
		}
	}

	// Two failures, a success, two failures: never three in a row.
	for i, err := range []error{probeFail, probeFail, nil, probeFail, probeFail} {
		tn.setProbe(err)
		e.tick(t, 1)
		stillRouted(fmt.Sprintf("probe %d", i+1))
	}

	// The third in a row.
	tn.setProbe(probeFail)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileError)
	waitNoHost(t, k, "10.61.0.7")
	if st := e.profileState(id); !strings.Contains(st.Error, "could not reach the DNS server") {
		t.Errorf("error = %q", st.Error)
	}
	if !e.hasActivity(activity.KindVPN, "Travel", "unhealthy") {
		t.Errorf("unhealthy must be recorded: %v", e.activityDetails(activity.KindVPN, "Travel"))
	}
	// Further failures change nothing and add no events.
	events := len(e.activityDetails(activity.KindVPN, "Travel"))
	e.tick(t, 1)
	if got := len(e.activityDetails(activity.KindVPN, "Travel")); got != events {
		t.Errorf("a failure while already unhealthy recorded %d new events", got-events)
	}

	// One success is enough.
	tn.setProbe(nil)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileConnected)
	waitHost(t, k, "10.61.0.7", iface)
	if !e.hasActivity(activity.KindVPN, "Travel", "healthy again") {
		t.Errorf("recovery must be recorded: %v", e.activityDetails(activity.KindVPN, "Travel"))
	}
	if got := e.health.waited(); len(got) == 0 || got[0] != 30*time.Second {
		t.Errorf("Outline probe waits = %v, want 30 s apart", got)
	}
}

func TestOutlineStaysConnectingUntilTheFirstProbeSucceeds(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	probeFail := errors.New("connection refused")
	e.starter.onStart = func(_ tunnelStartRequest, tn *fakeTunnel) { tn.setProbe(probeFail) }

	id := e.importOutline(t, "Travel", "198.51.100.7")
	e.setList(t, id, "10.61.0.7")
	iface := e.connect(t, id)
	e.armed(t, 1)

	for i := 1; i <= 2; i++ {
		if st := e.profileState(id); st.State != api.ProfileConnecting {
			t.Fatalf("after %d failed probe(s): state %q, want connecting", i, st.State)
		}
		e.tick(t, 1)
	}
	e.waitState(t, id, api.ProfileError) // the third failure in a row
	if _, ok := k.hostRoute("10.61.0.7"); ok {
		t.Error("an unproven profile must not route")
	}

	e.starter.tunnel(id).setProbe(nil)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileConnected)
	waitHost(t, k, "10.61.0.7", iface)
}

func TestAnUnhealthyProfileSendsItsEntriesDirectAndNothingFailsOver(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	d := e.d
	e.starter.onStart = func(req tunnelStartRequest, tn *fakeTunnel) {
		if req.Profile.Kind == "wireguard" {
			tn.setHandshake(e.clock.Now(), true)
		} else {
			tn.setProbe(nil)
		}
	}

	// Alpha (WireGuard) outranks Beta (Outline); both list 10.99.0.1.
	a := e.importWireGuard(t, "Alpha", "vpn.example.com:51820")
	b := e.importOutline(t, "Beta", "198.51.100.7")
	e.setList(t, a, "10.99.0.1")
	e.setList(t, b, "10.99.0.1", "10.99.0.2")
	ifaceA := e.connect(t, a)
	ifaceB := e.connect(t, b)
	e.waitState(t, a, api.ProfileConnected)
	e.waitState(t, b, api.ProfileConnected)
	waitHost(t, k, "10.99.0.1", ifaceA)
	waitHost(t, k, "10.99.0.2", ifaceB)

	// Alpha's handshake goes stale: its entry goes direct, and Beta, which also
	// lists it and is healthy, does not take it over.
	e.clock.advance(wgHandshakeFresh + time.Second)
	e.starter.tunnel(b).setProbe(nil)
	e.tick(t, 2)
	e.waitState(t, a, api.ProfileError)
	waitNoHost(t, k, "10.99.0.1")
	d.syncRoutes(d.currentGeneration())
	if _, ok := k.hostRoute("10.99.0.1"); ok || holds(d, ifaceB, "10.99.0.1") {
		t.Error("an unhealthy profile's entry must go direct, never to a lower-priority tunnel")
	}
	if got, ok := k.hostRoute("10.99.0.2"); !ok || got != ifaceB {
		t.Errorf("the healthy profile keeps its own entry, got %q %v", got, ok)
	}
}

func TestTheAnyVPNListNeverRoutesThroughABuiltInProfile(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	d := e.d

	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	iface := e.connect(t, id)
	e.waitState(t, id, api.ProfileConnected)
	d.syncRoutes(d.currentGeneration())
	// With no detected tunnel the Any VPN entries go direct, even though a
	// healthy built-in tunnel is up.
	if _, ok := k.hostRoute("10.50.0.1"); ok || holds(d, iface, "10.50.0.1") {
		t.Fatal("the Any VPN list must not use a built-in profile when no detected tunnel is up")
	}

	e.connectAWS()
	waitForSession(t, d, awsIface)
	waitHost(t, k, "10.50.0.1", awsIface)

	// AWS leaves: the entries go direct again, they do not fall to the profile.
	e.disconnectAWS()
	waitNoHost(t, k, "10.50.0.1")
	d.syncRoutes(d.currentGeneration())
	if _, ok := k.hostRoute("10.50.0.1"); ok {
		t.Error("the Any VPN list must go direct when the detected tunnel is gone")
	}
}

func TestAProfileThatBecomesHealthyAfterAnyListedNamesWereLearnedRoutesOnlyItsOwnList(t *testing.T) {
	// A built-in profile's wildcard answers belong to its own list alone.
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"*.any.example.com"}, nil, nil)
	d := e.d
	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	e.setList(t, id, "*.corp.example.com")
	iface := e.connect(t, id)
	e.waitState(t, id, api.ProfileConnected)

	answer(d, "git.corp.example.com", "10.70.0.4")
	answer(d, "x.any.example.com", "10.71.0.4")
	if !holds(d, iface, "10.70.0.4") {
		t.Error("the profile's own wildcard name must route through it")
	}
	if _, ok := k.hostRoute("10.71.0.4"); ok {
		t.Error("an Any VPN wildcard name must not route through a built-in profile")
	}
}

// --- hygiene ---

func TestHealthErrorsAndEventsNeverCarrySecrets(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	d := e.d

	// A check error that echoes the profile's own secret, as a careless
	// transport might.
	e.starter.onStart = func(req tunnelStartRequest, tn *fakeTunnel) {
		own := wgPrivateKeyText
		if req.Profile.Kind == "outline" {
			own = outlinePassword
		}
		tn.setProbe(fmt.Errorf("probe through %q failed with key %s (%s)", req.Secret, own, req.Secret))
	}
	wg := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	ol := e.importOutline(t, "Travel", "198.51.100.7")
	e.connect(t, wg)
	e.connect(t, ol)
	// An Outline probe must fail three times in a row; a WireGuard check once.
	e.tick(t, 2)
	e.tick(t, 2)
	e.tick(t, 2)
	e.waitState(t, wg, api.ProfileError)
	e.waitState(t, ol, api.ProfileError)

	outputs := []string{
		fmt.Sprintf("%+v", d.ProfilesList()),
		fmt.Sprintf("%+v", d.activity.List(0, 0)),
		fmt.Sprintf("%+v", d.Tunnels()),
		e.logs.String(),
	}
	for _, out := range outputs {
		for _, secret := range allSecrets() {
			if strings.Contains(out, secret) {
				t.Errorf("secret %q leaked through a health error or event into %.100s...", secret[:8]+"…", out)
			}
		}
	}
	if !strings.Contains(outputs[0], "[redacted]") {
		t.Error("the scrubbed error must still be shown, with the secret replaced")
	}
}
