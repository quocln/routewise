package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/history"
)

// --- owned sessions on the fake kernel ---

func TestAProfilesListRoutesThroughItsUtunAndTouchesNoDefault(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, []string{"aws.example.com"})
	e.answers.set("any.example.com", "10.50.0.1")
	e.answers.set("aws.example.com", "10.200.0.1")
	e.answers.set("app.example.com", "10.60.0.9")
	d := e.d

	office := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	travel := e.importOutline(t, "Travel", "198.51.100.7")
	e.setList(t, office, "10.60.0.5", "10.70.0.0/16", "app.example.com")
	e.setList(t, travel, "10.61.0.7")

	e.connectAWS()
	waitForSession(t, d, awsIface)
	officeIface := e.connect(t, office)
	travelIface := e.connect(t, travel)

	waitHost(t, k, "10.60.0.5", officeIface)
	waitHost(t, k, "10.60.0.9", officeIface)
	waitHost(t, k, "10.61.0.7", travelIface)
	waitHost(t, k, "10.200.0.1", awsIface)
	waitFor(t, "the CIDR entry to route through the utun", func() bool { return k.hasNet("10.70.0.0/16", officeIface) })

	// Routes leave through the utun by interface; the helper owns the utun, so
	// there is no gateway to name.
	if !k.has("add -host 10.60.0.5 -interface " + officeIface) {
		t.Errorf("host routes must be added with -interface; calls: %v", k.log())
	}

	// A built-in tunnel never changes the default route or touches a catch-all.
	if gw, iface := k.defaultRoute(); gw != "192.168.7.1" || iface != "en0" {
		t.Errorf("default route = %s via %s, want the LAN's, untouched", gw, iface)
	}
	for _, forbidden := range []string{"change default", "add default", "delete default", "-net 0.0.0.0/1", "-net 128.0.0.0/1", "-net 0/1", "-net 128/1"} {
		if k.has(forbidden) {
			t.Errorf("a command containing %q ran; built-in tunnels must not touch default or catch-all routes", forbidden)
		}
	}
	if got := len(k.netRoutes()); got != 1 {
		t.Errorf("network routes = %v, want only the one CIDR entry", k.netRoutes())
	}

	for _, s := range d.sessionList() {
		if s.owned && !s.manager.Additive() {
			t.Errorf("owned session %s must run an additive manager so no catch-all is ever removed", s.iface)
		}
	}

	// The status lists them with their profile IDs and names.
	byIface := map[string]api.TunnelStatus{}
	for _, tun := range d.Tunnels() {
		byIface[tun.Interface] = tun
	}
	if got := byIface[officeIface]; got.ProfileID != office || got.Client.Name != "Office" || got.Client.ID != "routewise-wireguard:"+office {
		t.Errorf("office tunnel status = %+v", got)
	}
	if got := byIface[travelIface]; got.ProfileID != travel || got.Client.ID != "routewise-outline:"+travel {
		t.Errorf("travel tunnel status = %+v", got)
	}
	if byIface[awsIface].ProfileID != "" {
		t.Error("a detected tunnel has no profile id")
	}
	if st := e.d.GetStatus(); !st.VPNConnected {
		t.Error("status must report a VPN connected while a built-in tunnel is up")
	}

	// The history verdict for the owned utun is vpn, named after the profile.
	if verdict, vpn := d.flowVerdict(officeIface); verdict != history.VerdictVPN || vpn != "Office" {
		t.Errorf("flowVerdict(%s) = %s, %q; want vpn, Office", officeIface, verdict, vpn)
	}
	// The monitor must never see the helper's own utun as a VPN to manage.
	if d.admitTunnel(officeIface) {
		t.Error("admitTunnel admitted a RouteWise-owned utun")
	}
	if _, pending := d.VPNClients(); len(pending) != 0 {
		t.Errorf("an owned utun was reported as a pending VPN: %+v", pending)
	}

	// Disconnecting sends the profile's entries direct, and only its own.
	if err := d.ProfileDisconnect(office); err != nil {
		t.Fatal(err)
	}
	waitNoHost(t, k, "10.60.0.5")
	waitNoHost(t, k, "10.60.0.9")
	waitFor(t, "the CIDR route to go", func() bool { return !k.hasNet("10.70.0.0/16", officeIface) })
	if _, ok := k.hostRoute("10.61.0.7"); !ok {
		t.Error("the other profile's route must stay")
	}
	if d.sessions.get(officeIface) != nil {
		t.Error("the session must go with its tunnel")
	}
	if got := d.ownerFor("app.example.com"); got != nil {
		t.Errorf("a disconnected profile's names must go direct, owner = %v", got)
	}
	if st := e.profileState(office); st.State != api.ProfileDisconnected {
		t.Errorf("state after disconnect = %s", st.State)
	}
	if !e.starter.tunnel(office).isStopped() {
		t.Error("disconnect must stop the tunnel")
	}
}

func TestTwoProfilesAndADetectedTunnelFollowTheAllowlistPriority(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	d := e.d

	a := e.importWireGuard(t, "Alpha", "vpn.example.com:51820")
	b := e.importOutline(t, "Beta", "198.51.100.7")
	e.setList(t, a, "10.99.0.1")
	e.setList(t, b, "10.99.0.1", "10.99.0.2")

	// Priority: Beta, then AWS (detected), then Alpha.
	cfg := mustSnapshot(d)
	order := []string{config.ProfileClientID("outline", b), awsClientPath, config.ProfileClientID("wireguard", a), wireGuardPath}
	var vpns []config.VPNRoute
	for _, id := range order {
		for _, v := range cfg.VPNs {
			if v.Client == id {
				vpns = append(vpns, v)
			}
		}
	}
	cfg.VPNs = vpns
	if _, err := d.store.Replace(cfg); err != nil {
		t.Fatal(err)
	}

	e.connectAWS()
	awsSess := waitForSession(t, d, awsIface)
	ifaceA := e.connect(t, a)
	ifaceB := e.connect(t, b)

	sessions := d.sessionList()
	if len(sessions) != 3 || sessions[0].iface != ifaceB || sessions[1] != awsSess || sessions[2].iface != ifaceA {
		var got []string
		for _, s := range sessions {
			got = append(got, s.iface)
		}
		t.Fatalf("priority order = %v, want Beta (%s), AWS (%s), Alpha (%s)", got, ifaceB, awsIface, ifaceA)
	}

	// An address two lists claim goes to the higher-priority profile; the other
	// records a refusal.
	waitHost(t, k, "10.99.0.1", ifaceB)
	waitHost(t, k, "10.99.0.2", ifaceB)
	waitFor(t, "the refusal to be recorded", func() bool {
		for _, ev := range d.activity.List(0, 0) {
			if ev.Kind == activity.KindRefused && ev.Name == "10.99.0.1" {
				return true
			}
		}
		return false
	})
	// The Any VPN list belongs to detected tunnels alone: it goes to AWS even
	// though Beta, a built-in profile, outranks it.
	waitHost(t, k, "10.50.0.1", awsIface)
	if holds(d, ifaceB, "10.50.0.1") || holds(d, ifaceA, "10.50.0.1") {
		t.Error("a built-in profile must never carry the Any VPN list")
	}
	if holds(d, ifaceA, "10.99.0.1") {
		t.Error("the lower-priority profile must not hold an address the higher one routes")
	}

	// When Beta goes, 10.99.0.1 is Beta's entry and goes direct: Alpha, which
	// lists it too, never inherits it. AWS takes the Any list.
	if err := d.ProfileDisconnect(b); err != nil {
		t.Fatal(err)
	}
	waitNoHost(t, k, "10.99.0.1")
	waitNoHost(t, k, "10.99.0.2")
	waitHost(t, k, "10.50.0.1", awsIface)
	d.syncRoutes(d.currentGeneration())
	if _, ok := k.hostRoute("10.99.0.1"); ok || holds(d, ifaceA, "10.99.0.1") {
		t.Error("an entry whose owner is down must not fall through to a lower-priority profile")
	}
}

func TestRemovingAProfileDeletesItsSecretListAndEntry(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	d := e.d
	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	e.setList(t, id, "10.60.0.5")
	iface := e.connect(t, id)
	waitHost(t, k, "10.60.0.5", iface)

	clientID := config.ProfileClientID("wireguard", id)
	if err := d.SetVPNClientAllowed(clientID, false); err == nil {
		t.Error("a built-in VPN must not be revoked through the allowlist")
	}
	if err := d.SetVPNClientAllowed(config.ProfileClientID("wireguard", "deadbeef"), true); err == nil {
		t.Error("a built-in client without a profile must not be allowed")
	}

	if err := d.ProfileRemove(id); err != nil {
		t.Fatal(err)
	}
	waitNoHost(t, k, "10.60.0.5")
	if e.secrets.count() != 0 {
		t.Error("removing a profile must delete its secret")
	}
	cfg := mustSnapshot(d)
	if len(cfg.Profiles) != 0 || slices.Contains(cfg.AllowedClients(), clientID) {
		t.Errorf("profile or client entry left behind: %+v", cfg)
	}
	if d.sessions.get(iface) != nil || !e.starter.tunnel(id).isStopped() {
		t.Error("removing a profile must disconnect it")
	}
	if err := d.ProfileConnect(id); err == nil {
		t.Error("connecting a removed profile must fail")
	}
}

// --- endpoint safety ---

func TestEntriesCoveringAnEndpointAreRefusedAlsoAfterReResolution(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	e.answers.set("edge.example.com", "203.0.113.50")
	e.starter.plan = func(n int, req tunnelStartRequest) ([]netip.Addr, error) {
		// The server's name resolves to a new address at the second start.
		if n == 1 {
			return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}
	d := e.d
	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	e.setList(t, id, "203.0.113.9", "203.0.113.0/24", "198.51.100.1", "edge.example.com", "10.60.0.5")
	iface := e.connect(t, id)

	// First endpoint 198.51.100.1: the entry equal to it is refused, the rest
	// route, including the CIDR that covers only the later address.
	waitHost(t, k, "10.60.0.5", iface)
	waitHost(t, k, "203.0.113.9", iface)
	waitHost(t, k, "203.0.113.50", iface)
	waitFor(t, "the CIDR route", func() bool { return k.hasNet("203.0.113.0/24", iface) })
	if _, ok := k.hostRoute("198.51.100.1"); ok {
		t.Fatal("an entry equal to the server address was routed into the tunnel")
	}
	refused := func(name string) bool {
		for _, ev := range d.activity.List(0, 0) {
			if ev.Kind == activity.KindRefused && ev.Name == name {
				return true
			}
		}
		return false
	}
	waitFor(t, "the refusal event", func() bool { return refused("198.51.100.1") })
	if !strings.Contains(e.logs.String(), "not routing list entry") {
		t.Error("the refusal must be logged")
	}

	// The tunnel dies and comes back with the server on 203.0.113.9: the IP
	// entry, the CIDR covering it, and the domain resolving inside the CIDR are
	// re-checked against the new address.
	e.starter.tunnel(id).die()
	waitFor(t, "the reconnect wait", func() bool { return len(e.clock.waited()) == 1 })
	e.clock.fire()
	waitFor(t, "the second start", func() bool { return e.starter.startCount() == 2 })
	waitFor(t, "the tunnel to be up again", func() bool { return e.profileState(id).State == api.ProfileConnected })
	waitFor(t, "the old route to the new server address to go", func() bool {
		_, hostOK := k.hostRoute("203.0.113.9")
		return !hostOK && !k.hasNet("203.0.113.0/24", iface)
	})
	waitHost(t, k, "198.51.100.1", iface) // no longer the server: routable now
	waitHost(t, k, "10.60.0.5", iface)
	waitFor(t, "refusal of the CIDR covering the new server address", func() bool { return refused("203.0.113.0/24") })
	waitFor(t, "refusal of the new server address", func() bool { return refused("203.0.113.9") })
	// The domain resolved to 203.0.113.50, inside the refused CIDR but not the
	// server itself, so it stays routed.
	waitHost(t, k, "203.0.113.50", iface)

	// A domain that resolves onto the server address is refused as well.
	e.answers.set("edge.example.com", "203.0.113.9")
	d.syncRoutes(d.currentGeneration())
	waitNoHost(t, k, "203.0.113.50")
	if _, ok := k.hostRoute("203.0.113.9"); ok {
		t.Error("a domain resolving to the server address must not be routed")
	}
	waitFor(t, "refusal of the domain", func() bool { return refused("edge.example.com") })
}

// --- reconnect backoff ---

func TestReconnectBacksOffFromOneToSixtySecondsAndResetsAfterAStableRun(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	failures := 8
	e.starter.plan = func(n int, _ tunnelStartRequest) ([]netip.Addr, error) {
		if n <= failures {
			return nil, errors.New("no route to host")
		}
		return nil, nil
	}
	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	if err := e.d.ProfileConnect(id); err != nil {
		t.Fatal(err)
	}

	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		waitFor(t, fmt.Sprintf("wait %d to be requested", i+1), func() bool { return len(e.clock.waited()) == i+1 })
		if got := e.clock.waited()[i]; got != w*time.Second {
			t.Fatalf("wait %d = %v, want %v (all: %v)", i+1, got, w*time.Second, e.clock.waited())
		}
		if st := e.profileState(id); st.State != api.ProfileError || st.Error != "no route to host" {
			t.Fatalf("state while backing off = %+v", st)
		}
		e.clock.fire()
	}
	waitFor(t, "the ninth attempt to connect", func() bool { return e.profileState(id).State == api.ProfileConnected })

	// A run that lasts at least the stable period starts the backoff over.
	e.clock.advance(tunnelStableAfter + time.Second)
	e.starter.tunnel(id).die()
	waitFor(t, "the next wait", func() bool { return len(e.clock.waited()) == len(want)+1 })
	if got := e.clock.waited()[len(want)]; got != time.Second {
		t.Errorf("wait after a stable run = %v, want 1s", got)
	}
	e.clock.fire()
	waitFor(t, "reconnected", func() bool { return e.starter.startCount() == failures+2 })

	// A quick death does not reset it: the delay grows from where it was.
	waitFor(t, "connected again", func() bool { return e.profileState(id).State == api.ProfileConnected })
	e.starter.tunnel(id).die()
	waitFor(t, "the following wait", func() bool { return len(e.clock.waited()) == len(want)+2 })
	if got := e.clock.waited()[len(want)+1]; got != 2*time.Second {
		t.Errorf("wait after a short run = %v, want 2s", got)
	}

	// Disconnecting stops the retries.
	if err := e.d.ProfileDisconnect(id); err != nil {
		t.Fatal(err)
	}
	startsBefore := e.starter.startCount()
	e.clock.fire()
	time.Sleep(50 * time.Millisecond)
	if e.starter.startCount() != startsBefore || e.profileState(id).State != api.ProfileDisconnected {
		t.Error("a disconnected profile must not reconnect")
	}
}

func TestBackoffDelayAndJitter(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i, w := range want {
		if got := backoffDelay(i); got != w*time.Second {
			t.Errorf("backoffDelay(%d) = %v, want %v", i, got, w*time.Second)
		}
	}
	if backoffDelay(1000) != 60*time.Second {
		t.Error("a huge attempt count must stay capped")
	}
	for range 200 {
		if j := randomJitter(10 * time.Second); j < 0 || j > 2*time.Second {
			t.Fatalf("jitter %v outside [0, 2s]", j)
		}
	}
}

func TestEveryReconnectStartsTheTunnelAgainSoTheServerIsResolvedAnew(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	id := e.importOutline(t, "Travel", "vpn.example.com")
	e.connect(t, id)
	first := e.starter.tunnel(id)
	first.die()
	waitFor(t, "the reconnect wait", func() bool { return len(e.clock.waited()) == 1 })
	e.clock.fire()
	waitFor(t, "a second start", func() bool { return e.starter.startCount() == 2 })
	waitFor(t, "connected", func() bool { return e.profileState(id).State == api.ProfileConnected })
	if e.starter.tunnel(id) == first || !first.isStopped() {
		t.Error("the dead tunnel must be stopped and replaced by a fresh one")
	}
	// Each Outline profile keeps its own /32 from 10.233.0.0/16.
	addr := e.starter.request(0).Address
	if !addr.IsValid() || !outlineBase.Contains(addr) {
		t.Errorf("outline address = %v, want one inside %s", addr, outlineBase)
	}
}

func TestOutlineProfilesGetDistinctAddresses(t *testing.T) {
	m := newTunnelManager()
	a, _ := m.allocOutlineAddr("a")
	b, _ := m.allocOutlineAddr("b")
	again, _ := m.allocOutlineAddr("a")
	if a == b || a != again || !outlineBase.Contains(a) || !outlineBase.Contains(b) {
		t.Errorf("addresses a=%v b=%v again=%v", a, b, again)
	}
	m.releaseOutlineAddr("a")
	c, _ := m.allocOutlineAddr("c")
	if c != a {
		t.Errorf("a released address must be reused, got %v want %v", c, a)
	}
}

// --- secret hygiene ---

func TestSecretsAppearInNoResponseExportErrorActivityOrLog(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	d := e.d

	// A connection failure whose error text echoes the secrets: the manager
	// must scrub it before it is shown anywhere.
	e.starter.plan = func(n int, req tunnelStartRequest) ([]netip.Addr, error) {
		// The failure echoes the profile's own secret, raw and quoted.
		own := wgPrivateKeyText
		if req.Profile.Kind == "outline" {
			own = outlinePassword
		}
		return nil, fmt.Errorf("handshake failed for config %q with key %s (%s)", req.Secret, own, req.Secret)
	}
	wg := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	ol := e.importOutline(t, "Travel", "198.51.100.7")
	for _, id := range []string{wg, ol} {
		if err := d.ProfileConnect(id); err != nil {
			t.Fatal(err)
		}
		e.waitState(t, id, api.ProfileError)
	}

	var outputs []string
	collect := func(label string, v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		outputs = append(outputs, label+": "+string(raw))
	}
	collect("profiles.list", d.ProfilesList())
	collect("export", d.ExportConfig())
	collect("tunnels", d.Tunnels())
	collect("settings", d.Settings())
	collect("activity", d.activity.List(0, 0))
	collect("routes", d.GetActiveRoutes())
	_, events := d.Activity(0, 0, 0)
	collect("activity.list", events)

	// Errors a caller can provoke, with the secret in the request.
	badKey := strings.Replace(wireGuardConf("vpn.example.com:51820"), "AllowedIPs = 0.0.0.0/0", "AllowedIPs = not-a-prefix "+wgPrivateKeyText, 1)
	_, err := d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", Name: "Bad", WireguardConfig: badKey})
	if err == nil {
		t.Fatal("an invalid config must be rejected")
	}
	outputs = append(outputs, "import error: "+err.Error())
	_, err = d.ProfileImport(api.ProfileImportParams{Kind: "outline", Name: "Bad", AccessKey: "ss://" + outlinePassword + "@@@"})
	if err == nil {
		t.Fatal("an invalid key must be rejected")
	}
	outputs = append(outputs, "import error: "+err.Error())
	_, err = d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", Name: "Mixed", WireguardConfig: wireGuardConf("x:1"), AccessKey: outlinePassword})
	outputs = append(outputs, fmt.Sprint("mixed error: ", err))
	err = d.ProfileUpdate(api.ProfileUpdateParams{ID: wg, WireguardConfig: "[Interface]\nPrivateKey = " + wgPrivateKeyText + "\nbogus line"})
	if err == nil {
		t.Fatal("an invalid replacement config must be rejected")
	}
	outputs = append(outputs, "update error: "+err.Error())

	// Healthy path too: the tunnels connect and stay up, with stats and logs.
	e.starter.plan = nil
	for _, id := range []string{wg, ol} {
		if err := d.ProfileConnect(id); err != nil {
			t.Fatal(err)
		}
		e.waitState(t, id, api.ProfileConnected)
	}
	collect("profiles.list connected", d.ProfilesList())
	collect("tunnels connected", d.Tunnels())
	collect("activity connected", d.activity.List(0, 0))
	_ = d.ProfileDisconnect(wg)
	_ = d.ProfileDisconnect(ol)

	outputs = append(outputs, "daemon log: "+e.logs.String())
	for _, out := range outputs {
		for _, secret := range allSecrets() {
			if strings.Contains(out, secret) {
				t.Errorf("secret %q leaked into %.80s...", secret[:8]+"…", out)
			}
		}
	}
	// And the secret is where it belongs.
	if got, _ := e.secrets.ProfileSecret(wg); !strings.Contains(got, wgPrivateKeyText) {
		t.Error("the WireGuard secret must be kept in the secret store")
	}
	if got, _ := e.secrets.ProfileSecret(ol); !strings.Contains(got, outlinePassword) && !strings.Contains(got, allSecrets()[3]) {
		t.Error("the Outline secret must be kept in the secret store")
	}
}

func TestProfileListReportsNeedsCredentialsUntilASecretExists(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	if st := e.profileState(id); st.State != api.ProfileDisconnected {
		t.Fatalf("imported profile state = %s", st.State)
	}
	if err := e.secrets.DeleteProfileSecret(id); err != nil {
		t.Fatal(err)
	}
	if st := e.profileState(id); st.State != api.ProfileNeedsCredentials {
		t.Errorf("a profile without a secret = %s, want needsCredentials", st.State)
	}
	if err := e.d.ProfileConnect(id); !errors.Is(err, api.ErrRejected) {
		t.Errorf("connecting without credentials = %v, want a rejection", err)
	}
	// Adding credentials makes it connectable again.
	err := e.d.ProfileUpdate(api.ProfileUpdateParams{ID: id, WireguardConfig: wireGuardConf("vpn.example.com:51820")})
	if err != nil {
		t.Fatal(err)
	}
	if st := e.profileState(id); st.State != api.ProfileDisconnected {
		t.Errorf("after adding credentials = %s", st.State)
	}
}

func TestImportDefaultsFollowTheKind(t *testing.T) {
	e := newBuiltinEnv(t, newFakeKernel(), []string{"any.example.com"}, nil, nil)
	wg := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	ol := e.importOutline(t, "", "198.51.100.7")
	profiles := map[string]api.ProfileInfo{}
	for _, p := range e.d.ProfilesList() {
		profiles[p.ID] = p
	}
	if !slices.Equal(profiles[wg].DNS, []string{"10.8.0.1"}) {
		t.Errorf("WireGuard DNS = %v, want the .conf's", profiles[wg].DNS)
	}
	if !slices.Equal(profiles[ol].DNS, []string{"1.0.0.1"}) || profiles[ol].Name != "Travel" {
		t.Errorf("Outline profile = %+v, want DNS 1.0.0.1 and the key's tag as its name", profiles[ol])
	}
	// A second unnamed import of the same tag gets a distinct name.
	ol2 := e.importOutline(t, "", "198.51.100.8")
	for _, p := range e.d.ProfilesList() {
		if p.ID == ol2 && p.Name != "Travel 2" {
			t.Errorf("second profile name = %q, want Travel 2", p.Name)
		}
	}
	if _, err := e.d.ProfileImport(api.ProfileImportParams{Kind: "outline", Name: "office", AccessKey: outlineAccessKey("1.2.3.4")}); !errors.Is(err, api.ErrRejected) {
		t.Errorf("a duplicate name (any case) must be rejected, got %v", err)
	}
	if _, err := e.d.ProfileImport(api.ProfileImportParams{Kind: "openvpn", Name: "x", AccessKey: "y"}); !errors.Is(err, api.ErrRejected) {
		t.Errorf("an unknown kind must be rejected, got %v", err)
	}
}

// --- export round trip ---

func TestExportCarriesProfilesWithoutSecretsAndImportNeedsCredentials(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	e.setList(t, id, "10.60.0.5", "app.corp.example.com")

	export := e.d.ExportConfig()
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range allSecrets() {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("export leaks a secret: %s", raw)
		}
	}
	if len(export.Profiles) != 1 || export.Profiles[0].ID != id || export.Profiles[0].Name != "Office" {
		t.Fatalf("export profiles = %+v", export.Profiles)
	}
	var list []string
	for _, v := range export.VPNs {
		if v.Client == config.ProfileClientID("wireguard", id) {
			list = v.Domains
		}
	}
	if !slices.Equal(list, []string{"10.60.0.5", "app.corp.example.com"}) {
		t.Errorf("the profile's list in the export = %v", list)
	}

	// Import into a fresh helper: the profile arrives with its list and no
	// credentials.
	// One helper runs at a time: Windows refuses a second server on its pipe.
	e.d.Stop()
	parsed, err := config.ParseExport(raw)
	if err != nil {
		t.Fatal(err)
	}
	fresh := newBuiltinEnv(t, newFakeKernel(), []string{"other.example.com"}, nil, nil)
	if _, err := fresh.d.ImportConfig(parsed); err != nil {
		t.Fatal(err)
	}
	st := fresh.profileState(id)
	if st.ID != id || st.State != api.ProfileNeedsCredentials || st.Name != "Office" {
		t.Fatalf("imported profile = %+v, want needsCredentials", st)
	}
	if fresh.secrets.count() != 0 {
		t.Error("an import must never create a secret")
	}
	list2, _, err := fresh.d.ListDomains(config.ProfileClientID("wireguard", id))
	if err != nil || len(list2) != 2 {
		t.Errorf("imported list = %v, %v", list2, err)
	}
	// Then credentials make it usable.
	if err := fresh.d.ProfileUpdate(api.ProfileUpdateParams{ID: id, WireguardConfig: wireGuardConf("vpn.example.com:51820")}); err != nil {
		t.Fatal(err)
	}
	fresh.connect(t, id)
}

func TestImportingAConfigWithoutAProfileDisconnectsItAndDropsItsSecret(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	iface := e.connect(t, id)

	cfg := mustSnapshot(e.d)
	cfg.Profiles = nil
	cfg.VPNs = slices.DeleteFunc(cfg.VPNs, func(v config.VPNRoute) bool { return config.IsBuiltinClient(v.Client) })
	if _, err := e.d.ImportConfig(config.NewExport(cfg, time.Now())); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the session to go", func() bool { return e.d.sessions.get(iface) == nil })
	if e.secrets.count() != 0 {
		t.Error("a profile dropped by an import must lose its secret")
	}
	if !e.starter.tunnel(id).isStopped() {
		t.Error("a profile dropped by an import must be disconnected")
	}
}

func TestUpdatingADisconnectedProfileDoesNotConnectIt(t *testing.T) {
	e := newBuiltinEnv(t, newFakeKernel(), []string{"any.example.com"}, nil, nil)
	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	name, auto := "Renamed", true
	dns := []string{"10.9.0.1", "10.9.0.1"}
	if err := e.d.ProfileUpdate(api.ProfileUpdateParams{ID: id, Name: &name, AutoConnect: &auto, DNS: &dns}); err != nil {
		t.Fatal(err)
	}
	st := e.profileState(id)
	if st.Name != "Renamed" || !st.AutoConnect || !slices.Equal(st.DNS, []string{"10.9.0.1"}) || st.State != api.ProfileDisconnected {
		t.Errorf("after update = %+v", st)
	}
	bad := []string{"fe80::1"}
	if err := e.d.ProfileUpdate(api.ProfileUpdateParams{ID: id, DNS: &bad}); !errors.Is(err, api.ErrRejected) {
		t.Errorf("an IPv6 DNS server must be rejected, got %v", err)
	}
	if e.starter.startCount() != 0 {
		t.Error("an update must not connect a disconnected profile")
	}
}

func TestAutoConnectProfilesStartWithTheHelper(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	auto := e.importWireGuard(t, "Auto", "vpn.example.com:51820")
	manual := e.importOutline(t, "Manual", "198.51.100.7")
	on := true
	if err := e.d.ProfileUpdate(api.ProfileUpdateParams{ID: auto, AutoConnect: &on}); err != nil {
		t.Fatal(err)
	}
	e.d.autoConnectProfiles()
	e.waitState(t, auto, api.ProfileConnected)
	if st := e.profileState(manual); st.State != api.ProfileDisconnected {
		t.Errorf("a profile without auto-connect = %s", st.State)
	}
}

func TestStopTearsEveryBuiltInTunnelDown(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	a := e.importWireGuard(t, "A", "vpn.example.com:51820")
	b := e.importOutline(t, "B", "198.51.100.7")
	e.setList(t, a, "10.60.0.5")
	ia, ib := e.connect(t, a), e.connect(t, b)
	waitHost(t, k, "10.60.0.5", ia)

	e.d.Stop()
	for _, id := range []string{a, b} {
		if !e.starter.tunnel(id).isStopped() {
			t.Errorf("tunnel %s still running after Stop", id)
		}
	}
	if _, ok := k.hostRoute("10.60.0.5"); ok {
		t.Error("Stop must give the profile's routes back")
	}
	_, _ = ia, ib
	if err := e.d.ProfileConnect(a); err == nil {
		t.Error("a stopped helper must not connect profiles")
	}
}

// --- an entry belongs to the highest-priority client that lists it ---

func TestACIDRInTwoListsIsOwnedByTheHigherPriorityClientAndNeverFallsThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		// highDetected: the higher-priority client is the detected AWS tunnel
		// and the lower one a built-in profile; otherwise both are profiles.
		highDetected bool
	}{{"two built-in profiles", false}, {"detected over built-in", true}} {
		t.Run(tc.name, func(t *testing.T) {
			k := newFakeKernel()
			e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
			e.answers.set("any.example.com", "10.50.0.1")
			d := e.d
			const cidr, ip = "10.80.0.0/16", "10.81.0.1"

			low := e.importOutline(t, "Low", "198.51.100.7")
			e.setList(t, low, cidr, ip)
			var high, highClient string
			var highIface func() string
			if tc.highDetected {
				highClient = awsClientPath
				if err := d.SetDomains(awsClientPath, []string{cidr, ip}, 0); err != nil {
					t.Fatal(err)
				}
				highIface = func() string { return awsIface }
			} else {
				high = e.importWireGuard(t, "High", "vpn.example.com:51820")
				highClient = config.ProfileClientID("wireguard", high)
				e.setList(t, high, cidr, ip)
				highIface = func() string { return e.starter.iface(high) }
			}
			// Priority: the high client first.
			cfg := mustSnapshot(d)
			slices.SortStableFunc(cfg.VPNs, func(a, b config.VPNRoute) int {
				rank := func(c string) int {
					if c == highClient {
						return 0
					}
					return 1
				}
				return rank(a.Client) - rank(b.Client)
			})
			if _, err := d.store.Replace(cfg); err != nil {
				t.Fatal(err)
			}

			connectHigh := func() {
				if tc.highDetected {
					e.connectAWS()
					waitForSession(t, d, awsIface)
				} else {
					e.connect(t, high)
				}
			}
			connectHigh()
			lowIface := e.connect(t, low)

			// Both up: the route goes via the owner, and the other records a refusal.
			waitFor(t, "the CIDR via the owner", func() bool { return k.hasNet(cidr, highIface()) })
			waitHost(t, k, ip, highIface())
			if k.hasNet(cidr, lowIface) {
				t.Fatal("the lower-priority client must not route a CIDR the owner routes")
			}
			waitFor(t, "the refusal event", func() bool {
				for _, ev := range d.activity.List(0, 0) {
					if ev.Kind == activity.KindRefused && ev.Name == cidr {
						return true
					}
				}
				return false
			})

			// Owner down: the entries go direct, not through the lower tunnel.
			if tc.highDetected {
				e.disconnectAWS()
				waitFor(t, "the AWS session to go", func() bool { return d.sessions.get(awsIface) == nil })
			} else {
				if err := d.ProfileDisconnect(high); err != nil {
					t.Fatal(err)
				}
			}
			waitFor(t, "the owner's routes to go", func() bool { return !k.hasNet(cidr, highIface()) })
			waitNoHost(t, k, ip)
			d.syncRoutes(d.currentGeneration())
			d.syncRoutes(d.currentGeneration())
			if k.hasNet(cidr, lowIface) || len(k.netRoutes()) != 0 {
				t.Errorf("with the owner down the CIDR must go direct, nets = %v", k.netRoutes())
			}
			if _, ok := k.hostRoute(ip); ok {
				t.Error("with the owner down the IP must go direct")
			}

			// Owner back: it takes the entries again.
			connectHigh()
			waitFor(t, "the CIDR via the owner again", func() bool { return k.hasNet(cidr, highIface()) })
		})
	}
}

func TestAnEntryWhoseOwnerIsDegradedGoesDirect(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	d := e.d
	high := e.importWireGuard(t, "High", "vpn.example.com:51820")
	low := e.importOutline(t, "Low", "198.51.100.7")
	e.setList(t, high, "10.82.0.0/16", "10.83.0.1", "10.83.0.2")
	e.setList(t, low, "10.82.0.0/16", "10.83.0.1", "10.84.0.1")
	highIface, lowIface := e.connect(t, high), e.connect(t, low)
	waitHost(t, k, "10.83.0.1", highIface)
	waitHost(t, k, "10.84.0.1", lowIface)

	// High cannot delete a route, which degrades it.
	k.failNext("delete -host 10.83.0.2", errors.New("route: delete: operation not permitted"))
	if err := d.SetDomains(config.ProfileClientID("wireguard", high), []string{"10.82.0.0/16", "10.83.0.1"}, 0); err != nil {
		t.Fatal(err)
	}
	d.syncRoutes(d.currentGeneration())
	if degraded, _ := d.sessions.get(highIface).manager.Degraded(); !degraded {
		t.Fatal("test setup: the high-priority profile should be degraded")
	}
	d.syncRoutes(d.currentGeneration())
	if k.hasNet("10.82.0.0/16", lowIface) {
		t.Error("a CIDR whose owner is degraded must not route through the lower-priority profile")
	}
	if iface, ok := k.hostRoute("10.83.0.1"); ok && iface == lowIface {
		t.Error("an IP whose owner is degraded must not route through the lower-priority profile")
	}
	// The lower profile still routes what only it lists.
	waitHost(t, k, "10.84.0.1", lowIface)
}

func TestAnAnyVPNEntryAClientAlsoListsBelongsToThatClient(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"10.85.0.1", "any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	d := e.d
	p := e.importOutline(t, "Owner", "198.51.100.7")
	e.setList(t, p, "10.85.0.1")
	e.connectAWS()
	waitForSession(t, d, awsIface)
	iface := e.connect(t, p)
	waitHost(t, k, "10.85.0.1", iface)
	if err := d.ProfileDisconnect(p); err != nil {
		t.Fatal(err)
	}
	waitNoHost(t, k, "10.85.0.1")
	d.syncRoutes(d.currentGeneration())
	if _, ok := k.hostRoute("10.85.0.1"); ok {
		t.Error("an entry a client lists must not fall to the Any VPN owner when that client is down")
	}
}

// --- one key and one address per WireGuard profile ---

func TestWireGuardProfilesMustNotShareAKeyOrAnAddress(t *testing.T) {
	e := newBuiltinEnv(t, newFakeKernel(), []string{"any.example.com"}, nil, nil)
	d := e.d
	keyA := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
	keyB := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32))
	keyC := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 32))

	first, err := d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", Name: "First", WireguardConfig: wireGuardConfWith(keyA, "10.0.0.2/24")})
	if err != nil {
		t.Fatal(err)
	}

	// Same key, different address.
	_, err = d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", Name: "Clone", WireguardConfig: wireGuardConfWith(keyA, "10.0.1.2/24")})
	if !errors.Is(err, api.ErrRejected) || !strings.Contains(err.Error(), "this WireGuard key is already used by profile First") {
		t.Errorf("duplicate key error = %v", err)
	}
	if err != nil && strings.Contains(err.Error(), keyA) {
		t.Error("the duplicate-key error must never contain the key")
	}

	// Same address (any prefix length), different key.
	_, err = d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", Name: "Twin", WireguardConfig: wireGuardConfWith(keyB, "10.0.0.2/32")})
	if !errors.Is(err, api.ErrRejected) || !strings.Contains(err.Error(), "address 10.0.0.2 is already used by profile First") {
		t.Errorf("duplicate address error = %v", err)
	}
	if err != nil && (strings.Contains(err.Error(), keyB) || strings.Contains(err.Error(), keyA)) {
		t.Error("the duplicate-address error must never contain a key")
	}
	if len(d.store.Profiles()) != 1 || e.secrets.count() != 1 {
		t.Errorf("a refused import left state behind: %d profiles, %d secrets", len(d.store.Profiles()), e.secrets.count())
	}

	// Distinct key and address are fine, and Outline is never compared.
	second, err := d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", Name: "Second", WireguardConfig: wireGuardConfWith(keyB, "10.0.2.2/24")})
	if err != nil {
		t.Fatalf("a distinct config must be accepted: %v", err)
	}
	if _, err := d.ProfileImport(api.ProfileImportParams{Kind: "outline", Name: "Out", AccessKey: outlineAccessKey("198.51.100.7")}); err != nil {
		t.Fatalf("an Outline profile must not be compared with WireGuard ones: %v", err)
	}

	// Updating: the profile may keep its own key and address, but not take
	// another's.
	if err := d.ProfileUpdate(api.ProfileUpdateParams{ID: first, WireguardConfig: wireGuardConfWith(keyA, "10.0.0.2/24")}); err != nil {
		t.Errorf("re-submitting a profile's own config must be accepted: %v", err)
	}
	err = d.ProfileUpdate(api.ProfileUpdateParams{ID: second, WireguardConfig: wireGuardConfWith(keyA, "10.0.2.2/24")})
	if !errors.Is(err, api.ErrRejected) || !strings.Contains(err.Error(), "this WireGuard key is already used by profile First") || strings.Contains(err.Error(), keyA) {
		t.Errorf("update with another profile's key = %v", err)
	}
	err = d.ProfileUpdate(api.ProfileUpdateParams{ID: second, WireguardConfig: wireGuardConfWith(keyC, "10.0.0.2/24")})
	if !errors.Is(err, api.ErrRejected) || !strings.Contains(err.Error(), "address 10.0.0.2 is already used by profile First") || strings.Contains(err.Error(), keyC) {
		t.Errorf("update with another profile's address = %v", err)
	}
	// A refused update changes nothing: the old secret is still stored.
	if got, _ := e.secrets.ProfileSecret(second); !strings.Contains(got, keyB) {
		t.Error("a refused update must leave the stored credentials alone")
	}
	if err := d.ProfileUpdate(api.ProfileUpdateParams{ID: second, WireguardConfig: wireGuardConfWith(keyC, "10.0.3.2/24")}); err != nil {
		t.Errorf("a distinct replacement must be accepted: %v", err)
	}
}
