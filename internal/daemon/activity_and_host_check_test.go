package daemon

import (
	"net/netip"
	"testing"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/dnswatch"
)

func eventsOfKind(d *Daemon, kind activity.Kind) []activity.Event {
	var out []activity.Event
	_, events := d.Activity(0, 0, 0)
	for _, e := range events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func TestActivityRecordsConnectRoutesAndDisconnect(t *testing.T) {
	d, watcher, _, _ := newDNSTestDaemonWith(t, nil, "api.rw-test.invalid")

	connect(watcher)
	s := waitForSession(t, d, "utun9")
	if err := s.manager.AddRoute(netip.MustParseAddr("10.20.30.40"), "api.rw-test.invalid", false); err != nil {
		t.Fatal(err)
	}
	disconnect(watcher)
	waitFor(t, "the disconnect to be recorded", func() bool {
		for _, e := range eventsOfKind(d, activity.KindVPN) {
			if e.Detail == "disconnected" {
				return true
			}
		}
		return false
	})

	added := eventsOfKind(d, activity.KindRouteAdded)
	if len(added) != 1 || added[0].Name != "api.rw-test.invalid" || added[0].Addresses[0].Verdict != activity.ViaVPN || added[0].Interface != "utun9" {
		t.Fatalf("route events = %+v, want the /32 for api.rw-test.invalid through utun9", added)
	}
	if added[0].VPN != s.client.Name || added[0].List == nil || added[0].Rule != "api.rw-test.invalid" {
		t.Errorf("route event = %+v, want the tunnel %q and the matched entry", added[0], s.client.Name)
	}
	if vpn := eventsOfKind(d, activity.KindVPN); len(vpn) < 2 || vpn[0].Detail != "connected" {
		t.Fatalf("VPN events = %+v, want connected then disconnected", vpn)
	}
}

func TestDNSAnswersAreMarkedVPNOrDirectAndDeduplicated(t *testing.T) {
	d, watcher, _, _ := newDNSTestDaemonWith(t, nil, "api.rw-test.invalid")
	connect(watcher)
	s := waitForSession(t, d, "utun9")
	routed := netip.MustParseAddr("10.20.30.40")
	if err := s.manager.AddRoute(routed, "api.rw-test.invalid", false); err != nil {
		t.Fatal(err)
	}

	answer := dnswatch.Answer{
		Name:      "api.rw-test.invalid",
		Addresses: []netip.Addr{routed, netip.MustParseAddr("93.184.216.34")},
		Server:    netip.MustParseAddr("1.1.1.1"),
		Interface: "en0",
	}
	d.recordDNSAnswer(answer)
	d.recordDNSAnswer(answer) // the same answer from a second server

	dnsEvents := eventsOfKind(d, activity.KindDNS)
	if len(dnsEvents) != 1 {
		t.Fatalf("DNS events = %d, want the duplicate dropped", len(dnsEvents))
	}
	got := dnsEvents[0].Addresses
	if got[0].Verdict != activity.ViaVPN || got[1].Verdict != activity.Direct {
		t.Fatalf("verdicts = %+v, want the routed address via VPN and the other direct", got)
	}
	// The answer is attributed to the tunnel carrying its routed address and to
	// the list entry its name matches.
	if dnsEvents[0].VPN != s.client.Name {
		t.Errorf("dns vpn = %q, want %q", dnsEvents[0].VPN, s.client.Name)
	}
	if dnsEvents[0].List == nil || dnsEvents[0].Rule != "api.rw-test.invalid" {
		t.Errorf("dns list = %v rule = %q, want the matched entry", dnsEvents[0].List, dnsEvents[0].Rule)
	}
}

func TestDNSAnswerNoTunnelCarriesHasNoVPNAndAnUnlistedNameNoList(t *testing.T) {
	d, _, _, _ := newDNSTestDaemonWith(t, nil, "api.rw-test.invalid")
	d.recordDNSAnswer(dnswatch.Answer{
		Name:      "unlisted.example.org",
		Addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
		Server:    netip.MustParseAddr("1.1.1.1"),
		Interface: "en0",
	})
	events := eventsOfKind(d, activity.KindDNS)
	if len(events) != 1 || events[0].VPN != "" || events[0].List != nil || events[0].Rule != "" {
		t.Fatalf("events = %+v, want no vpn, list or rule", events)
	}
}

func TestCheckHostAsksTheKernelForEachAddress(t *testing.T) {
	d, watcher, _, runner := newDNSTestDaemonWith(t, nil, "*.rw-test.invalid")
	runner.getOutput = func(host string) string {
		if host == "10.20.30.40" {
			return "   route to: 10.20.30.40\n  interface: utun9\n"
		}
		return "   route to: " + host + "\n    gateway: 192.168.7.1\n  interface: en0\n"
	}
	connect(watcher)
	waitForSession(t, d, "utun9")

	viaVPN, err := d.CheckHost("https://10.20.30.40:8443/login")
	if err != nil {
		t.Fatal(err)
	}
	if viaVPN.Host != "10.20.30.40" || viaVPN.Addresses[0].Verdict != "vpn" || viaVPN.Addresses[0].Interface != "utun9" {
		t.Fatalf("check = %+v, want 10.20.30.40 through utun9", viaVPN)
	}

	direct, err := d.CheckHost("93.184.216.34")
	if err != nil {
		t.Fatal(err)
	}
	if direct.Addresses[0].Verdict != "direct" || direct.Addresses[0].Gateway != "192.168.7.1" {
		t.Fatalf("check = %+v, want direct via 192.168.7.1", direct)
	}

	if _, err := d.CheckHost("   "); err == nil {
		t.Fatal("an empty host must be rejected")
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Jira.Corp.Example.com.":                 "jira.corp.example.com",
		"https://jira.corp.example.com/browse/X": "jira.corp.example.com",
		"jira.corp.example.com:443":              "jira.corp.example.com",
		" 10.0.0.1 ":                             "10.0.0.1",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
