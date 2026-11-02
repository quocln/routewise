package route

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSessionJournalPathSitsNextToTheBaseJournal(t *testing.T) {
	got, err := SessionJournalPath("/var/run/routewise/transition.json", "utun7")
	if err != nil {
		t.Fatalf("SessionJournalPath: %v", err)
	}
	if want := filepath.FromSlash("/var/run/routewise/transition-utun7.json"); got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

func TestSessionJournalPathRejectsAnInterfaceThatCouldEscapeTheDirectory(t *testing.T) {
	ifaces := append([]string{"", "../utun7", "utun7/../../x"}, invalidInterfaceNames...)
	for _, iface := range ifaces {
		if got, err := SessionJournalPath("/var/run/routewise/transition.json", iface); err == nil {
			t.Errorf("SessionJournalPath(%q) = %q, want an error", iface, got)
		}
	}
}

func TestSessionJournalPathsListsOnlyTunnelJournals(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "transition.json")
	for _, name := range []string{
		"transition.json",        // the base journal is recovered separately
		"transition-utun7.json",  // a tunnel journal
		"transition-utun12.json", // another one
		"transition-.json",       // no interface
		"transition-bad'name.json",
		"transition-utun7.json.tmp",
		"other-utun7.json",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := SessionJournalPaths(base)
	if err != nil {
		t.Fatalf("SessionJournalPaths: %v", err)
	}
	slices.Sort(got)
	want := []string{filepath.Join(dir, "transition-utun12.json"), filepath.Join(dir, "transition-utun7.json")}
	if !slices.Equal(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}
}

func TestSessionJournalPathsToleratesAMissingDirectory(t *testing.T) {
	got, err := SessionJournalPaths(filepath.Join(t.TempDir(), "absent", "transition.json"))
	if err != nil || len(got) != 0 {
		t.Errorf("paths = %v, err = %v, want none and no error", got, err)
	}
}

func TestSessionManagerTakesTheCapturedGatewayAndSharesTheBaseConfiguration(t *testing.T) {
	base := NewManager()
	base.SetJournalPath(filepath.Join(t.TempDir(), "transition.json"))
	base.SetAdditiveMode(true)
	gw := netip.MustParseAddr("192.168.7.1")
	base.SetOriginalGateway(gw, "en0")

	session := NewManager()
	session.SetOriginalGateway(base.GetOriginalGateway(), base.GetLocalInterface())
	session.SetAdditiveMode(base.Additive())
	session.SetTable(base.Table())
	path, err := SessionJournalPath(base.JournalPath(), "utun7")
	if err != nil {
		t.Fatal(err)
	}
	session.SetJournalPath(path)

	if session.GetOriginalGateway() != gw || session.GetLocalInterface() != "en0" {
		t.Errorf("gateway = %v on %q, want %v on en0", session.GetOriginalGateway(), session.GetLocalInterface(), gw)
	}
	if !session.Additive() {
		t.Error("the session manager must inherit the additive mode")
	}
	if session.JournalPath() != path {
		t.Errorf("journal path = %q, want %q", session.JournalPath(), path)
	}
	if session.Table() != base.Table() {
		t.Error("the session manager must share the base routing table")
	}
}

func TestGetRouteReportsTheRouteHeldForADestination(t *testing.T) {
	m := NewManager()
	ip := netip.MustParseAddr("10.1.1.1")
	m.mu.Lock()
	m.activeRoutes[ip] = RouteInfo{Destination: ip, SourceDomain: "a.example", IsProtected: true}
	m.mu.Unlock()

	if info, ok := m.GetRoute(ip); !ok || info.SourceDomain != "a.example" || !info.IsProtected {
		t.Errorf("GetRoute = %+v, %v", info, ok)
	}
	if _, ok := m.GetRoute(netip.MustParseAddr("10.1.1.2")); ok {
		t.Error("an unrouted destination must report no route")
	}
}

func TestJournalTokenEncodesNamesAFileCannotHold(t *testing.T) {
	for _, iface := range []string{"wg0", "utun7", "Ethernet 2", "VPN: a*b", "Wi-Fi.", "x"} {
		token := encodeJournalToken(iface)
		if strings.ContainsAny(token, `*?:<>| .`) {
			t.Errorf("token %q for %q is not a safe file name", token, iface)
		}
		got, ok := decodeJournalToken(token)
		if !ok || got != iface {
			t.Errorf("decode(%q) = %q, %v; want %q", token, got, ok, iface)
		}
	}
	if got := encodeJournalToken("utun7"); got != "utun7" {
		t.Errorf("a plain name must stay readable, got %q", got)
	}
	if _, ok := decodeJournalToken("~zz"); ok {
		t.Error("malformed token must not decode")
	}
}
