package tunnelnet

import (
	"net/netip"
	"testing"
)

func TestFreeTunNameSkipsTakenNamesIgnoringCase(t *testing.T) {
	cases := []struct {
		existing []string
		want     string
	}{
		{nil, "rwtun0"},
		{[]string{"Ethernet", "Wi-Fi", "wg0"}, "rwtun0"},
		{[]string{"rwtun0"}, "rwtun1"},
		{[]string{"RWTUN0", "rwtun1", "rwtun3"}, "rwtun2"},
	}
	for _, c := range cases {
		if got := freeTunName(c.existing); got != c.want {
			t.Errorf("freeTunName(%v) = %q, want %q", c.existing, got, c.want)
		}
	}
}

func TestTunGUIDIsStablePerNameAndWellFormed(t *testing.T) {
	a1, a2, a3, a4 := tunGUID("rwtun0")
	b1, b2, b3, b4 := tunGUID("RWTUN0")
	if a1 != b1 || a2 != b2 || a3 != b3 || a4 != b4 {
		t.Fatal("the GUID must not depend on case")
	}
	c1, _, _, _ := tunGUID("rwtun1")
	if a1 == c1 {
		t.Fatal("different names need different GUIDs")
	}
	if a3>>12 != 5 || a4[0]>>6 != 2 {
		t.Fatalf("version/variant bits wrong: %x %x", a3, a4[0])
	}
}

func TestPlanWindowsAddress(t *testing.T) {
	plan, err := planWindowsAddress("10.9.0.2", "10.9.0.2")
	if err != nil || plan.Local != netip.MustParsePrefix("10.9.0.2/32") || plan.Peer.IsValid() {
		t.Fatalf("got %+v %v, want a plain /32 and no peer route", plan, err)
	}
	plan, err = planWindowsAddress("10.9.0.2", "10.9.0.1")
	if err != nil || plan.Peer != netip.MustParseAddr("10.9.0.1") {
		t.Fatalf("got %+v %v, want a peer route", plan, err)
	}
	plan, err = planWindowsAddress("10.9.0.2/24", "10.9.0.2")
	if err != nil || plan.Local != netip.MustParsePrefix("10.9.0.2/24") {
		t.Fatalf("got %+v %v", plan, err)
	}
	for _, bad := range [][2]string{{"fd00::2", "fd00::1"}, {"10.9.0.2", "fd00::1"}, {"nope", "10.9.0.1"}, {"10.9.0.2", "nope"}} {
		if _, err := planWindowsAddress(bad[0], bad[1]); err == nil {
			t.Errorf("planWindowsAddress(%q, %q) must fail", bad[0], bad[1])
		}
	}
}
