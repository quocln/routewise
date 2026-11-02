package main

import (
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/quocln/routewise/internal/platform"
)

func TestWindowsInstallPlan(t *testing.T) {
	plan := newWindowsInstallPlan(`C:\Program Files`, `C:\ProgramData\RouteWise`, `C:\ProgramData\RouteWise\logs`,
		`C:\ProgramData\RouteWise\run`, `C:\ProgramData\RouteWise\config.yaml`)

	if want := filepath.Join(`C:\Program Files`, "RouteWise", "routewise.exe"); plan.ExePath != want {
		t.Errorf("ExePath = %q, want %q", plan.ExePath, want)
	}
	wantArgs := []string{"start", "--foreground", "--config", `C:\ProgramData\RouteWise\config.yaml`}
	if strings.Join(plan.Args, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Errorf("Args = %q, want %q", plan.Args, wantArgs)
	}
	if len(plan.Dirs) != 3 || plan.Dirs[0].SDDL != dataDirSDDL {
		t.Fatalf("Dirs = %+v: the data directory must come first with its own access list", plan.Dirs)
	}
	for _, d := range plan.Dirs[1:] {
		if d.SDDL != sharedDirSDDL || !strings.HasPrefix(d.Path, plan.Dirs[0].Path) {
			t.Errorf("%+v: logs and run belong under the data directory with the shared access list", d)
		}
	}
}

// aceRE reads one ACE of an SDDL string: (type;flags;rights;;;trustee).
var aceRE = regexp.MustCompile(`\((\w);(\w*);(\w+);;;(\w+)\)`)

func TestServiceDirectoryAccessListsKeepUsersReadOnly(t *testing.T) {
	for name, sddl := range map[string]string{"data": dataDirSDDL, "shared": sharedDirSDDL} {
		if !strings.HasPrefix(sddl, "D:P") {
			t.Errorf("%s: %q must be protected so ProgramData's permissive defaults are not inherited", name, sddl)
		}
		aces := aceRE.FindAllStringSubmatch(sddl, -1)
		if strings.Count(sddl, "(") != len(aces) {
			t.Errorf("%s: %q has entries this test cannot read", name, sddl)
		}
		trustees := map[string]bool{}
		for _, ace := range aces {
			trustee, rights := ace[4], ace[3]
			trustees[trustee] = true
			switch trustee {
			case "SY", "BA":
				if rights != "FA" {
					t.Errorf("%s: %s has %q, want full access", name, trustee, rights)
				}
			case "BU":
				mask, err := strconv.ParseUint(strings.TrimPrefix(rights, "0x"), 16, 32)
				if err != nil || platform.GrantsWrite(uint32(mask)) {
					t.Errorf("%s: Users right %q must be a read-only mask", name, rights)
				}
			default:
				t.Errorf("%s: unexpected trustee %s", name, trustee)
			}
		}
		for _, want := range []string{"SY", "BA", "BU"} {
			if !trustees[want] {
				t.Errorf("%s: no entry for %s", name, want)
			}
		}
	}
	// The data directory's own entry for Users must not flow to the database.
	if !strings.Contains(dataDirSDDL, "(A;;0x1200a9;;;BU)") {
		t.Error("Users must get read access on the data directory itself only")
	}
}

func TestWithDependenciesKeepsWhatAnAdministratorAdded(t *testing.T) {
	got := withDependencies([]string{"LanmanWorkstation", "nsi"}, helperServiceDependencies)
	want := []string{"LanmanWorkstation", "nsi", "Dnscache"}
	if !slices.Equal(got, want) {
		t.Fatalf("withDependencies = %v, want %v", got, want)
	}
	if got := withDependencies(nil, helperServiceDependencies); !slices.Equal(got, helperServiceDependencies) {
		t.Fatalf("withDependencies(nil) = %v", got)
	}
}
