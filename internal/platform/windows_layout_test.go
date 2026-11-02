package platform

import (
	"errors"
	"testing"
)

func TestWindowsLayout(t *testing.T) {
	l := windowsLayout(`D:\ProgramData\`)
	for name, got := range map[string]string{
		"root": l.root, "log": l.logDir, "run": l.runDir, "root of logs": l.logRoots[0],
	} {
		want := map[string]string{
			"root":         `D:\ProgramData\RouteWise`,
			"log":          `D:\ProgramData\RouteWise\logs`,
			"run":          `D:\ProgramData\RouteWise\run`,
			"root of logs": `D:\ProgramData\RouteWise`,
		}[name]
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestResolveProgramData(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "ProgramData" {
				return v
			}
			return ""
		}
	}
	known := func(p string, err error) func() (string, error) {
		return func() (string, error) { return p, err }
	}
	for name, c := range map[string]struct {
		known func() (string, error)
		env   string
		want  string
	}{
		"known folder wins":         {known(`E:\PD`, nil), `F:\Other`, `E:\PD`},
		"known folder fails":        {known("", errors.New("no shell")), `F:\Other`, `F:\Other`},
		"known folder not absolute": {known(`PD`, nil), `F:\Other`, `F:\Other`},
		"env not absolute":          {nil, `..\x`, defaultProgramData},
		"nothing set":               {nil, "", defaultProgramData},
		"unc":                       {known(`\\srv\share`, nil), "", `\\srv\share`},
	} {
		if got := resolveProgramData(c.known, env(c.env)); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}

func TestWithinRoot(t *testing.T) {
	for _, c := range []struct {
		dir, root string
		fold      bool
		want      bool
	}{
		{"/var/log", "/var/log", false, true},
		{"/var/log/routewise", "/var/log", false, true},
		{"/var/logs", "/var/log", false, false},
		{"/var/logevil/x", "/var/log", false, false},
		{"/VAR/log", "/var/log", false, false},
		{`C:\ProgramData\RouteWise\logs`, `C:\ProgramData\RouteWise`, true, true},
		{`c:/programdata/routewise/logs`, `C:\ProgramData\RouteWise`, true, true},
		{`C:\ProgramData\RouteWiseX`, `C:\ProgramData\RouteWise`, true, false},
		{`C:\Users\me`, `C:\ProgramData\RouteWise`, true, false},
	} {
		if got := withinRoot(c.dir, c.root, c.fold); got != c.want {
			t.Errorf("withinRoot(%q, %q, fold=%v) = %v, want %v", c.dir, c.root, c.fold, got, c.want)
		}
	}
}

func TestTrustedOwnerSID(t *testing.T) {
	for sid, want := range map[string]bool{
		sidSystem: true, sidAdministrators: true, sidTrustedInstaller: true,
		sidUsers: false, sidEveryone: false, "S-1-5-21-1-2-3-1001": false, "": false,
	} {
		if got := TrustedOwnerSID(sid); got != want {
			t.Errorf("TrustedOwnerSID(%q) = %v, want %v", sid, got, want)
		}
	}
}

func TestLowPrivilegeWriters(t *testing.T) {
	const fullControl, readExecute = 0x1f01ff, 0x1200a9
	for name, c := range map[string]struct {
		entries []accessEntry
		want    int
	}{
		"admins and system only":       {[]accessEntry{{sidSystem, fullControl, false, false}, {sidAdministrators, fullControl, false, false}}, 0},
		"users read":                   {[]accessEntry{{sidUsers, readExecute, false, false}}, 0},
		"users write":                  {[]accessEntry{{sidUsers, fileWriteData, false, false}}, 1},
		"everyone append":              {[]accessEntry{{sidEveryone, fileAppendData, false, false}}, 1},
		"authenticated users full":     {[]accessEntry{{sidAuthenticatedUser, fullControl, false, false}}, 1},
		"generic all":                  {[]accessEntry{{sidInteractive, genericAll, false, false}}, 1},
		"write dac":                    {[]accessEntry{{sidUsers, accessWriteDAC, false, false}}, 1},
		"a deny entry is not a grant":  {[]accessEntry{{sidUsers, fullControl, true, false}}, 0},
		"inherit only is for children": {[]accessEntry{{sidUsers, fullControl, false, true}}, 0},
		"another account can write":    {[]accessEntry{{"S-1-5-21-1-2-3-1001", fullControl, false, false}}, 1},
		"another account can read":     {[]accessEntry{{"S-1-5-21-1-2-3-1001", readExecute, false, false}}, 0},
		"creator owner, inherit only":  {[]accessEntry{{"S-1-3-0", fullControl, false, true}}, 0},
		"trusted installer":            {[]accessEntry{{sidTrustedInstaller, fullControl, false, false}}, 0},
	} {
		if got := len(lowPrivilegeWriters(c.entries)); got != c.want {
			t.Errorf("%s: %d writers, want %d", name, got, c.want)
		}
	}
	if GrantsWrite(readExecute) || !GrantsWrite(fullControl) {
		t.Error("GrantsWrite misclassifies read/execute or full control")
	}
}
