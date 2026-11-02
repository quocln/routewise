package platform

import (
	"runtime"
	"testing"
)

func TestPathsPerOS(t *testing.T) {
	want := map[string]map[string]string{
		"darwin": {
			"config": "/Library/Application Support/RouteWise/config.yaml",
			"data":   "/Library/Application Support/RouteWise",
			"log":    "/var/log/routewise.log",
			"pid":    "/var/run/routewise.pid",
			"owner":  "root:wheel",
		},
		"linux": {
			"config": "/etc/routewise/config.yaml",
			"data":   "/var/lib/routewise",
			"log":    "/var/log/routewise/routewise.log",
			"pid":    "/run/routewise.pid",
			"owner":  "root:root",
		},
	}[runtime.GOOS]
	if want == nil {
		t.Skipf("no layout defined for %s", runtime.GOOS)
	}
	got := map[string]string{
		"config": ConfigFile(), "data": DataDir(), "log": LogFile(), "pid": PidFile(), "owner": RootOwner(),
	}
	for key, w := range want {
		if got[key] != w {
			t.Errorf("%s = %q, want %q", key, got[key], w)
		}
	}
}

func TestLogRootsReturnsACopy(t *testing.T) {
	roots := LogRoots()
	if len(roots) == 0 {
		t.Fatal("no log roots")
	}
	roots[0] = "/changed"
	if LogRoots()[0] == "/changed" {
		t.Error("LogRoots exposes its backing slice")
	}
}
