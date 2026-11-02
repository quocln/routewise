//go:build windows

package platform

import (
	"strings"
	"testing"
)

func TestWindowsPathsAreUnderProgramData(t *testing.T) {
	if !isWindowsAbs(ConfigDir()) || !strings.HasSuffix(ConfigFile(), `\RouteWise\config.yaml`) {
		t.Errorf("config = %q in %q", ConfigFile(), ConfigDir())
	}
	if DataDir() != ConfigDir() {
		t.Errorf("data dir %q should be the config dir %q", DataDir(), ConfigDir())
	}
	for name, p := range map[string]string{"log": LogFile(), "pid": PidFile()} {
		if !LogPathAllowed(p[:strings.LastIndex(p, `\`)]) && name == "log" {
			t.Errorf("the default %s path %q is outside the log roots", name, p)
		}
	}
}
