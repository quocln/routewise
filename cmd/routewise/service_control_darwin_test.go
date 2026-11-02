//go:build darwin

package main

import (
	"os"
	"strings"
	"testing"
)

func TestVerifyProcessMatchesTheCommandName(t *testing.T) {
	if !verifyProcess(os.Getpid(), "routewise") {
		t.Error("the test binary is routewise.test and must match")
	}
	if verifyProcess(os.Getpid(), "no-such-name") {
		t.Error("a different name must not match")
	}
	if verifyProcess(1<<30, "routewise") {
		t.Error("a missing process must not match")
	}
}

func TestRestartTargetsTheInstalledLaunchdLabel(t *testing.T) {
	if helperLaunchdLabel != "com.routewise.helper" {
		t.Errorf("label = %q, want the label scripts/install.sh installs", helperLaunchdLabel)
	}
	if !strings.HasPrefix(psPath, "/") || !strings.HasPrefix(launchctlPath, "/") {
		t.Error("system tools must be run by absolute path")
	}
}
