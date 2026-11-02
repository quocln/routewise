//go:build linux

package daemon

import (
	"strings"
	"testing"
)

func TestParseActiveSeatUID(t *testing.T) {
	const active = "IS_SEAT0=1\nCAN_MULTI_SESSION=1\nACTIVE=2\nACTIVE_UID=1000\nSESSIONS=2:1000\nUIDS=1000\n"
	uid, err := parseActiveSeatUID(strings.NewReader(active))
	if err != nil || uid != 1000 {
		t.Fatalf("parseActiveSeatUID = %d, %v; want 1000", uid, err)
	}

	for name, state := range map[string]string{
		"no active session": "IS_SEAT0=1\nCAN_MULTI_SESSION=1\n",
		"invalid uid":       "ACTIVE_UID=bob\n",
		"negative uid":      "ACTIVE_UID=-1\n",
		"empty":             "",
	} {
		if _, err := parseActiveSeatUID(strings.NewReader(state)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
