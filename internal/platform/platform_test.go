package platform

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestUnsupportedWrapsErrUnsupported(t *testing.T) {
	err := Unsupported("route table")
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error does not wrap ErrUnsupported: %v", err)
	}
	if !strings.Contains(err.Error(), "route table") {
		t.Errorf("error does not name the feature: %v", err)
	}
}

func TestFileOwnerUIDMatchesCurrentUserOnUnix(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	uid, ok := FileOwnerUID(info)
	if !ok {
		t.Skip("platform exposes no file owner")
	}
	if int(uid) != os.Geteuid() {
		t.Errorf("owner = %d, want %d", uid, os.Geteuid())
	}
}
