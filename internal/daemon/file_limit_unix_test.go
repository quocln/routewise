//go:build unix

package daemon

import (
	"io"
	"log/slog"
	"syscall"
	"testing"
)

func TestRaiseFileLimitNeverLowersTheLimitsAndKeepsTheHardOne(t *testing.T) {
	var before syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &before); err != nil {
		t.Skip(err)
	}
	RaiseFileLimit(slog.New(slog.NewTextHandler(io.Discard, nil)))
	var after syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &after); err != nil {
		t.Fatal(err)
	}
	if after.Max != before.Max {
		t.Errorf("hard limit changed: %d -> %d", before.Max, after.Max)
	}
	if after.Cur < before.Cur {
		t.Errorf("soft limit lowered: %d -> %d", before.Cur, after.Cur)
	}
	if want := min(uint64(wantedOpenFiles), before.Max); before.Cur < want && after.Cur < min(want, 10240) {
		t.Errorf("soft limit = %d, want at least %d", after.Cur, min(want, 10240))
	}
}
