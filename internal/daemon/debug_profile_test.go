package daemon

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/quocln/routewise/internal/api"
)

func profileDaemon(t *testing.T) *Daemon {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Daemon{baseCtx: ctx}
}

func TestProfileReturnsARealProfileOfEachKind(t *testing.T) {
	d := profileDaemon(t)
	for _, kind := range []api.ProfileKind{api.ProfileCPU, api.ProfileHeap, api.ProfileMutex} {
		data, err := d.Profile(kind, 1)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		// A pprof profile is gzip-compressed protobuf.
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: not a pprof file: %v", kind, err)
		}
		if _, err := io.ReadAll(reader); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
}

func TestProfileRefusesWhatItCannotDo(t *testing.T) {
	d := profileDaemon(t)
	for name, tt := range map[string]struct {
		kind    api.ProfileKind
		seconds int
	}{
		"no time":      {api.ProfileCPU, 0},
		"too long":     {api.ProfileCPU, api.MaxProfileSeconds + 1},
		"unknown kind": {"goroutine", 1},
	} {
		if _, err := d.Profile(tt.kind, tt.seconds); !errors.Is(err, api.ErrRejected) {
			t.Errorf("%s: err = %v, want ErrRejected", name, err)
		}
	}
}

func TestOnlyOneProfileRunsAtATime(t *testing.T) {
	d := profileDaemon(t)
	profileRunning.Store(true)
	defer profileRunning.Store(false)
	if _, err := d.Profile(api.ProfileHeap, 1); !errors.Is(err, api.ErrRejected) {
		t.Errorf("err = %v, want ErrRejected while one runs", err)
	}
}
