//go:build darwin

package tunnelnet

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recorder struct {
	calls [][]string
	err   error
}

func (r *recorder) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if r.err != nil {
		return []byte("boom"), r.err
	}
	return nil, nil
}

func TestAddAliasAndUpRecordExactArguments(t *testing.T) {
	r := &recorder{}
	if err := AddAlias(context.Background(), r, "utun7", "10.8.0.2/32", "10.8.0.2"); err != nil {
		t.Fatal(err)
	}
	if err := Up(context.Background(), r, "utun7"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"/sbin/ifconfig", "utun7", "inet", "10.8.0.2/32", "10.8.0.2", "alias"},
		{"/sbin/ifconfig", "utun7", "up"},
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls = %v, want %v", r.calls, want)
	}
}

func TestAddAliasAndUpWrapFailures(t *testing.T) {
	r := &recorder{err: errors.New("exit 1")}
	err := AddAlias(context.Background(), r, "utun7", "10.8.0.2", "10.8.0.2")
	if err == nil || !strings.Contains(err.Error(), "ifconfig utun7 inet 10.8.0.2") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("AddAlias err = %v", err)
	}
	err = Up(context.Background(), r, "utun7")
	if err == nil || !strings.Contains(err.Error(), "ifconfig utun7 up") {
		t.Fatalf("Up err = %v", err)
	}
}
