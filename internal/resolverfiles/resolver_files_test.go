package resolverfiles

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestApplyWritesMarkedFilesPointingAtTheForwarder(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, "127.0.0.1", 53053)

	skipped, err := m.Apply([]string{"corp.example.com", "Staging.Example.com"})
	if err != nil || len(skipped) != 0 {
		t.Fatalf("Apply = %v, %v", skipped, err)
	}

	content := readFile(t, filepath.Join(dir, "corp.example.com"))
	want := Marker + "\nnameserver 127.0.0.1\nport 53053\n"
	if content != want {
		t.Errorf("content = %q, want %q", content, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "staging.example.com")); err != nil {
		t.Errorf("expected the domain to be lowercased into its file name: %v", err)
	}
	if got := m.Active(); !slices.Equal(got, []string{"corp.example.com", "staging.example.com"}) {
		t.Errorf("Active = %v", got)
	}
}

func TestApplyNeverTouchesFilesItDoesNotOwn(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "corp.example.com")
	if err := os.WriteFile(foreign, []byte("nameserver 10.0.0.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := New(dir, "127.0.0.1", 53053)

	skipped, err := m.Apply([]string{"corp.example.com"})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !slices.Equal(skipped, []string{"corp.example.com"}) {
		t.Errorf("skipped = %v, want the foreign domain reported", skipped)
	}
	if got := readFile(t, foreign); got != "nameserver 10.0.0.53\n" {
		t.Errorf("foreign file was modified: %q", got)
	}

	if err := m.RemoveAll(); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("RemoveAll deleted a file RouteWise does not own: %v", err)
	}
}

func TestApplyRemovesOwnedFilesNoLongerWanted(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, "127.0.0.1", 53053)
	if _, err := m.Apply([]string{"a.example.com", "b.example.com"}); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Apply([]string{"b.example.com"}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "a.example.com")); !os.IsNotExist(err) {
		t.Errorf("expected the dropped domain's file removed, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.example.com")); err != nil {
		t.Errorf("expected the kept domain's file to remain: %v", err)
	}
}

func TestRemoveAllSweepsFilesLeftByAnEarlierProcess(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, "127.0.0.1", 53053).Apply([]string{"corp.example.com"}); err != nil {
		t.Fatal(err)
	}

	// A new process starts with no memory of what the old one wrote.
	fresh := New(dir, "127.0.0.1", 53053)
	if err := fresh.RemoveAll(); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected the stale file swept, found %v", entries)
	}
}

func TestApplyRejectsNamesThatCouldEscapeTheDirectory(t *testing.T) {
	m := New(t.TempDir(), "127.0.0.1", 53053)
	for _, bad := range []string{"../etc/hosts", "com", "corp.example.com/x", "*.example.com"} {
		if _, err := m.Apply([]string{bad}); err == nil || !strings.Contains(err.Error(), "not a valid domain") {
			t.Errorf("Apply(%q) error = %v, want a rejection", bad, err)
		}
	}
}

func TestRemoveAllOnMissingDirectoryIsANoOp(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "absent"), "127.0.0.1", 53053)
	if err := m.RemoveAll(); err != nil {
		t.Errorf("RemoveAll on a missing directory = %v, want nil", err)
	}
}
