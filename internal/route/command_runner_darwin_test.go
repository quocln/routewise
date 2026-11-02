package route

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateToolBinaryAcceptsCanonicalTool(t *testing.T) {
	if err := validateToolBinary("/bin/sleep"); err != nil {
		t.Errorf("expected /bin/sleep to validate, got %v", err)
	}
}

func TestValidateToolBinaryRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := validateToolBinary(link); err == nil {
		t.Error("expected symlink to be rejected")
	}
}

func TestValidateToolBinaryRejectsNonRegular(t *testing.T) {
	dir := t.TempDir()
	if err := validateToolBinary(dir); err == nil {
		t.Error("expected directory to be rejected")
	}
}

func TestValidateToolBinaryRejectsWritableByOthers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0777); err != nil {
		t.Fatalf("write tool: %v", err)
	}

	if err := validateToolBinary(path); err == nil {
		t.Error("expected group/world-writable binary to be rejected")
	}
}

func TestValidateToolBinaryRejectsNonRootOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: every file this test creates is root-owned, so the rejection path cannot be exercised")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("write tool: %v", err)
	}

	if err := validateToolBinary(path); err == nil {
		t.Error("expected binary owned by the test's own non-root uid to be rejected")
	}
}

func TestExecRunnerRunSucceeds(t *testing.T) {
	r := &execRunner{
		tools:     map[string]string{"echo": "/bin/echo"},
		timeout:   5 * time.Second,
		maxOutput: 4096,
	}

	out, err := r.Run(context.Background(), "echo", "hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Errorf("Run output = %q, want %q", out, "hello")
	}
}

func TestExecRunnerRunUnknownTool(t *testing.T) {
	r := &execRunner{tools: map[string]string{"echo": "/bin/echo"}, timeout: time.Second, maxOutput: 4096}

	if _, err := r.Run(context.Background(), "nope"); err == nil {
		t.Error("expected error for unknown tool name")
	}
}

func TestExecRunnerRunTimesOut(t *testing.T) {
	r := &execRunner{
		tools:     map[string]string{"sleep": "/bin/sleep"},
		timeout:   50 * time.Millisecond,
		maxOutput: 4096,
	}

	_, err := r.Run(context.Background(), "sleep", "5")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout error, got %v", err)
	}
}

func TestExecRunnerRunOutputTooLarge(t *testing.T) {
	r := &execRunner{
		tools:     map[string]string{"echo": "/bin/echo"},
		timeout:   5 * time.Second,
		maxOutput: 4,
	}

	_, err := r.Run(context.Background(), "echo", "this line is definitely longer than four bytes")
	if err == nil {
		t.Fatal("expected output-too-large error")
	}
	if !strings.Contains(err.Error(), "exceeded maximum size") {
		t.Errorf("expected output-too-large error, got %v", err)
	}
}

func TestExecRunnerRunRejectsInsecureBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hi\n"), 0777); err != nil {
		t.Fatalf("write tool: %v", err)
	}

	r := &execRunner{
		tools:     map[string]string{"tool": path},
		timeout:   time.Second,
		maxOutput: 4096,
	}

	if _, err := r.Run(context.Background(), "tool"); err == nil {
		t.Error("expected insecure binary to be rejected before execution")
	}
}
