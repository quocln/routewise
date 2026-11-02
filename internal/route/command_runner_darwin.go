//go:build darwin

package route

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/quocln/routewise/internal/platform"
)

const (
	// commandTimeout bounds every privileged subprocess so a hung tool can
	// never block route mutation indefinitely.
	commandTimeout = 10 * time.Second

	// maxCommandOutput caps captured stdout so a misbehaving tool cannot
	// exhaust memory.
	maxCommandOutput = 256 * 1024

	// maxNetstatOutput is the cap for netstat, whose output grows with the
	// routing table: about 70 bytes a row, so 256 KiB would end at a table of
	// roughly 3,700 routes. Production reads the table in process and runs
	// netstat only when that fails.
	maxNetstatOutput = 8 * 1024 * 1024
)

// canonicalToolPaths maps a logical tool name to the one absolute path this
// package will ever execute for it. Tools are never resolved via PATH.
var canonicalToolPaths = map[string]string{
	toolRoute:   "/sbin/route",
	toolNetstat: "/usr/sbin/netstat",
}

// errOutputTooLarge marks a subprocess whose combined output exceeded the
// configured cap. The command is treated as failed rather than silently
// truncated, since a partial route table must never be parsed as complete.
var errOutputTooLarge = errors.New("command output exceeded maximum size")

// capturedOutput is a bounded io.Writer: once more than limit bytes have been
// offered to it, further writes fail so the subprocess pipe is no longer
// drained and the child's output stops growing our memory.
type capturedOutput struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func (c *capturedOutput) Write(p []byte) (int, error) {
	if c.exceeded {
		return 0, errOutputTooLarge
	}
	if c.buf.Len()+len(p) > c.limit {
		c.exceeded = true
		return 0, errOutputTooLarge
	}
	return c.buf.Write(p)
}

// execRunner is the production commandRunner. Tool paths, timeout, and
// output cap are fields (not constants) purely so tests can point at a
// harmless real binary (e.g. /bin/sleep) to exercise real timeout/output-cap
// behavior without ever invoking route or netstat.
type execRunner struct {
	tools     map[string]string
	timeout   time.Duration
	maxOutput int
	// toolMaxOutput overrides maxOutput for a tool.
	toolMaxOutput map[string]int
}

func newExecRunner() *execRunner {
	return &execRunner{
		tools:     canonicalToolPaths,
		timeout:   commandTimeout,
		maxOutput: maxCommandOutput,

		toolMaxOutput: map[string]int{toolNetstat: maxNetstatOutput},
	}
}

// defaultRunner is the process-wide production runner used by every package
// helper unless a Manager has an injected fake for testing.
var defaultRunner = newExecRunner()

// validateToolBinary rejects anything other than a root-owned, non-symlink,
// non-group/world-writable regular file. It runs on every invocation (not
// just once at startup) so a binary swapped out after the daemon started is
// still caught.
func validateToolBinary(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat tool binary: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("tool binary %s is a symlink; refusing to execute", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("tool binary %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0022 != 0 {
		return fmt.Errorf("tool binary %s is group- or world-writable (mode %o)", path, perm.Perm())
	}
	if uid, ok := platform.FileOwnerUID(info); ok && uid != 0 {
		return fmt.Errorf("tool binary %s is owned by uid %d, not root", path, uid)
	}
	return nil
}

// Run resolves tool by canonical path only (never PATH), validates the
// binary, bounds execution with a timeout, caps captured output, and passes
// args through as a fixed argv with no shell interpretation.
func (r *execRunner) Run(ctx context.Context, tool string, args ...string) (string, error) {
	path, ok := r.tools[tool]
	if !ok {
		return "", fmt.Errorf("unknown tool %q", tool)
	}
	if err := validateToolBinary(path); err != nil {
		return "", fmt.Errorf("%s: %w", tool, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, path, args...)
	limit := r.maxOutput
	if override, ok := r.toolMaxOutput[tool]; ok {
		limit = override
	}
	stdout := &capturedOutput{limit: limit}
	var stderr bytes.Buffer
	cmd.Stdout = stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if stdout.exceeded {
		return "", fmt.Errorf("%s %s: %w", tool, strings.Join(args, " "), errOutputTooLarge)
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("%s %s: timed out after %s", tool, strings.Join(args, " "), r.timeout)
	}
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", tool, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.buf.String(), nil
}

// systemTable is the table the daemon drives on macOS: the command table's logic, with
// its common route changes carried out on a routing socket, and route(8) and netstat,
// run by absolute path through the validating runner, for the rest.
func systemTable() Table { return newCommandTable(newRouteSocketRunner(defaultRunner)) }
