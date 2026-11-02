//go:build !windows

package daemon

import "github.com/quocln/routewise/internal/platform"

// consoleSessionID has no meaning off Windows, where sessions are not how the
// console user is told apart: only a Windows peer is ever compared against it.
func consoleSessionID() (uint32, error) {
	return 0, platform.Unsupported("console session lookup")
}
