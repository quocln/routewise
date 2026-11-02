//go:build !darwin && !linux

package daemon

import "github.com/quocln/routewise/internal/platform"

// consoleOwnerUID reports that the logged-in console user cannot be determined
// here, so only root is ever allowed to change routing.
func consoleOwnerUID() (uint32, error) {
	return 0, platform.Unsupported("console user lookup")
}
