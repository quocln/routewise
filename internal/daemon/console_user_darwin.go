//go:build darwin

package daemon

import (
	"fmt"
	"os"

	"github.com/quocln/routewise/internal/platform"
)

// consoleDevicePath is the device macOS chowns to whoever is logged in at the
// machine's own display. Comparing against its owner is what keeps a background
// process belonging to some other account from rerouting the console user's
// traffic, even though socket group membership lets it read status.
const consoleDevicePath = "/dev/console"

// consoleOwnerUID returns the owner of the console device.
func consoleOwnerUID() (uint32, error) {
	info, err := os.Stat(consoleDevicePath)
	if err != nil {
		return 0, err
	}
	uid, ok := platform.FileOwnerUID(info)
	if !ok {
		return 0, fmt.Errorf("console device owner is unavailable on this platform")
	}
	return uid, nil
}
