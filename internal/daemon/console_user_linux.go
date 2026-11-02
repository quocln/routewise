//go:build linux

package daemon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// seatStatePath is the file systemd-logind keeps for the machine's own seat.
// Its ACTIVE_UID line names whoever is logged in at the local display, the
// Linux counterpart of the owner of macOS's /dev/console. Comparing against it
// is what keeps a background process belonging to some other account from
// rerouting the active user's traffic.
const seatStatePath = "/run/systemd/seats/seat0"

// consoleOwnerUID returns the uid of the active user on seat0.
func consoleOwnerUID() (uint32, error) {
	f, err := os.Open(seatStatePath)
	if err != nil {
		return 0, fmt.Errorf("read seat state: %w", err)
	}
	defer f.Close()
	return parseActiveSeatUID(f)
}

// parseActiveSeatUID reads the ACTIVE_UID value from logind's seat state. A
// seat with no active session (a headless machine, or a locked-out greeter)
// has no such line and reports an error, so only root may change routing.
func parseActiveSeatUID(r io.Reader) (uint32, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		value, ok := strings.CutPrefix(scanner.Text(), "ACTIVE_UID=")
		if !ok {
			continue
		}
		uid, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("seat state has an invalid ACTIVE_UID %q", value)
		}
		return uint32(uid), nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read seat state: %w", err)
	}
	return 0, fmt.Errorf("no active user on the local seat")
}
