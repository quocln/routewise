//go:build darwin

package dns

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// scutilPath is the absolute path of scutil. The daemon runs as root, so it
// never resolves the tool through PATH.
const scutilPath = "/usr/sbin/scutil"

// scutilTimeout bounds one `scutil --dns` call so a wedged configd cannot
// stall a VPN connect.
const scutilTimeout = 3 * time.Second

// systemDNSConfig returns the system's resolver configuration in `scutil
// --dns` format, the text parseResolverBlocks reads.
func systemDNSConfig(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, scutilTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, scutilPath, "--dns").Output()
	if err != nil {
		return "", fmt.Errorf("scutil --dns: %w", err)
	}
	return string(out), nil
}
