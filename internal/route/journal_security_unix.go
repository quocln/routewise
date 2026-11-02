//go:build !windows

package route

import (
	"fmt"
	"os"

	"github.com/quocln/routewise/internal/platform"
)

// checkJournalFileSecurity holds the journal to the Unix invariant: owned by
// root (or the daemon's own uid) with no group or world access.
func checkJournalFileSecurity(_ string, info os.FileInfo) error {
	if uid, ok := platform.FileOwnerUID(info); ok {
		if err := checkJournalOwnership(uid); err != nil {
			return err
		}
	}
	return checkJournalMode(info.Mode().Perm())
}

// syncJournalDir flushes the directory so the journal's rename survives a
// crash.
func syncJournalDir(dir string) error {
	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open transition journal dir: %w", err)
	}
	defer dirFile.Close()
	if err := dirFile.Sync(); err != nil {
		return fmt.Errorf("sync transition journal dir: %w", err)
	}
	return nil
}
