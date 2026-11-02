//go:build windows

package route

import (
	"fmt"
	"os"

	"github.com/quocln/routewise/internal/platform"
)

// checkJournalFileSecurity holds the journal to the Windows invariant: Go
// reports 0666 for every writable file there, so the mode says nothing. The
// owner and access list decide instead, the same rule the config file gets.
func checkJournalFileSecurity(path string, _ os.FileInfo) error {
	if err := platform.CheckFileSecurity(path); err != nil {
		return fmt.Errorf("%w: %v", ErrJournalInsecureMode, err)
	}
	return nil
}

// syncJournalDir does nothing: Windows cannot flush a directory handle, and
// the rename of the already flushed temp file is atomic on NTFS.
func syncJournalDir(string) error { return nil }
