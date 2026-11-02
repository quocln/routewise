package route

import (
	"path/filepath"

	"github.com/quocln/routewise/internal/platform"
)

// defaultJournalPath is where the transition journal lives in production: in
// the helper's run directory under %ProgramData%, which only administrators
// and SYSTEM may write by default. Tests always override transactionStore.path
// with a t.TempDir() path.
var defaultJournalPath = filepath.Join(platform.RunDir(), "transition.json")
