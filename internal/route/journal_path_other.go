//go:build !darwin && !linux && !windows

package route

// defaultJournalPath is where the transition journal lives in production on
// the other Unix systems, which clear /var/run at boot together with the routes
// the journal describes. Tests always override transactionStore.path with a
// t.TempDir() path.
const defaultJournalPath = "/var/run/routewise/transition.json"
