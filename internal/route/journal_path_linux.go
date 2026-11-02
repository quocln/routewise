//go:build linux

package route

// defaultJournalPath is where the transition journal lives in production:
// /run is the tmpfs systemd gives every root service, cleared at boot together
// with the routes the journal describes. Tests always override
// transactionStore.path with a t.TempDir() path.
const defaultJournalPath = "/run/routewise/transition.json"
