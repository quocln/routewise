//go:build darwin

package route

// defaultJournalPath is where the transition journal lives in production.
// Tests always override transactionStore.path with a t.TempDir() path.
const defaultJournalPath = "/var/run/routewise/transition.json"
