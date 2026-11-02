package daemon

import (
	"database/sql"

	"github.com/quocln/routewise/internal/activity"
)

// openActivityStore starts persisting activity into the shared database and
// resumes the sequence numbers after the stored ones, so they keep rising across
// restarts. The store is opened whether or not history is enabled, so enabling
// it later needs no restart; nothing is written while it is off. A failure is
// logged and leaves activity in memory only.
func (d *Daemon) openActivityStore(db *sql.DB) {
	store, err := activity.OpenStore(db, int(d.historyDays.Load()), d.logger)
	if err != nil {
		d.logger.Error("stored activity is unavailable; activity stays in memory", "error", err)
		return
	}
	latest, err := store.LatestSeq()
	if err != nil {
		d.logger.Error("stored activity is unavailable; activity stays in memory", "error", err)
		store.Close()
		return
	}
	d.activity.Resume(latest)
	d.activityStore = store
}

// closeActivityStore writes the queued events and stops the store.
func (d *Daemon) closeActivityStore() {
	if d.activityStore != nil {
		d.activityStore.Close()
	}
}

// storedActivity reads events from the activity table when that is the complete
// answer: history is on, the store still records, and the in-memory ring does
// not already hold everything newer than since (as it does for a client that
// follows closely). ok is false when the caller should use the ring.
func (d *Daemon) storedActivity(since uint64, limit int) (events []activity.Event, ok bool) {
	if d.activityStore == nil || !d.historyOn.Load() || !d.activityStore.Healthy() || d.activity.Covers(since) {
		return nil, false
	}
	events, err := d.activityStore.List(since, limit)
	if err != nil {
		d.logger.Warn("could not read stored activity; answering from memory", "error", err)
		return nil, false
	}
	return events, true
}
