package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/configdb"
	"github.com/quocln/routewise/internal/dnswatch"
	"github.com/quocln/routewise/internal/history"
	"github.com/quocln/routewise/internal/ifacename"
)

// OpenHistory starts recording into the shared database: the access history
// and the activity log. History is disposable and never worth stopping the
// helper for: a failure is logged and leaves the helper running without it. It
// first moves a legacy history.db, if one is beside the database, into the
// access table (see history.MigrateLegacy); a failed move leaves the file for
// the next start. Call it before Start.
func (d *Daemon) OpenHistory(db *configdb.DB) {
	logDB, err := db.LogDB()
	if err != nil {
		d.logger.Error("access history is unavailable", "path", db.Path(), "error", err)
		return
	}
	ctx := d.baseCtx
	if ctx == nil {
		ctx = context.Background()
	}
	legacy := history.LegacyPathFor(db.Path())
	if n, err := history.MigrateLegacy(ctx, logDB, legacy); err != nil {
		d.logger.Error("could not move the old access history into the shared database; "+
			history.LegacyFileName+" stays in place and the move is retried at the next start",
			"path", legacy, "error", err)
	} else if n > 0 {
		d.logger.Info("moved the old access history into the shared database", "rows", n, "from", legacy)
	}

	d.openActivityStore(logDB)
	store, err := history.Open(logDB, int(d.historyDays.Load()), d.logger)
	if err != nil {
		d.logger.Error("access history is unavailable", "path", db.Path(), "error", err)
		return
	}
	d.history = store
	if d.dnsWatcher != nil {
		d.dnsWatcher.SetFlowsEnabled(d.historyOn.Load())
	}
	d.logger.Info("access history opened", "path", db.Path(),
		"enabled", d.historyOn.Load(), "retention_days", d.historyDays.Load())
}

// closeHistory flushes and closes the access history store. The shared
// database stays open for its owner.
func (d *Daemon) closeHistory() {
	if d.history == nil {
		return
	}
	if err := d.history.Close(); err != nil {
		d.logger.Warn("could not close the access history", "error", err)
	}
}

// onFlow records one outbound connection start. It runs on a capture
// goroutine and only queues the record.
func (d *Daemon) onFlow(f dnswatch.Flow) {
	if d.history == nil || !d.historyOn.Load() {
		return
	}
	verdict, vpn := d.flowVerdict(f.Interface)
	e := history.Entry{
		Time:      f.Time.UTC(),
		IP:        f.Dst.Unmap().String(),
		Port:      int(f.DstPort),
		Proto:     string(f.Proto),
		Interface: f.Interface,
		VPN:       vpn,
		Verdict:   verdict,
	}
	if name, ok := d.names.Lookup(f.Dst); ok {
		e.Name = name
	}
	if m, ok := d.store.Policy().matchingEntry(e.Name, f.Dst); ok {
		e.List, e.Rule = &m.list, m.rule
	}
	d.history.Record(e)
}

// flowVerdict decides from the capture interface alone: a managed tunnel is
// "vpn" and names its client, any other tunnel is "other", and everything else
// is "direct".
func (d *Daemon) flowVerdict(iface string) (verdict, vpn string) {
	if s := d.sessions.get(iface); s != nil {
		return history.VerdictVPN, s.client.Name
	}
	if ifacename.IsTunnel(iface) {
		return history.VerdictOther, ""
	}
	return history.VerdictDirect, ""
}

// AccessList answers an access history query. A long-poll holds until a
// matching record exists, the wait ends, or the helper stops.
func (d *Daemon) AccessList(q api.AccessListParams) (api.AccessListResult, error) {
	ctx := d.baseCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if d.history == nil {
		return d.listWithoutHistory(ctx, q)
	}
	res, err := d.history.List(ctx, q)
	if err != nil {
		if errors.Is(err, history.ErrInvalidQuery) {
			return api.AccessListResult{}, fmt.Errorf("%w: %v", api.ErrRejected, err)
		}
		return api.AccessListResult{}, err
	}
	return res, nil
}

// listWithoutHistory answers while no store exists: an empty history. A
// long-poll still waits, or a following client would spin.
func (d *Daemon) listWithoutHistory(ctx context.Context, q api.AccessListParams) (api.AccessListResult, error) {
	empty := api.AccessListResult{Entries: []history.Entry{}}
	if q.AfterID == nil || q.WaitMs <= 0 {
		return empty, nil
	}
	timer := time.NewTimer(min(time.Duration(q.WaitMs)*time.Millisecond, history.MaxWait))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	return empty, nil
}

// AccessClear deletes the whole access history.
func (d *Daemon) AccessClear() (int64, error) {
	if d.history == nil {
		return 0, nil
	}
	n, err := d.history.Clear()
	if err != nil {
		return 0, err
	}
	d.logger.Info("access history cleared", "deleted", n)
	return n, nil
}

// SetHistory changes history.enabled and history.retention_days and applies
// them at once: disabling stops recording, and a retention change purges. It
// holds no daemon lock while the purge touches the database.
func (d *Daemon) SetHistory(enabled *bool, retentionDays *int) error {
	if _, err := d.store.SetHistory(enabled, retentionDays); err != nil {
		return classifyConfigError(err)
	}
	cfg, _ := d.store.Snapshot()
	d.applyHistorySettings(cfg.History.Enabled, cfg.History.RetentionDays)
	d.logger.Info("history settings changed", "enabled", cfg.History.Enabled, "retention_days", cfg.History.RetentionDays)
	return nil
}

// applyHistorySettings makes enabled and days the live settings.
func (d *Daemon) applyHistorySettings(enabled bool, days int) {
	d.historyOn.Store(enabled)
	changed := d.historyDays.Swap(int64(days)) != int64(days)
	if d.dnsWatcher != nil {
		d.dnsWatcher.SetFlowsEnabled(enabled && d.history != nil)
	}
	if d.history != nil && changed {
		if err := d.history.SetRetention(days); err != nil {
			d.logger.Warn("could not purge access history", "error", err)
		}
	}
	if d.activityStore != nil && changed {
		if err := d.activityStore.SetRetention(days); err != nil {
			d.logger.Warn("could not purge stored activity", "error", err)
		}
	}
}
