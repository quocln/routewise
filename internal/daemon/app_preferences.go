package daemon

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/configdb"
)

// PrefStore keeps per-user app preferences.
type PrefStore interface {
	Prefs(uid uint32) (map[string]json.RawMessage, error)
	SetPref(uid uint32, key string, value json.RawMessage) error
}

// SetPrefStore gives the daemon its app preference storage. Call it before
// Start.
func (d *Daemon) SetPrefStore(s PrefStore) { d.prefs = s }

var errNoPrefStore = errors.New("app preferences are unavailable")

// Prefs returns the app preferences stored for uid, which the RPC layer takes
// from the caller's socket credentials.
func (d *Daemon) Prefs(uid uint32) (map[string]json.RawMessage, error) {
	if d.prefs == nil {
		return nil, errNoPrefStore
	}
	return d.prefs.Prefs(uid)
}

// SetPref stores a preference for uid, or deletes it when value is JSON null.
// A key or value the store refuses is the caller's mistake, so it is reported
// as a rejection.
func (d *Daemon) SetPref(uid uint32, key string, value json.RawMessage) error {
	if d.prefs == nil {
		return errNoPrefStore
	}
	if err := d.prefs.SetPref(uid, key, value); err != nil {
		if errors.Is(err, configdb.ErrInvalidPref) {
			return fmt.Errorf("%w: %v", api.ErrRejected, err)
		}
		return err
	}
	return nil
}
