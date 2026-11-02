package configdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Bounds of a stored app preference.
const (
	// MaxPrefValueBytes caps one value's compact JSON form.
	MaxPrefValueBytes = 4096
	// MaxPrefsPerUID caps how many keys one user may store.
	MaxPrefsPerUID = 64
)

// ErrInvalidPref marks a preference the caller must correct: a malformed key,
// a value that is not JSON or is too large, or a user over the key limit.
var ErrInvalidPref = errors.New("invalid preference")

var prefKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,63}$`)

// Prefs returns every preference stored for uid, each value as its JSON text.
func (d *DB) Prefs(uid uint32) (map[string]json.RawMessage, error) {
	rows, err := d.db.Query(`SELECT key, value FROM app_prefs WHERE uid = ?`, uid)
	if err != nil {
		return nil, fmt.Errorf("read preferences: %w", err)
	}
	defer rows.Close()
	prefs := map[string]json.RawMessage{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("read preferences: %w", err)
		}
		prefs[key] = json.RawMessage(value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read preferences: %w", err)
	}
	return prefs, nil
}

// SetPref stores value (any JSON) under key for uid. A JSON null deletes the
// key, and deleting a key that does not exist is not an error. The backup is
// refreshed afterwards, because preferences are part of it.
func (d *DB) SetPref(uid uint32, key string, value json.RawMessage) error {
	if !prefKeyPattern.MatchString(key) {
		return fmt.Errorf("%w: key must match %s", ErrInvalidPref, prefKeyPattern)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, value); err != nil {
		return fmt.Errorf("%w: value is not valid JSON", ErrInvalidPref)
	}
	if compact.Len() > MaxPrefValueBytes {
		return fmt.Errorf("%w: value is larger than %d bytes", ErrInvalidPref, MaxPrefValueBytes)
	}

	if compact.String() == "null" {
		if _, err := d.db.Exec(`DELETE FROM app_prefs WHERE uid = ? AND key = ?`, uid, key); err != nil {
			return fmt.Errorf("delete preference: %w", err)
		}
		d.refreshBackup()
		return nil
	}

	// The key count and the write share a transaction, so concurrent sets of
	// new keys cannot both pass the limit.
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin preference write: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	var exists, count int
	if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(key = ?), 0) FROM app_prefs WHERE uid = ?`, key, uid).Scan(&count, &exists); err != nil {
		return fmt.Errorf("count preferences: %w", err)
	}
	if exists == 0 && count >= MaxPrefsPerUID {
		return fmt.Errorf("%w: at most %d keys per user", ErrInvalidPref, MaxPrefsPerUID)
	}
	if _, err := tx.Exec(`INSERT INTO app_prefs (uid, key, value, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(uid, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		uid, key, compact.String(), time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("store preference: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit preference write: %w", err)
	}
	d.refreshBackup()
	return nil
}
