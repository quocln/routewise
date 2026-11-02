package configdb

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

// ErrNoSecret reports that a profile has no stored secret yet.
var ErrNoSecret = errors.New("profile has no stored secret")

// The profile secret accessors are the only code that touches profile_secrets.
// The tunnel manager is the only reader of ProfileSecret; nothing here is
// reachable from RPC, export, or logging, and no error message carries a
// secret.

// ProfileSecret returns the secret stored for a profile, or ErrNoSecret.
func (d *DB) ProfileSecret(id string) (string, error) {
	var secret string
	err := d.db.QueryRow(`SELECT secret FROM profile_secrets WHERE id = ?`, id).Scan(&secret)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", ErrNoSecret
	case err != nil:
		return "", fmt.Errorf("read profile secret: %w", err)
	}
	return secret, nil
}

// HasProfileSecret reports whether a secret is stored, without reading it.
func (d *DB) HasProfileSecret(id string) (bool, error) {
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM profile_secrets WHERE id = ?`, id).Scan(&n); err != nil {
		return false, fmt.Errorf("check profile secret: %w", err)
	}
	return n > 0, nil
}

// SetProfileSecret stores or replaces a profile's secret. The backup is
// refreshed afterwards so a restore never loses a credential the user added.
func (d *DB) SetProfileSecret(id, secret string) error {
	if _, err := d.db.Exec(`INSERT INTO profile_secrets (id, secret) VALUES (?, ?)
		ON CONFLICT(id) DO UPDATE SET secret = excluded.secret`, id, secret); err != nil {
		return fmt.Errorf("store profile secret: %w", err)
	}
	d.refreshBackup()
	return nil
}

// DeleteProfileSecret removes a profile's secret; a missing one is not an error.
func (d *DB) DeleteProfileSecret(id string) error {
	if _, err := d.db.Exec(`DELETE FROM profile_secrets WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete profile secret: %w", err)
	}
	d.refreshBackup()
	return nil
}

// PruneProfileSecrets deletes secrets whose profile no longer exists, which
// only a crash between storing a secret and saving its profile can leave. It
// returns how many were removed.
func (d *DB) PruneProfileSecrets() (int, error) {
	res, err := d.db.Exec(`DELETE FROM profile_secrets WHERE id NOT IN (SELECT id FROM profiles)`)
	if err != nil {
		return 0, fmt.Errorf("prune profile secrets: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// refreshBackup rewrites the backup after a change outside Save; a failure is
// logged, not reported, because the change itself is committed.
func (d *DB) refreshBackup() {
	if err := d.writeBackup(); err != nil {
		slog.Warn("could not refresh the config database backup", "path", d.path+BackupSuffix, "error", err)
	}
}
