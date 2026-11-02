package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LegacyFileName is the separate database older builds kept the access history
// in, beside routewise.db. MigrateLegacy folds it into the shared database.
const LegacyFileName = "history.db"

// migratedSuffix names the legacy file once its rows are in the shared
// database. The file is kept, not deleted, so nothing is lost if the import was
// wrong, but it is no longer read.
const migratedSuffix = ".migrated"

// importMarkerKey is the meta row that records a committed import whose legacy
// file is not yet set aside, so a retry after a failed rename does not copy the
// rows twice.
const importMarkerKey = "history_db_imported"

// legacyCompanions are the files SQLite may keep beside a database.
var legacyCompanions = []string{"", "-wal", "-shm", "-journal"}

// LegacyPathFor returns where the legacy history database sits for a shared
// database at dbPath: in the same directory.
func LegacyPathFor(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), LegacyFileName)
}

// MigrateLegacy copies the access rows of the legacy history database at
// legacyPath into the access table of db (the shared database's history handle)
// and then renames the legacy file, with its -wal, -shm and -journal, to
// history.db.migrated. It reports how many rows it copied; a missing legacy file
// is not an error and copies nothing.
//
// Rows keep their timestamps and their order. They keep their ids too when the
// access table is empty; when it already holds rows (recording ran while an
// earlier attempt kept failing) they get fresh ids in the legacy order, so
// nothing collides. Columns an older build never had (list, rule) stay NULL.
//
// The copy is one transaction, so a failure leaves the shared database as it
// was and the legacy file in place for the next start to retry.
func MigrateLegacy(ctx context.Context, db *sql.DB, legacyPath string) (int64, error) {
	if _, err := os.Stat(legacyPath); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil {
		return 0, fmt.Errorf("check legacy history database: %w", err)
	}

	// ATTACH belongs to one connection, so the whole copy runs on a pinned one.
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, fmt.Errorf("open history handle: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `ATTACH DATABASE ? AS legacy`, "file:"+uriPath(legacyPath)); err != nil {
		return 0, fmt.Errorf("open legacy history database: %w", err)
	}
	copied, err := copyLegacyRows(ctx, conn)
	// Detach before renaming: the file must not be held open.
	if _, derr := conn.ExecContext(ctx, `DETACH DATABASE legacy`); derr != nil && err == nil {
		err = fmt.Errorf("close legacy history database: %w", derr)
	}
	if err != nil {
		return 0, err
	}

	for _, suffix := range legacyCompanions {
		if err := os.Rename(legacyPath+suffix, legacyPath+migratedSuffix+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return copied, fmt.Errorf("set aside %s after import: %w", legacyPath+suffix, err)
		}
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, importMarkerKey); err != nil {
		return copied, fmt.Errorf("clear the import marker: %w", err)
	}
	return copied, nil
}

// copyLegacyRows runs the import transaction against the attached legacy file.
func copyLegacyRows(ctx context.Context, conn *sql.Conn) (int64, error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin history import: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed

	var marked int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM meta WHERE key = ?`, importMarkerKey).Scan(&marked); err != nil {
		return 0, fmt.Errorf("read the import marker: %w", err)
	}
	if marked > 0 {
		return 0, nil // already imported; only the rename is left
	}

	have, err := legacyColumns(ctx, tx)
	if err != nil {
		return 0, err
	}
	if !have["ts"] { // no access table: an empty or foreign file has nothing to import
		return 0, nil
	}
	column := func(name string) string {
		if have[name] {
			return name
		}
		return "NULL"
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM main.access`).Scan(&existing); err != nil {
		return 0, fmt.Errorf("read access history: %w", err)
	}
	insert := `INSERT INTO main.access (id, ts, name, ip, port, proto, iface, vpn, verdict, list, rule)
		SELECT id, ts, name, ip, port, proto, iface, vpn, verdict, ` + column("list") + `, ` + column("rule") + `
		FROM legacy.access ORDER BY id`
	if existing > 0 {
		insert = `INSERT INTO main.access (ts, name, ip, port, proto, iface, vpn, verdict, list, rule)
			SELECT ts, name, ip, port, proto, iface, vpn, verdict, ` + column("list") + `, ` + column("rule") + `
			FROM legacy.access ORDER BY id`
	}
	res, err := tx.ExecContext(ctx, insert)
	if err != nil {
		return 0, fmt.Errorf("copy legacy access history: %w", err)
	}
	copied, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, importMarkerKey, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return 0, fmt.Errorf("record the import: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit history import: %w", err)
	}
	return copied, nil
}

// legacyColumns lists the columns of the legacy access table; it is empty when
// the table does not exist.
func legacyColumns(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_info('access', 'legacy')`)
	if err != nil {
		return nil, fmt.Errorf("read legacy history schema: %w", err)
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("read legacy history schema: %w", err)
		}
		have[name] = true
	}
	return have, rows.Err()
}

func uriPath(path string) string {
	return strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23").Replace(path)
}
