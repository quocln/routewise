package history

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/configdb"
)

// legacySchemaWithColumns is the table older builds created, verbatim.
const legacySchemaWithColumns = `
CREATE TABLE access (
	id    INTEGER PRIMARY KEY AUTOINCREMENT,
	ts    INTEGER NOT NULL,
	name  TEXT,
	ip    TEXT NOT NULL,
	port  INTEGER NOT NULL,
	proto TEXT NOT NULL,
	iface TEXT NOT NULL,
	vpn   TEXT,
	verdict TEXT NOT NULL,
	list  TEXT,
	rule  TEXT
);
CREATE INDEX access_ts ON access (ts);`

// legacySchemaWithoutColumns is the first build's table, before list and rule.
const legacySchemaWithoutColumns = `
CREATE TABLE access (
	id    INTEGER PRIMARY KEY AUTOINCREMENT,
	ts    INTEGER NOT NULL,
	name  TEXT,
	ip    TEXT NOT NULL,
	port  INTEGER NOT NULL,
	proto TEXT NOT NULL,
	iface TEXT NOT NULL,
	vpn   TEXT,
	verdict TEXT NOT NULL
);
CREATE INDEX access_ts ON access (ts);`

func writeLegacy(t *testing.T, path, schema string, inserts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range append([]string{schema}, inserts...) {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%v\n%s", err, stmt)
		}
	}
}

// migrationEnv is a shared database and the history handle to migrate into.
func migrationEnv(t *testing.T) (db *sql.DB, dir string) {
	t.Helper()
	dir = t.TempDir()
	cdb, err := configdb.Open(filepath.Join(dir, configdb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cdb.Close() })
	db, err = cdb.LogDB()
	if err != nil {
		t.Fatal(err)
	}
	return db, dir
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestMigrationCopiesALegacyDatabaseAndSetsItAside(t *testing.T) {
	db, dir := migrationEnv(t)
	legacy := filepath.Join(dir, LegacyFileName)
	base := time.Now().Add(-time.Hour).UnixMilli()
	writeLegacy(t, legacy, legacySchemaWithColumns,
		fmt.Sprintf(`INSERT INTO access (id, ts, name, ip, port, proto, iface, vpn, verdict, list, rule) VALUES
			(7, %d, 'a.corp.example.com', '10.0.0.1', 443, 'tcp', 'utun4', 'WireGuard', 'vpn', 'wg', '*.corp.example.com'),
			(9, %d, NULL, '1.1.1.1', 53, 'udp', 'en0', NULL, 'direct', NULL, NULL),
			(8, %d, 'any.example.com', '2.2.2.2', 80, 'tcp', 'en0', NULL, 'direct', '', 'any.example.com')`,
			base+1000, base+3000, base+2000))

	n, err := MigrateLegacy(context.Background(), db, legacy)
	if err != nil || n != 3 {
		t.Fatalf("migrated %d rows (%v), want 3", n, err)
	}
	if exists(legacy) || !exists(legacy+".migrated") {
		t.Errorf("history.db must be renamed to history.db.migrated (old exists %v)", exists(legacy))
	}

	s, err := Open(db, 7, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := list(t, s, Query{AfterID: ptr(int64(0))})
	if len(got.Entries) != 3 || got.LatestID != 9 {
		t.Fatalf("entries = %+v, latest %d", got.Entries, got.LatestID)
	}
	if ids := ids(got); ids[0] != 7 || ids[1] != 8 || ids[2] != 9 {
		t.Errorf("ids = %v, want the legacy ids in order", ids)
	}
	first, second, third := got.Entries[0], got.Entries[1], got.Entries[2]
	if first.Name != "a.corp.example.com" || first.VPN != "WireGuard" || first.Port != 443 || first.Interface != "utun4" ||
		first.Time.UnixMilli() != base+1000 || first.List == nil || *first.List != "wg" || first.Rule != "*.corp.example.com" {
		t.Errorf("first = %+v", first)
	}
	if second.List == nil || *second.List != "" || second.Rule != "any.example.com" {
		t.Errorf("second = %+v, want the Any VPN list", second)
	}
	if third.List != nil || third.Rule != "" || third.Name != "" {
		t.Errorf("third = %+v, want no list", third)
	}

	// New rows continue above the imported ids.
	s.Record(entry(time.Now(), "new.example.com", "3.3.3.3", VerdictDirect))
	s.Flush()
	if latest := list(t, s, Query{}).LatestID; latest <= 9 {
		t.Errorf("latest after recording = %d, want above 9", latest)
	}
}

func TestMigrationLeavesMissingListAndRuleColumnsNull(t *testing.T) {
	db, dir := migrationEnv(t)
	legacy := filepath.Join(dir, LegacyFileName)
	writeLegacy(t, legacy, legacySchemaWithoutColumns,
		`INSERT INTO access (ts, name, ip, port, proto, iface, vpn, verdict) VALUES (5000, 'old.example.com', '10.0.0.9', 443, 'tcp', 'en0', NULL, 'direct')`)

	if n, err := MigrateLegacy(context.Background(), db, legacy); err != nil || n != 1 {
		t.Fatalf("migrated %d (%v), want 1", n, err)
	}
	var list, rule sql.NullString
	if err := db.QueryRow(`SELECT list, rule FROM access`).Scan(&list, &rule); err != nil {
		t.Fatal(err)
	}
	if list.Valid || rule.Valid {
		t.Errorf("list = %v, rule = %v, want NULL for columns the old build lacked", list, rule)
	}
}

func TestMigrationSetsAsideTheLegacyJournalFilesToo(t *testing.T) {
	db, dir := migrationEnv(t)
	legacy := filepath.Join(dir, LegacyFileName)
	writeLegacy(t, legacy, legacySchemaWithColumns)
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.WriteFile(legacy+suffix, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// An empty -wal or -journal beside a sound file is harmless to SQLite.
	if _, err := MigrateLegacy(context.Background(), db, legacy); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if exists(legacy + suffix) {
			t.Errorf("history.db%s was left in place", suffix)
		}
		if !exists(legacy + ".migrated" + suffix) {
			t.Errorf("history.db.migrated%s is missing", suffix)
		}
	}
}

func TestMigrationWithoutALegacyFileDoesNothing(t *testing.T) {
	db, dir := migrationEnv(t)
	if n, err := MigrateLegacy(context.Background(), db, filepath.Join(dir, LegacyFileName)); err != nil || n != 0 {
		t.Fatalf("migrated %d (%v), want nothing and no error", n, err)
	}
}

func TestAFailedMigrationLeavesTheLegacyFileForTheNextStart(t *testing.T) {
	db, dir := migrationEnv(t)
	legacy := filepath.Join(dir, LegacyFileName)
	// A file that is not a database cannot be imported.
	garbage := []byte("this is not a sqlite database, only text that happens to sit where history.db should be")
	if err := os.WriteFile(legacy, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacy(context.Background(), db, legacy); err == nil {
		t.Fatal("migrating a non-database must fail")
	}
	if got, err := os.ReadFile(legacy); err != nil || string(got) != string(garbage) {
		t.Fatalf("the legacy file must stay in place untouched (%v)", err)
	}
	if exists(legacy + ".migrated") {
		t.Error("a failed migration must not set the file aside")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM access`).Scan(&n); err != nil || n != 0 {
		t.Errorf("access rows after a failed migration = %d (%v)", n, err)
	}
}

func TestARetryAfterAFailedRenameDoesNotCopyTwice(t *testing.T) {
	db, dir := migrationEnv(t)
	legacy := filepath.Join(dir, LegacyFileName)
	writeLegacy(t, legacy, legacySchemaWithColumns,
		`INSERT INTO access (ts, ip, port, proto, iface, verdict) VALUES (1000, '1.1.1.1', 443, 'tcp', 'en0', 'direct')`)

	// A directory where the legacy file must land makes the rename fail after
	// the rows are committed.
	blocker := legacy + ".migrated"
	if err := os.MkdirAll(filepath.Join(blocker, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacy(context.Background(), db, legacy); err == nil {
		t.Fatal("the rename must fail while a directory is in the way")
	}
	if !exists(legacy) {
		t.Fatal("history.db must stay in place when it cannot be set aside")
	}

	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacy(context.Background(), db, legacy); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM access`).Scan(&n); err != nil || n != 1 {
		t.Errorf("access rows = %d (%v), want the one legacy row exactly once", n, err)
	}
	if exists(legacy) {
		t.Error("history.db must be set aside by the retry")
	}
	var marker int
	if err := db.QueryRow(`SELECT COUNT(*) FROM meta WHERE key = ?`, importMarkerKey).Scan(&marker); err != nil || marker != 0 {
		t.Errorf("import marker rows = %d (%v), want it cleared", marker, err)
	}
}

func TestMigrationIntoANonEmptyTableAppendsWithFreshIds(t *testing.T) {
	db, dir := migrationEnv(t)
	if _, err := db.Exec(`INSERT INTO access (ts, ip, port, proto, iface, verdict) VALUES (9000, '9.9.9.9', 443, 'tcp', 'en0', 'direct')`); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, LegacyFileName)
	writeLegacy(t, legacy, legacySchemaWithColumns,
		`INSERT INTO access (id, ts, ip, port, proto, iface, verdict) VALUES (1, 1000, '1.1.1.1', 443, 'tcp', 'en0', 'direct'), (2, 2000, '2.2.2.2', 443, 'tcp', 'en0', 'direct')`)

	if n, err := MigrateLegacy(context.Background(), db, legacy); err != nil || n != 2 {
		t.Fatalf("migrated %d (%v), want 2", n, err)
	}
	rows, err := db.Query(`SELECT id, ip FROM access ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id int64
		var ip string
		rows.Scan(&id, &ip)
		got = append(got, ip)
		if id <= 0 {
			t.Errorf("bad id %d", id)
		}
	}
	if len(got) != 3 || got[0] != "9.9.9.9" || got[1] != "1.1.1.1" || got[2] != "2.2.2.2" {
		t.Errorf("rows = %v, want the existing row, then the legacy rows in order", got)
	}
}

func TestLegacyPathSitsBesideTheSharedDatabase(t *testing.T) {
	got := LegacyPathFor("/Library/Application Support/RouteWise/routewise.db")
	if got != filepath.FromSlash("/Library/Application Support/RouteWise/history.db") {
		t.Errorf("LegacyPathFor = %q", got)
	}
}
