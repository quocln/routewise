package configdb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/testenv"
)

func openShared(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), FileName)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, path
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func rawRows(t *testing.T, path, table string) int {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+uriPath(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	return countRows(t, raw, table)
}

func addHistoryRows(t *testing.T, d *DB) {
	t.Helper()
	logDB, err := d.LogDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logDB.Exec(`INSERT INTO access (ts, ip, port, proto, iface, verdict) VALUES (1, '1.1.1.1', 443, 'tcp', 'en0', 'direct')`); err != nil {
		t.Fatal(err)
	}
	if _, err := logDB.Exec(`INSERT INTO activity (sequence, time, kind, name, addresses, interface, detail) VALUES (1, 1, 'dns', 'a.example.com', '[]', '', '')`); err != nil {
		t.Fatal(err)
	}
}

func TestTheSharedFileIsWALIncrementalAndPrivate(t *testing.T) {
	d, path := openShared(t)
	addHistoryRows(t, d)

	logDB, _ := d.LogDB()
	for name, db := range map[string]*sql.DB{"config": d.db, "history": logDB} {
		var mode string
		if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
			t.Errorf("%s handle journal_mode = %q (%v), want wal", name, mode, err)
		}
	}
	var vacuum int
	if err := d.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&vacuum); err != nil || vacuum != 2 {
		t.Errorf("auto_vacuum = %d (%v), want 2 (incremental)", vacuum, err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			t.Fatalf("%s: %v", suffix, err)
		}
		if !testenv.HasPerm(info, 0o600) {
			t.Errorf("%s mode = %v, want 0600", path+suffix, info.Mode().Perm())
		}
	}
}

func TestAHistoryWriteInFlightDoesNotBlockConfigReads(t *testing.T) {
	d, _ := openShared(t)
	if err := d.Save(config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	logDB, _ := d.LogDB()
	tx, err := logDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO access (ts, ip, port, proto, iface, verdict) VALUES (1, '1.1.1.1', 443, 'tcp', 'en0', 'direct')`); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := d.Load()
		if err == nil {
			_, err = d.Prefs(501)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("config read during a history write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a config read waited on an open history write")
	}
}

func TestBackupsCarryConfigSecretsAndPrefsButNeverHistory(t *testing.T) {
	d, path := openShared(t)
	addHistoryRows(t, d)
	if err := d.SetProfileSecret("p1", "secret-material"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPref(501, "launchAtLogin", json.RawMessage(`true`)); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: "kept.example.com"}}
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}

	backup := path + BackupSuffix
	for _, table := range []string{"settings", "domains", "profile_secrets", "app_prefs"} {
		if !tableExists(t, backup, table) {
			t.Errorf("the backup lacks %s", table)
		}
	}
	for _, table := range []string{"access", "activity"} {
		if tableExists(t, backup, table) {
			t.Errorf("the backup must not carry %s", table)
		}
	}
	if rawRows(t, backup, "app_prefs") != 1 || rawRows(t, backup, "profile_secrets") != 1 || rawRows(t, backup, "domains") != 1 {
		t.Error("the backup lost configuration, a secret or a preference")
	}
	info, err := os.Stat(backup)
	if err != nil || !testenv.HasPerm(info, 0o600) {
		t.Errorf("backup mode = %v (%v), want 0600", info, err)
	}
	if left, _ := filepath.Glob(backup + ".*"); len(left) != 0 {
		t.Errorf("temporary backup files left behind: %v", left)
	}
}

// writeV2Database builds a schema 2 database: configuration, profiles and
// secrets, but none of the history or preference tables.
func writeV2Database(t *testing.T, path string) {
	t.Helper()
	writeV1Database(t, path)
	raw, err := sql.Open("sqlite", "file:"+uriPath(path))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, s := range []string{
		`CREATE TABLE profiles (id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, auto_connect INTEGER NOT NULL, dns TEXT NOT NULL, position INTEGER NOT NULL)`,
		`CREATE TABLE profile_secrets (id TEXT PRIMARY KEY, secret TEXT NOT NULL)`,
		`UPDATE meta SET value = '2' WHERE key = 'schema_version'`,
	} {
		if _, err := raw.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUpgradingSchema2KeepsAPermanentCopyAndAddsTheNewTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	writeV2Database(t, path)

	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	permanent := path + ".v2.bak"
	if got := schemaVersionOf(t, permanent); got != "2" {
		t.Errorf("pre-upgrade copy schema = %s, want 2", got)
	}
	for _, table := range []string{"access", "activity", "app_prefs"} {
		if tableExists(t, permanent, table) {
			t.Errorf("the pre-upgrade copy must be the old schema, but has %s", table)
		}
		if !tableExists(t, path, table) {
			t.Errorf("the upgraded database lacks %s", table)
		}
	}
	if got := schemaVersionOf(t, path); got != fmt.Sprint(schemaVersion) {
		t.Errorf("schema after upgrading = %s, want %d", got, schemaVersion)
	}
	var vacuum int
	if err := d.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&vacuum); err != nil || vacuum != 2 {
		t.Errorf("an upgraded file must reclaim space incrementally: auto_vacuum = %d (%v)", vacuum, err)
	}
	if cfg, found, err := d.Load(); err != nil || !found || len(cfg.Domains) != 1 {
		t.Errorf("upgraded config = %+v, %v, %v", cfg, found, err)
	}
}

func TestACorruptDatabaseRestoresFromABackupThatHoldsNoHistory(t *testing.T) {
	yamlPath := seed(t, "kept.example.com")
	d, _, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	addHistoryRows(t, d)
	if err := d.SetPref(501, "keepOnTop", json.RawMessage(`true`)); err != nil {
		t.Fatal(err)
	}
	d.Close()
	corrupt(t, yamlPath)

	d2, cfg, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatalf("a corrupt database must not stop the helper: %v", err)
	}
	defer d2.Close()
	if len(cfg.Domains) != 1 || d2.RecoveryNotice() == "" {
		t.Fatalf("config = %+v, notice = %q", cfg.Domains, d2.RecoveryNotice())
	}
	logDB, err := d2.LogDB()
	if err != nil {
		t.Fatal(err)
	}
	if countRows(t, logDB, "access") != 0 || countRows(t, logDB, "activity") != 0 {
		t.Error("history must start empty after a restore")
	}
	prefs, err := d2.Prefs(501)
	if err != nil || string(prefs["keepOnTop"]) != "true" {
		t.Errorf("prefs after restore = %v, %v", prefs, err)
	}
}

func TestPrefsAreStoredPerUIDAndNullDeletes(t *testing.T) {
	d, _ := openShared(t)
	if err := d.SetPref(501, "launchAtLogin", json.RawMessage(` true `)); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPref(501, "lastUpdateCheck", json.RawMessage(`{"at": 12, "found":false}`)); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPref(0, "launchAtLogin", json.RawMessage(`false`)); err != nil {
		t.Fatal(err)
	}

	got, err := d.Prefs(501)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got["launchAtLogin"]) != "true" || string(got["lastUpdateCheck"]) != `{"at":12,"found":false}` {
		t.Errorf("uid 501 prefs = %v", got)
	}
	if root, _ := d.Prefs(0); len(root) != 1 || string(root["launchAtLogin"]) != "false" {
		t.Errorf("uid 0 prefs = %v", root)
	}
	if other, err := d.Prefs(502); err != nil || other == nil || len(other) != 0 {
		t.Errorf("uid 502 prefs = %v, %v, want an empty map", other, err)
	}

	if err := d.SetPref(501, "launchAtLogin", json.RawMessage(`null`)); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPref(501, "neverSet", json.RawMessage(`null`)); err != nil {
		t.Errorf("deleting a missing key: %v", err)
	}
	if got, _ := d.Prefs(501); len(got) != 1 {
		t.Errorf("after delete: %v", got)
	}
	if root, _ := d.Prefs(0); len(root) != 1 {
		t.Error("deleting one user's key must not touch another's")
	}
}

func TestPrefsRejectBadKeysValuesAndTooManyKeys(t *testing.T) {
	d, _ := openShared(t)
	for _, key := range []string{"", "1abc", "has space", "a/b", strings.Repeat("k", 65)} {
		if err := d.SetPref(501, key, json.RawMessage(`1`)); !errors.Is(err, ErrInvalidPref) {
			t.Errorf("key %q: err = %v, want ErrInvalidPref", key, err)
		}
	}
	for _, key := range []string{"a", "A.b-c_d", strings.Repeat("k", 64)} {
		if err := d.SetPref(501, key, json.RawMessage(`1`)); err != nil {
			t.Errorf("key %q: %v", key, err)
		}
	}

	if err := d.SetPref(501, "bad", json.RawMessage(`{nope`)); !errors.Is(err, ErrInvalidPref) {
		t.Errorf("malformed JSON: %v", err)
	}
	big := json.RawMessage(`"` + strings.Repeat("x", MaxPrefValueBytes) + `"`)
	if err := d.SetPref(501, "big", big); !errors.Is(err, ErrInvalidPref) {
		t.Errorf("oversized value: %v", err)
	}
	fits := json.RawMessage(`"` + strings.Repeat("x", MaxPrefValueBytes-2) + `"`)
	if err := d.SetPref(501, "fits", fits); err != nil {
		t.Errorf("a value of exactly the limit: %v", err)
	}

	// 4 keys are already stored for uid 501 (a, A.b-c_d, 64 k's, fits = 4).
	for i := 4; i < MaxPrefsPerUID; i++ {
		if err := d.SetPref(501, fmt.Sprintf("key%d", i), json.RawMessage(`1`)); err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
	}
	if err := d.SetPref(501, "onetoomany", json.RawMessage(`1`)); !errors.Is(err, ErrInvalidPref) {
		t.Errorf("the 65th key: %v", err)
	}
	if err := d.SetPref(501, "a", json.RawMessage(`2`)); err != nil {
		t.Errorf("replacing a key at the limit: %v", err)
	}
	if err := d.SetPref(502, "onetoomany", json.RawMessage(`1`)); err != nil {
		t.Errorf("the limit is per user: %v", err)
	}
	if err := d.SetPref(501, "a", json.RawMessage(`null`)); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPref(501, "onetoomany", json.RawMessage(`1`)); err != nil {
		t.Errorf("a freed slot must be usable: %v", err)
	}
}

func TestOpeningTightensLoosePermissionsOnTheFileAndItsWALCompanions(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	addHistoryRows(t, d)
	// A WAL left by a crashed helper, with loose modes, as hand-copying could make it.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	defer d.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil || !testenv.HasPerm(info, 0o600) {
			t.Errorf("%s: mode %v (%v), want 0600", path+suffix, info, err)
		}
	}
}

// writeV3Database builds a schema 3 database as the previous release left it:
// the activity table has no list, rule or vpn column, and holds a row.
func writeV3Database(t *testing.T, path string) {
	t.Helper()
	writeV2Database(t, path)
	raw, err := sql.Open("sqlite", "file:"+uriPath(path))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, s := range []string{
		`CREATE TABLE access (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, name TEXT, ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL, iface TEXT NOT NULL, vpn TEXT, verdict TEXT NOT NULL, list TEXT, rule TEXT)`,
		`CREATE INDEX access_ts ON access (ts)`,
		`CREATE TABLE activity (sequence INTEGER PRIMARY KEY, time INTEGER NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL, addresses TEXT NOT NULL, interface TEXT NOT NULL, detail TEXT NOT NULL)`,
		`CREATE INDEX activity_time ON activity (time)`,
		`CREATE TABLE app_prefs (uid INTEGER NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (uid, key))`,
		`INSERT INTO activity VALUES (7, 1700000000000000000, 'dns', 'old.example.com', '[{"ip":"1.2.3.4","verdict":"direct"}]', 'en0', 'answered by 1.1.1.1')`,
		`UPDATE meta SET value = '3' WHERE key = 'schema_version'`,
	} {
		if _, err := raw.Exec(s); err != nil {
			t.Fatalf("seed schema 3: %v\n%s", err, s)
		}
	}
}

func TestUpgradingSchema3AddsActivityColumnsKeepsRowsAndTheBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	writeV3Database(t, path)

	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	permanent := path + ".v3.bak"
	if got := schemaVersionOf(t, permanent); got != "3" {
		t.Errorf("pre-upgrade copy schema = %s, want 3", got)
	}
	if got := schemaVersionOf(t, path); got != "4" {
		t.Errorf("schema after upgrading = %s, want 4", got)
	}
	logDB, err := d.LogDB()
	if err != nil {
		t.Fatal(err)
	}
	var name string
	var list, rule, vpn sql.NullString
	if err := logDB.QueryRow(`SELECT name, list, rule, vpn FROM activity WHERE sequence = 7`).Scan(&name, &list, &rule, &vpn); err != nil {
		t.Fatalf("read the upgraded row: %v", err)
	}
	if name != "old.example.com" || list.Valid || rule.Valid || vpn.Valid {
		t.Errorf("old row = %q %v %v %v, want its name and NULL new columns", name, list, rule, vpn)
	}
	if _, err := logDB.Exec(`INSERT INTO activity (sequence, time, kind, name, addresses, interface, detail, list, rule, vpn) VALUES (8, 1, 'dns', 'n', '[]', '', '', '', 'r', 'SG')`); err != nil {
		t.Errorf("insert with the new columns: %v", err)
	}
	if cfg, found, err := d.Load(); err != nil || !found || len(cfg.Domains) != 1 {
		t.Errorf("upgraded config = %+v, %v, %v", cfg, found, err)
	}

	// Opening the upgraded file again changes nothing and fails nothing.
	d.Close()
	d2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen the upgraded file: %v", err)
	}
	d2.Close()
}

func TestURIPathHandlesWindowsDrivePaths(t *testing.T) {
	for in, want := range map[string]string{
		`C:\ProgramData\RouteWise\routewise.db`: "/C:/ProgramData/RouteWise/routewise.db",
		`d:/data/a?b.db`:                        "/d:/data/a%3Fb.db",
		"/var/lib/routewise/routewise.db":       "/var/lib/routewise/routewise.db",
		"/tmp/a#b/x.db":                         "/tmp/a%23b/x.db",
		"relative/x.db":                         "relative/x.db",
	} {
		if got := uriPath(in); got != want {
			t.Errorf("uriPath(%q) = %q, want %q", in, got, want)
		}
	}
}
