// Package configdb owns RouteWise's one SQLite file: the configuration, the
// built-in VPN secrets, per-user app preferences, and the access and activity
// history. The helper is its only writer; every configuration change replaces
// the stored configuration in one transaction, so a crash leaves either the old
// or the new config, never a mix. The file is root-owned and private (0600),
// like the YAML it replaces, and so are its -wal and -shm companions.
//
// The history tables can grow large, so their writers use a second handle
// (LogDB) and the file runs in WAL mode: a batch insert never blocks a config
// read, and backups copy only the configuration tables.
package configdb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/platform"

	sqlite "modernc.org/sqlite" // pure-Go driver: keeps the helper cgo-free and universal
)

// FileName is the database's name, next to where config.yaml used to live.
const FileName = "routewise.db"

// schemaVersion is bumped with every schema change; migrate upgrades older
// files in place after copying them to a .bak file.
const schemaVersion = 4

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL -- JSON
);
CREATE TABLE IF NOT EXISTS vpn_clients (
	client   TEXT PRIMARY KEY,
	position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
	list     TEXT NOT NULL, -- '' is the Any VPN list, otherwise a vpn_clients.client
	pattern  TEXT NOT NULL,
	position INTEGER NOT NULL,
	PRIMARY KEY (list, pattern)
);
-- Schema 2: built-in VPN profiles. The metadata lives in profiles; the secret
-- (a WireGuard .conf or an Outline access key) lives in profile_secrets, which
-- only the tunnel manager reads and which no export, RPC, or log carries.
CREATE TABLE IF NOT EXISTS profiles (
	id           TEXT PRIMARY KEY,
	kind         TEXT NOT NULL,
	name         TEXT NOT NULL,
	auto_connect INTEGER NOT NULL,
	dns          TEXT NOT NULL, -- JSON array of IPv4 addresses
	position     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS profile_secrets (
	id     TEXT PRIMARY KEY,
	secret TEXT NOT NULL
);
-- Schema 3: access and activity history, and per-user app preferences. Only
-- app_prefs is configuration; access and activity are disposable history that
-- no backup carries.
CREATE TABLE IF NOT EXISTS access (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	ts      INTEGER NOT NULL, -- unix milliseconds
	name    TEXT,
	ip      TEXT NOT NULL,
	port    INTEGER NOT NULL,
	proto   TEXT NOT NULL,
	iface   TEXT NOT NULL,
	vpn     TEXT,
	verdict TEXT NOT NULL,
	list    TEXT, -- client id of the list the connection matched; '' is Any VPN
	rule    TEXT  -- the list entry it matched
);
CREATE INDEX IF NOT EXISTS access_ts ON access (ts);
CREATE TABLE IF NOT EXISTS activity (
	sequence  INTEGER PRIMARY KEY, -- the event's sequence number; keeps rising across restarts
	time      INTEGER NOT NULL,    -- unix nanoseconds
	kind      TEXT NOT NULL,
	name      TEXT NOT NULL,
	addresses TEXT NOT NULL,       -- JSON array of {ip, verdict}
	interface TEXT NOT NULL,
	detail    TEXT NOT NULL,
	list      TEXT, -- client id of the list the event matched; '' is Any VPN; NULL none
	rule      TEXT, -- the list entry it matched
	vpn       TEXT  -- the managed tunnel's client name
);
CREATE INDEX IF NOT EXISTS activity_time ON activity (time);
CREATE TABLE IF NOT EXISTS app_prefs (
	uid        INTEGER NOT NULL,
	key        TEXT NOT NULL,
	value      TEXT NOT NULL, -- JSON
	updated_at INTEGER NOT NULL, -- unix milliseconds
	PRIMARY KEY (uid, key)
);`

// BackupSuffix names the copy of the database kept next to it. It is rewritten
// after every successful save and is what a corrupt database is restored from.
const BackupSuffix = ".bak"

// preUpgradeBackupFormat names the copy of the database taken just before a
// schema upgrade, as routewise.db.v<old schema>.bak. Unlike .bak, no save ever
// touches it, so it keeps the pre-upgrade lists and allowlist for as long as it
// stays on disk: a schema upgrade cannot be undone from .bak, which the first
// save after it overwrites with the new schema, and an older helper refuses a
// newer schema. Restore it by hand (stop the helper, copy it over routewise.db)
// to go back to the older helper build. It is 0600, like the database, and the
// uninstaller removes it with the rest. A corrupt-database notice names it when
// it exists.
const preUpgradeBackupFormat = ".v%d.bak"

// preUpgradeBackups lists the pre-upgrade copies that exist beside the database.
func preUpgradeBackups(dbPath string) []string {
	entries, err := os.ReadDir(filepath.Dir(dbPath))
	if err != nil {
		return nil
	}
	prefix := filepath.Base(dbPath) + ".v"
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".bak") && !e.IsDir() {
			out = append(out, filepath.Join(filepath.Dir(dbPath), name))
		}
	}
	return out // ReadDir sorts by name
}

// preUpgradeBackupPath is where the pre-upgrade copy of a schema version lives.
func preUpgradeBackupPath(dbPath string, version int) string {
	return dbPath + fmt.Sprintf(preUpgradeBackupFormat, version)
}

// ErrNewerSchema marks a database written by a newer helper. It is never moved
// aside: the data is fine, this helper is just too old to read it.
var ErrNewerSchema = errors.New("config database schema is newer than this helper supports")

// ErrInvalidConfig marks a stored configuration that parses but holds values
// the helper must not act on. It is reported, never repaired automatically.
var ErrInvalidConfig = errors.New("stored configuration is invalid")

// DB is an open configuration database.
type DB struct {
	db   *sql.DB
	path string
	// backupMu serializes backup writes: Save and the profile-secret setters
	// all refresh the same backup file.
	backupMu sync.Mutex
	// logMu guards logDB, the lazily opened handle of the history writers.
	logMu sync.Mutex
	logDB *sql.DB
	// recovery describes how the database was rebuilt at open, or is empty.
	recovery string
}

// RecoveryNotice describes how OpenOrMigrate rebuilt a corrupt database, or
// returns "" when the database opened normally. The caller shows it loudly.
func (d *DB) RecoveryNotice() string { return d.recovery }

// PathFor returns the database path for a config location: the directory of
// configPath (a legacy config.yaml path) holds routewise.db, except for the
// OS's default config path, whose database lives in the platform data
// directory (the same directory on macOS).
func PathFor(configPath string) string {
	if configPath == config.DefaultConfigPath {
		return filepath.Join(platform.DataDir(), FileName)
	}
	return filepath.Join(filepath.Dir(configPath), FileName)
}

// Open opens or creates the database at path with private permissions.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create config directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open config database: %w", err)
	}
	f.Close()

	// WAL lets the history writers (LogDB) commit without blocking a config
	// read or save. The default synchronous level stays: a config save must
	// survive power loss.
	db, err := sql.Open("sqlite", "file:"+uriPath(path)+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=secure_delete(1)")
	if err != nil {
		return nil, fmt.Errorf("open config database: %w", err)
	}
	// One connection: the helper is the only writer, and SQLite serializes
	// writers anyway.
	db.SetMaxOpenConns(1)

	d := &DB{db: db, path: path}
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	d.securePermissions()
	return d, nil
}

// securePermissions makes the database and its WAL companions private. SQLite
// creates -wal and -shm with the database's mode, but a file made by hand or an
// older build may be looser, so it is enforced rather than assumed.
func (d *DB) securePermissions() {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chmod(d.path+suffix, 0o600); err != nil && !os.IsNotExist(err) {
			slog.Warn("could not restrict the config database file", "path", d.path+suffix, "error", err)
		}
	}
}

// LogDB returns the handle the access and activity writers use. It is a
// separate pool on the same file, so a large batch write or a history query
// waits on SQLite's lock (bounded by busy_timeout) instead of on the one
// connection config reads and saves share. Synchronous NORMAL is safe in WAL
// mode and trades the last commits of a power loss, which history can afford,
// for fewer fsyncs. The handle is closed by Close.
func (d *DB) LogDB() (*sql.DB, error) {
	d.logMu.Lock()
	defer d.logMu.Unlock()
	if d.logDB != nil {
		return d.logDB, nil
	}
	db, err := sql.Open("sqlite", "file:"+uriPath(d.path)+"?_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=journal_size_limit(67108864)")
	if err != nil {
		return nil, fmt.Errorf("open history handle: %w", err)
	}
	// Readers run beside the writer in WAL mode; the cap only bounds how many
	// slow history queries can pile up.
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open history handle: %w", err)
	}
	d.securePermissions()
	d.logDB = db
	return db, nil
}

// uriPath escapes the characters that would end or alter the path part of a
// SQLite URI filename, so a directory name with '?' or '#' opens the right file.
//
// A Windows drive path is rewritten to the "/C:/dir/file" form SQLite accepts on
// Windows, whatever the host OS (so it can be tested anywhere): backslashes are
// turned into slashes and the drive letter gets the leading slash that keeps it
// from reading as a URI authority.
func uriPath(path string) string {
	path = strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23").Replace(path)
	if len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') &&
		(path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z') {
		return "/" + strings.ReplaceAll(path, `\`, "/")
	}
	return path
}

// Path returns the database file path.
func (d *DB) Path() string { return d.path }

// Close closes the database and the history handle.
func (d *DB) Close() error {
	d.logMu.Lock()
	logDB := d.logDB
	d.logDB = nil
	d.logMu.Unlock()
	if logDB != nil {
		logDB.Close() //nolint:errcheck // the main handle's error is the one reported
	}
	return d.db.Close()
}

func (d *DB) migrate() error {
	stored, hasVersion, err := d.storedVersion()
	if err != nil {
		return err
	}
	if hasVersion && stored > schemaVersion {
		return fmt.Errorf("%w: file is schema %d, this helper supports %d", ErrNewerSchema, stored, schemaVersion)
	}
	// An older file is upgraded in place, but only after its current content is
	// copied to routewise.db.v<N>.bak (permanent) and .bak, so a failed or
	// unwanted upgrade can be undone by hand. No backup means no upgrade.
	if hasVersion && stored < schemaVersion {
		// The permanent copy first: it is the one that survives later saves.
		permanent := preUpgradeBackupPath(d.path, stored)
		if err := d.writeBackupTo(permanent); err != nil {
			return fmt.Errorf("back up the schema %d config database before upgrading it: %w", stored, err)
		}
		if err := d.writeBackup(); err != nil {
			return fmt.Errorf("back up the schema %d config database before upgrading it: %w", stored, err)
		}
		slog.Info("upgrading the config database schema", "from", stored, "to", schemaVersion,
			"backup", d.path+BackupSuffix, "permanent_backup", permanent)
	}
	if err := d.useIncrementalVacuum(); err != nil {
		return err
	}
	if _, err := d.db.Exec(schema); err != nil {
		return fmt.Errorf("create config schema: %w", err)
	}
	// CREATE TABLE IF NOT EXISTS leaves an older activity table as it was, so
	// schema 4's columns are added to it here. Rows written before stay NULL.
	if err := d.addMissingColumns("activity", "list", "rule", "vpn"); err != nil {
		return err
	}
	switch {
	case !hasVersion:
		_, err = d.db.Exec(`INSERT INTO meta (key, value) VALUES ('schema_version', ?)`, schemaVersion)
	case stored < schemaVersion:
		_, err = d.db.Exec(`UPDATE meta SET value = ? WHERE key = 'schema_version'`, schemaVersion)
	}
	return err
}

// addMissingColumns adds each named TEXT column that table lacks. It checks
// the table first, so a file already at the current schema, or one whose upgrade
// was interrupted after adding some columns, is left alone.
func (d *DB) addMissingColumns(table string, columns ...string) error {
	rows, err := d.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", table, err)
	}
	have := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("inspect %s: %w", table, err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("inspect %s: %w", table, err)
	}
	rows.Close()
	for _, c := range columns {
		if have[c] {
			continue
		}
		// Table and column names are this package's own constants.
		if _, err := d.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s TEXT`, table, c)); err != nil {
			return fmt.Errorf("add %s.%s: %w", table, c, err)
		}
	}
	return nil
}

// useIncrementalVacuum makes the file reclaim freed pages on request (see
// ReclaimSpace), so purging old history shrinks the file instead of leaving it
// at its high-water mark. SQLite applies the mode to a new file as it creates
// its first table and to an existing one only by rebuilding it, which is quick
// here because the file held nothing but configuration when it was made.
func (d *DB) useIncrementalVacuum() error {
	const incremental = 2
	var mode int
	if err := d.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return fmt.Errorf("read auto_vacuum mode: %w", err)
	}
	if mode == incremental {
		return nil
	}
	if _, err := d.db.Exec(`PRAGMA auto_vacuum = INCREMENTAL`); err != nil {
		return fmt.Errorf("set auto_vacuum mode: %w", err)
	}
	if _, err := d.db.Exec(`VACUUM`); err != nil {
		return fmt.Errorf("apply auto_vacuum mode: %w", err)
	}
	return nil
}

// ReclaimSpace hands up to maxPages freed pages back to the file system. It is
// bounded so one call never holds the write lock for long; the history writers
// call it after a purge.
func ReclaimSpace(db *sql.DB, maxPages int) error {
	_, err := db.Exec(fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, maxPages))
	return err
}

// storedVersion reads the schema version without creating anything. A file
// with no meta table, or none recorded yet, is new.
func (d *DB) storedVersion() (version int, found bool, err error) {
	var tables int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'`).Scan(&tables); err != nil {
		return 0, false, fmt.Errorf("read schema version: %w", err)
	}
	if tables == 0 {
		return 0, false, nil
	}
	err = d.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'`).Scan(&version)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("read schema version: %w", err)
	}
	return version, true, nil
}

// Load reads the stored configuration on top of the defaults. It reports
// false when nothing has been stored yet.
func (d *DB) Load() (*config.Config, bool, error) {
	cfg := config.DefaultConfig()
	fields := config.SettingFields(cfg)

	rows, err := d.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, false, fmt.Errorf("read settings: %w", err)
	}
	found := false
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			rows.Close()
			return nil, false, err
		}
		found = true
		if field, ok := fields[key]; ok {
			if err := json.Unmarshal([]byte(value), field); err != nil {
				rows.Close()
				return nil, false, fmt.Errorf("setting %s: %w", key, err)
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}

	clients, err := d.db.Query(`SELECT client FROM vpn_clients ORDER BY position`)
	if err != nil {
		return nil, false, fmt.Errorf("read VPN clients: %w", err)
	}
	for clients.Next() {
		var client string
		if err := clients.Scan(&client); err != nil {
			clients.Close()
			return nil, false, err
		}
		cfg.VPNs = append(cfg.VPNs, config.VPNRoute{Client: client})
	}
	clients.Close()

	profiles, err := d.db.Query(`SELECT id, kind, name, auto_connect, dns FROM profiles ORDER BY position`)
	if err != nil {
		return nil, false, fmt.Errorf("read profiles: %w", err)
	}
	for profiles.Next() {
		var p config.TunnelProfile
		var auto int
		var dnsJSON string
		if err := profiles.Scan(&p.ID, &p.Kind, &p.Name, &auto, &dnsJSON); err != nil {
			profiles.Close()
			return nil, false, err
		}
		p.AutoConnect = auto != 0
		if err := json.Unmarshal([]byte(dnsJSON), &p.DNS); err != nil {
			profiles.Close()
			return nil, false, fmt.Errorf("profile %s dns: %w", p.ID, err)
		}
		cfg.Profiles = append(cfg.Profiles, p)
	}
	profiles.Close()
	if err := profiles.Err(); err != nil {
		return nil, false, err
	}

	domains, err := d.db.Query(`SELECT list, pattern FROM domains ORDER BY list, position`)
	if err != nil {
		return nil, false, fmt.Errorf("read domains: %w", err)
	}
	defer domains.Close()
	cfg.Domains = nil
	for domains.Next() {
		var list, pattern string
		if err := domains.Scan(&list, &pattern); err != nil {
			return nil, false, err
		}
		rule := config.DomainRule{Pattern: pattern}
		if list == config.AnyVPN {
			cfg.Domains = append(cfg.Domains, rule)
			continue
		}
		for i := range cfg.VPNs {
			if cfg.VPNs[i].Client == list {
				cfg.VPNs[i].Domains = append(cfg.VPNs[i].Domains, rule)
			}
		}
	}
	if err := domains.Err(); err != nil {
		return nil, false, err
	}
	// The helper acts on these values as root, so a database edited by hand or
	// damaged by a bug is refused rather than trusted. A seeded store with no
	// domains yet is legitimate. Defaults go in first, so a row that never
	// stored a mode or a retention reads back the way the config file would.
	cfg.ApplyDefaults()
	if err := cfg.ValidateAllowingNoDomains(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return cfg, true, nil
}

// Save replaces the stored configuration in one transaction.
func (d *DB) Save(cfg *config.Config) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin config write: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed

	// profile_secrets is deliberately not cleared here: secrets have their own
	// accessors, and a configuration save must never lose or touch one.
	for _, table := range []string{"settings", "vpn_clients", "domains", "profiles"} {
		if _, err := tx.Exec(`DELETE FROM ` + table); err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}
	for key, field := range config.SettingFields(cfg) {
		value, err := json.Marshal(field)
		if err != nil {
			return fmt.Errorf("encode %s: %w", key, err)
		}
		if _, err := tx.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)`, key, string(value)); err != nil {
			return fmt.Errorf("write %s: %w", key, err)
		}
	}
	insertDomains := func(list string, rules []config.DomainRule) error {
		for i, r := range rules {
			if _, err := tx.Exec(`INSERT INTO domains (list, pattern, position) VALUES (?, ?, ?)`, list, r.Pattern, i); err != nil {
				return fmt.Errorf("write domain %s: %w", r.Pattern, err)
			}
		}
		return nil
	}
	if err := insertDomains(config.AnyVPN, cfg.Domains); err != nil {
		return err
	}
	for i, v := range cfg.VPNs {
		if _, err := tx.Exec(`INSERT INTO vpn_clients (client, position) VALUES (?, ?)`, v.Client, i); err != nil {
			return fmt.Errorf("write VPN client %s: %w", v.Client, err)
		}
		if err := insertDomains(v.Client, v.Domains); err != nil {
			return err
		}
	}
	for i, p := range cfg.Profiles {
		dns, err := json.Marshal(append([]string{}, p.DNS...))
		if err != nil {
			return fmt.Errorf("encode profile %s: %w", p.ID, err)
		}
		auto := 0
		if p.AutoConnect {
			auto = 1
		}
		if _, err := tx.Exec(`INSERT INTO profiles (id, kind, name, auto_connect, dns, position) VALUES (?, ?, ?, ?, ?, ?)`,
			p.ID, p.Kind, p.Name, auto, string(dns), i); err != nil {
			return fmt.Errorf("write profile %s: %w", p.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit config write: %w", err)
	}
	// The change is committed; a failed backup must not report it as lost.
	if err := d.writeBackup(); err != nil {
		slog.Warn("could not refresh the config database backup", "path", d.path+BackupSuffix, "error", err)
	}
	return nil
}

// writeBackup replaces <db>.bak with a consistent copy of the configuration.
// The copy is built privately (0600) beside the target and renamed over it, so a
// crash leaves the previous backup whole.
func (d *DB) writeBackup() error { return d.writeBackupTo(d.path + BackupSuffix) }

// backupTables are the tables a backup carries: the configuration, the secrets
// and the app preferences. The access and activity tables are deliberately
// absent, so a backup stays small however large the history grows and never
// holds a record of what this Mac connected to.
var backupTables = []string{"meta", "settings", "vpn_clients", "domains", "profiles", "profile_secrets", "app_prefs"}

// writeBackupTo writes the same private, atomic copy to target. Writers are
// serialized, and each builds its copy in its own temporary file, so one
// writer can never remove or replace another's half-built copy.
func (d *DB) writeBackupTo(target string) error {
	d.backupMu.Lock()
	defer d.backupMu.Unlock()

	// The temporary file is created private from the start instead of
	// tightened afterwards, and SQLite fills the empty file in place.
	f, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) //nolint:errcheck // gone after a successful rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := d.copyBackupTables(tmp); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

// copyBackupTables fills the empty file dst with the definition and a snapshot
// of each backupTables table the source has. The definitions come from the
// source, so a copy taken before an upgrade is exactly the old schema and
// content; opening a restored copy brings it up to date.
func (d *DB) copyBackupTables(dst string) error {
	bak, err := sql.Open("sqlite", "file:"+uriPath(dst)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer bak.Close()
	bak.SetMaxOpenConns(1) // ATTACH belongs to one connection
	if _, err := bak.Exec(`ATTACH DATABASE ? AS src`, "file:"+uriPath(d.path)); err != nil {
		return err
	}
	// One read transaction on the source: the tables are copied as of one moment.
	tx, err := bak.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	for _, table := range backupTables {
		var ddl string
		err := tx.QueryRow(`SELECT sql FROM src.sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&ddl)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ddl); err != nil {
			return fmt.Errorf("create %s: %w", table, err)
		}
		if _, err := tx.Exec(`INSERT INTO main.` + table + ` SELECT * FROM src.` + table); err != nil {
			return fmt.Errorf("copy %s: %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if _, err := bak.Exec(`DETACH DATABASE src`); err != nil {
		return err
	}
	return bak.Close()
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// OpenOrMigrate opens the database for a config location. When the database
// holds nothing yet, the legacy YAML at yamlPath (if any) is imported and
// renamed to config.yaml.migrated, so it is kept but no longer read; without
// one, the defaults are stored. It returns the loaded configuration.
//
// A corrupt or unreadable database does not stop the helper: it is moved aside
// to <db>.corrupt-<timestamp> and rebuilt from <db>.bak, else from
// config.yaml.migrated, else from the defaults. DB.RecoveryNotice reports what
// happened. A database that is merely invalid, locked, or newer than this
// helper is reported as an error and left untouched.
func OpenOrMigrate(yamlPath string) (*DB, *config.Config, error) {
	path := PathFor(yamlPath)
	d, cfg, found, err := openAndLoad(path)
	notice := ""
	if err != nil {
		if !IsCorrupt(err) {
			return nil, nil, err
		}
		d, cfg, found, notice, err = recoverCorrupt(path, err)
		if err != nil {
			return nil, nil, err
		}
	}
	d.recovery = notice
	if n, err := d.PruneProfileSecrets(); err != nil {
		slog.Warn("could not prune orphaned profile secrets", "error", err)
	} else if n > 0 {
		slog.Warn("removed profile secrets whose profile no longer exists", "count", n)
	}
	if found {
		d.ensureBackup()
		return d, cfg, nil
	}

	// Nothing stored yet: import the legacy YAML, or after a recovery the YAML
	// an earlier migration set aside, or fall back to the defaults.
	source := ""
	switch {
	case fileExists(yamlPath):
		source = yamlPath
	case notice != "" && fileExists(yamlPath+".migrated"):
		source = yamlPath + ".migrated"
	}
	switch {
	case source != "":
		cfg, err = config.Load(source)
		if err != nil {
			d.Close()
			return nil, nil, fmt.Errorf("import %s: %w", source, err)
		}
		if notice != "" {
			d.recovery += "; rebuilt from " + source
		}
	default:
		cfg = config.DefaultConfig()
		if notice != "" {
			d.recovery += "; no backup or migrated YAML was found, so it starts from the defaults"
		}
	}
	if err := d.Save(cfg); err != nil {
		d.Close()
		return nil, nil, err
	}
	if source == yamlPath {
		if err := os.Rename(yamlPath, yamlPath+".migrated"); err != nil {
			d.Close()
			return nil, nil, fmt.Errorf("set aside %s after import: %w", yamlPath, err)
		}
	}
	return d, cfg, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// openAndLoad opens path and reads its configuration.
func openAndLoad(path string) (*DB, *config.Config, bool, error) {
	d, err := Open(path)
	if err != nil {
		return nil, nil, false, err
	}
	cfg, found, err := d.Load()
	if err == nil {
		err = d.probeHistoryTables()
	}
	if err != nil {
		d.Close()
		return nil, nil, false, err
	}
	return d, cfg, found, nil
}

// probeHistoryTables touches the end of each history table and its index, so
// damage there is found at open, where the file can still be set aside and
// restored, rather than at the first write, where the writers can only stop.
func (d *DB) probeHistoryTables() error {
	for _, q := range []string{
		`SELECT COALESCE(MAX(id), 0) FROM access`,
		`SELECT COALESCE(MAX(ts), 0) FROM access`,
		`SELECT COALESCE(MAX(sequence), 0) FROM activity`,
		`SELECT COALESCE(MAX(time), 0) FROM activity`,
	} {
		var n int64
		if err := d.db.QueryRow(q).Scan(&n); err != nil {
			return fmt.Errorf("read history tables: %w", err)
		}
	}
	return nil
}

// ensureBackup writes the backup when none exists yet, as on the first start
// after an upgrade.
func (d *DB) ensureBackup() {
	if _, err := os.Stat(d.path + BackupSuffix); err == nil {
		return
	}
	if err := d.writeBackup(); err != nil {
		slog.Warn("could not write the config database backup", "path", d.path+BackupSuffix, "error", err)
	}
}

// IsCorrupt reports whether err means the database file itself is damaged, as
// opposed to busy, unwritable, invalid, or newer. Only damage justifies moving
// the file aside.
func IsCorrupt(err error) bool {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntax) || errors.As(err, &typeErr) {
		return true
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		// The low byte is the primary result code: 11 is SQLITE_CORRUPT and 26
		// is SQLITE_NOTADB.
		switch sqliteErr.Code() & 0xff {
		case 11, 26:
			return true
		}
	}
	return false
}

// recoverCorrupt moves the damaged database and its journals aside and returns
// a usable database: the .bak restored when it is sound, otherwise an empty
// one for the caller to seed. cause is why the original could not be used.
func recoverCorrupt(path string, cause error) (*DB, *config.Config, bool, string, error) {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	aside := path + ".corrupt-" + stamp
	if err := os.Rename(path, aside); err != nil {
		return nil, nil, false, "", fmt.Errorf("config database is corrupt (%v) and could not be moved aside: %w", cause, err)
	}
	// A leftover rollback journal or WAL belongs to the damaged file and would
	// be replayed into whatever replaces it.
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if err := os.Rename(path+suffix, aside+suffix); err != nil && !os.IsNotExist(err) {
			return nil, nil, false, "", fmt.Errorf("move %s aside: %w", path+suffix, err)
		}
	}
	// The history tables are not in any backup, so a restore never has them.
	notice := fmt.Sprintf("config database was corrupt (%v); moved to %s; access and activity history start empty", cause, aside)
	// A copy kept from a schema upgrade is the only record of the older lists.
	if kept := preUpgradeBackups(path); len(kept) > 0 {
		notice += "; the copy from before a schema upgrade is kept as " + strings.Join(kept, ", ")
	}
	slog.Error("config database is corrupt; rebuilding it", "error", cause, "moved_to", aside)

	backup := path + BackupSuffix
	if _, err := os.Stat(backup); err == nil {
		if err := copyPrivate(backup, path); err == nil {
			d, cfg, found, err := openAndLoad(path)
			if err == nil && found {
				return d, cfg, true, notice + "; restored from " + backup, nil
			}
			if d != nil {
				d.Close()
			}
			slog.Error("config database backup is not usable", "path", backup, "error", err)
			os.Remove(path) //nolint:errcheck // our own failed copy
		} else {
			slog.Error("could not restore the config database backup", "path", backup, "error", err)
		}
	}

	d, err := Open(path)
	if err != nil {
		return nil, nil, false, "", fmt.Errorf("recreate config database: %w", err)
	}
	return d, nil, false, notice, nil
}

// copyPrivate copies src to a new file dst with mode 0600.
func copyPrivate(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst) //nolint:errcheck // a partial copy is useless
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
