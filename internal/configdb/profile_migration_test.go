package configdb

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/platform"
	"github.com/quocln/routewise/internal/testenv"
)

// openVPN is the V1 database's one VPN client, and logFile its log path as the
// JSON settings store it: both must pass validation on this OS once loaded.
var (
	openVPN = testenv.Exe("/opt/homebrew/sbin/openvpn")
	logFile = func() string {
		encoded, err := json.Marshal(filepath.Join(platform.LogDir(), "routewise.log"))
		if err != nil {
			panic(err)
		}
		return string(encoded)
	}()
)

// schemaV1 is the schema the first releases created, verbatim.
const schemaV1 = `
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE vpn_clients (client TEXT PRIMARY KEY, position INTEGER NOT NULL);
CREATE TABLE domains (list TEXT NOT NULL, pattern TEXT NOT NULL, position INTEGER NOT NULL, PRIMARY KEY (list, pattern));
`

// writeV1Database builds a schema 1 database holding a small configuration.
func writeV1Database(t *testing.T, path string) {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+uriPath(path))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	stmts := []string{
		schemaV1,
		`INSERT INTO meta VALUES ('schema_version', '1')`,
		`INSERT INTO settings VALUES ('dns.servers', '["9.9.9.9"]')`,
		`INSERT INTO settings VALUES ('dns.cache_ttl', '120')`,
		`INSERT INTO settings VALUES ('dns.use_vpn_dns', 'true')`,
		`INSERT INTO settings VALUES ('routing.mode', '"additive"')`,
		`INSERT INTO settings VALUES ('daemon.poll_interval', '2')`,
		`INSERT INTO settings VALUES ('daemon.pid_file', '"/var/run/routewise.pid"')`,
		`INSERT INTO settings VALUES ('daemon.log_file', '` + logFile + `')`,
		`INSERT INTO settings VALUES ('daemon.log_level', '"info"')`,
		`INSERT INTO settings VALUES ('history.enabled', 'true')`,
		`INSERT INTO settings VALUES ('history.retention_days', '7')`,
		`INSERT INTO vpn_clients VALUES ('` + openVPN + `', 0)`,
		`INSERT INTO domains VALUES ('', 'any.example.com', 0)`,
		`INSERT INTO domains VALUES ('` + openVPN + `', '*.corp.example.com', 0)`,
	}
	for _, s := range stmts {
		if _, err := raw.Exec(s); err != nil {
			t.Fatalf("seed schema 1: %v\n%s", err, s)
		}
	}
}

func tableExists(t *testing.T, path, table string) bool {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+uriPath(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var n int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func schemaVersionOf(t *testing.T, path string) string {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+uriPath(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var v string
	if err := raw.QueryRow(`SELECT value FROM meta WHERE key='schema_version'`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestMigrationFromV1KeepsEverythingAndBacksUpFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	writeV1Database(t, path)

	d, err := Open(path)
	if err != nil {
		t.Fatalf("open a schema 1 database: %v", err)
	}
	defer d.Close()

	// The backup is the schema 1 file as it was before the upgrade.
	backup := path + BackupSuffix
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("no backup written before migrating: %v", err)
	}
	if tableExists(t, backup, "profiles") || tableExists(t, backup, "profile_secrets") {
		t.Error("the backup must be the pre-migration schema 1 content")
	}
	if got := schemaVersionOf(t, backup); got != "1" {
		t.Errorf("backup schema version = %s, want 1", got)
	}
	info, err := os.Stat(backup)
	if err != nil || !testenv.HasPerm(info, 0o600) {
		t.Errorf("backup mode = %v, want 0600 (err %v)", info.Mode().Perm(), err)
	}

	if got := schemaVersionOf(t, path); got != "4" {
		t.Errorf("schema version after migrating = %s, want 4", got)
	}
	for _, table := range []string{"profiles", "profile_secrets"} {
		if !tableExists(t, path, table) {
			t.Errorf("table %s was not created", table)
		}
	}

	cfg, found, err := d.Load()
	if err != nil || !found {
		t.Fatalf("load after migrating: found=%v err=%v", found, err)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0].Pattern != "any.example.com" ||
		len(cfg.VPNs) != 1 || cfg.VPNs[0].Client != openVPN ||
		len(cfg.VPNs[0].Domains) != 1 || cfg.VPNs[0].Domains[0].Pattern != "*.corp.example.com" {
		t.Errorf("lists changed by the migration: domains=%+v vpns=%+v", cfg.Domains, cfg.VPNs)
	}
	if cfg.DNS.Servers[0] != "9.9.9.9" || cfg.DNS.CacheTTL != 120 || !cfg.DNS.UseVPNDNS ||
		cfg.Routing.Mode != config.RoutingModeAdditive || cfg.Daemon.PollInterval != 2 {
		t.Errorf("settings changed by the migration: %+v", cfg)
	}
	if len(cfg.Profiles) != 0 {
		t.Errorf("a migrated database has no profiles, got %+v", cfg.Profiles)
	}

	// Reopening a current database does not back up or change anything.
	d.Close()
	before, _ := os.ReadFile(backup)
	d2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	d2.Close()
	after, _ := os.ReadFile(backup)
	if string(before) != string(after) {
		t.Error("opening a current database must not rewrite the backup")
	}
}

func TestMigrationRefusesToProceedWithoutABackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	writeV1Database(t, path)
	// A non-empty directory where the backup must land blocks the copy.
	if err := os.Mkdir(path+BackupSuffix, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+BackupSuffix, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("the upgrade must not run when the backup cannot be written")
	}
	if got := schemaVersionOf(t, path); got != "1" {
		t.Errorf("the database was upgraded without a backup (schema %s)", got)
	}
}

func TestProfilesAndSecretsLiveInTheirOwnTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	const secret = "PrivateKey = SUPERSECRETKEYMATERIAL"
	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: "a.example.com"}}
	cfg.Profiles = []config.TunnelProfile{{ID: "0a1b2c3d", Kind: "wireguard", Name: "Office", AutoConnect: true, DNS: []string{"10.8.0.1"}}}
	cfg.VPNs = []config.VPNRoute{{Client: "routewise-wireguard:0a1b2c3d", Domains: []config.DomainRule{{Pattern: "10.9.0.0/16"}}}}
	if err := d.SetProfileSecret("0a1b2c3d", secret); err != nil {
		t.Fatal(err)
	}
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}

	got, found, err := d.Load()
	if err != nil || !found {
		t.Fatalf("load: %v", err)
	}
	if len(got.Profiles) != 1 || got.Profiles[0].Name != "Office" || !got.Profiles[0].AutoConnect ||
		got.Profiles[0].DNS[0] != "10.8.0.1" || got.VPNs[0].Client != "routewise-wireguard:0a1b2c3d" {
		t.Errorf("profile round trip: %+v / %+v", got.Profiles, got.VPNs)
	}

	// The secret is readable only through its accessor.
	if s, err := d.ProfileSecret("0a1b2c3d"); err != nil || s != secret {
		t.Errorf("ProfileSecret = %q, %v", s, err)
	}
	if _, err := d.ProfileSecret("ffffffff"); err != ErrNoSecret {
		t.Errorf("a missing secret = %v, want ErrNoSecret", err)
	}
	if has, _ := d.HasProfileSecret("0a1b2c3d"); !has {
		t.Error("HasProfileSecret = false")
	}
	for _, table := range []string{"settings", "vpn_clients", "domains", "profiles", "meta"} {
		rows, err := d.db.Query(`SELECT * FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for _, v := range vals {
				if strings.Contains(strings.ToLower(toString(v)), "supersecret") {
					t.Errorf("secret found in table %s", table)
				}
			}
		}
		rows.Close()
	}

	// Saving the configuration again never loses or alters the secret.
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.ProfileSecret("0a1b2c3d"); s != secret {
		t.Error("a configuration save changed the secret")
	}

	// The backup carries it too, so a restore keeps the credentials.
	if !tableExists(t, path+BackupSuffix, "profile_secrets") {
		t.Error("the backup must include the secret table")
	}

	// A secret whose profile is gone is pruned at open, not at save.
	cfg.Profiles, cfg.VPNs = nil, nil
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if n, err := d.PruneProfileSecrets(); err != nil || n != 1 {
		t.Errorf("PruneProfileSecrets = %d, %v; want 1", n, err)
	}
	if _, err := d.ProfileSecret("0a1b2c3d"); err != ErrNoSecret {
		t.Error("the orphaned secret must be gone")
	}
	if err := d.DeleteProfileSecret("0a1b2c3d"); err != nil {
		t.Errorf("deleting a missing secret must not fail: %v", err)
	}
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	}
	return ""
}

func TestOpenOrMigratePrunesOrphanedSecrets(t *testing.T) {
	yamlPath := filepath.Join(t.TempDir(), "config.yaml")
	d, _, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetProfileSecret("deadbeef", "orphan"); err != nil {
		t.Fatal(err)
	}
	d.Close()

	d, _, err = OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.ProfileSecret("deadbeef"); err != ErrNoSecret {
		t.Errorf("an orphaned secret survived the open: %v", err)
	}
}

func TestMigrationKeepsAPermanentV1BackupThatLaterSavesNeverTouch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	writeV1Database(t, path)

	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	permanent := path + ".v1.bak"
	if want := preUpgradeBackupPath(path, 1); permanent != want {
		t.Fatalf("pre-upgrade backup path %s, want %s", want, permanent)
	}
	info, err := os.Stat(permanent)
	if err != nil {
		t.Fatalf("no permanent pre-migration backup: %v", err)
	}
	if !testenv.HasPerm(info, 0o600) {
		t.Errorf("permanent backup mode = %v, want 0600", info.Mode().Perm())
	}
	if got := schemaVersionOf(t, permanent); got != "1" || tableExists(t, permanent, "profiles") {
		t.Errorf("permanent backup must be the schema 1 file (version %s)", got)
	}
	before, err := os.ReadFile(permanent)
	if err != nil {
		t.Fatal(err)
	}

	// The first save after the upgrade rewrites .bak with the new schema, which
	// is exactly why the permanent copy exists.
	cfg, found, err := d.Load()
	if err != nil || !found {
		t.Fatalf("load: %v", err)
	}
	cfg.Domains = append(cfg.Domains, config.DomainRule{Pattern: "later.example.com"})
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if got := schemaVersionOf(t, path+BackupSuffix); got != "4" {
		t.Fatalf(".bak schema after a save = %s, want 4 (the save refreshes it)", got)
	}
	after, err := os.ReadFile(permanent)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("a save rewrote the permanent pre-migration backup")
	}

	// Neither does reopening the upgraded database.
	d.Close()
	d2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	again, _ := os.ReadFile(permanent)
	if string(before) != string(again) {
		t.Error("reopening rewrote the permanent pre-migration backup")
	}
}

func TestMigrationRefusesToProceedWithoutThePermanentBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	writeV1Database(t, path)
	// A non-empty directory where the permanent copy must land blocks it.
	blocker := path + ".v1.bak"
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocker, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("the upgrade must not run when the permanent backup cannot be written")
	}
	if got := schemaVersionOf(t, path); got != "1" {
		t.Errorf("the database was upgraded without the permanent backup (schema %s)", got)
	}
}

func TestRecoveryNoticeNamesThePermanentBackup(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	path := PathFor(yamlPath)
	writeV1Database(t, path)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	if err := os.WriteFile(path, []byte("this is not a database at all, just padding padding padding padding"), 0o600); err != nil {
		t.Fatal(err)
	}
	rebuilt, _, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rebuilt.Close()
	notice := rebuilt.RecoveryNotice()
	if !strings.Contains(notice, "routewise.db.v1.bak") {
		t.Errorf("the recovery notice must name the permanent pre-upgrade copy, got %q", notice)
	}
}

func TestDeletedSecretsAreOverwrittenInTheDatabaseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	const marker = "PRIVATEKEYMARKERzzzzzzzzzzzzzzzzzz"
	if err := d.SetProfileSecret("0a1b2c3d", marker); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteProfileSecret("0a1b2c3d"); err != nil {
		t.Fatal(err)
	}
	d.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), marker) {
		t.Error("a deleted secret is still readable in the database file's free pages")
	}
}
