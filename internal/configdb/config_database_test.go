package configdb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/testenv"
)

var wireGuard = testenv.Exe("/Applications/WireGuard.app/Contents/PlugIns/WireGuardNetworkExtension.appex/Contents/MacOS/WireGuardNetworkExtension")

func TestSaveAndLoadRoundTrip(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if _, found, err := d.Load(); err != nil || found {
		t.Fatalf("a new database must hold nothing yet (found=%v err=%v)", found, err)
	}

	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: "b.example.com"}, {Pattern: "a.example.com"}}
	cfg.VPNs = []config.VPNRoute{
		{Client: wireGuard, Domains: []config.DomainRule{{Pattern: "*.corp.example.com"}}},
		{Client: testenv.Exe("/opt/homebrew/sbin/openvpn")},
	}
	cfg.DNS.UseVPNDNS = true
	cfg.Routing.AllowIPv6 = true
	cfg.Routing.DefaultVPN = testenv.Exe("/opt/homebrew/sbin/openvpn")
	cfg.Routing.DefaultVPNFallback = wireGuard
	cfg.Routing.DefaultVPNExcept = []string{"bank.example.com", "10.20.0.0/16"}
	cfg.Routing.Mode = config.RoutingModeAdditive
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}

	got, found, err := d.Load()
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if len(got.Domains) != 2 || got.Domains[0].Pattern != "b.example.com" {
		t.Errorf("Domains = %+v, want the order kept", got.Domains)
	}
	if len(got.VPNs) != 2 || got.VPNs[0].Client != wireGuard || len(got.VPNs[0].Domains) != 1 || len(got.VPNs[1].Domains) != 0 {
		t.Errorf("VPNs = %+v, want both clients in priority order with their own lists", got.VPNs)
	}
	if got.Routing.DefaultVPN != testenv.Exe("/opt/homebrew/sbin/openvpn") || got.Routing.DefaultVPNFallback != wireGuard {
		t.Errorf("default VPN after a round trip = %q, fallback %q", got.Routing.DefaultVPN, got.Routing.DefaultVPNFallback)
	}
	if !slices.Equal(got.Routing.DefaultVPNExcept, cfg.Routing.DefaultVPNExcept) {
		t.Errorf("exceptions after a round trip = %v", got.Routing.DefaultVPNExcept)
	}
	if !got.DNS.UseVPNDNS || !got.Routing.AllowIPv6 || got.Routing.Mode != config.RoutingModeAdditive || got.Daemon.PidFile != cfg.Daemon.PidFile {
		t.Errorf("settings not round-tripped: %+v", got)
	}

	info, err := os.Stat(d.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !testenv.HasPerm(info, 0o600) {
		t.Errorf("database mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestSaveReplacesEverything(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	first := config.DefaultConfig()
	first.Domains = []config.DomainRule{{Pattern: "old.example.com"}}
	first.VPNs = []config.VPNRoute{{Client: wireGuard}}
	if err := d.Save(first); err != nil {
		t.Fatal(err)
	}
	second := config.DefaultConfig()
	second.Domains = []config.DomainRule{{Pattern: "new.example.com"}}
	if err := d.Save(second); err != nil {
		t.Fatal(err)
	}

	got, _, _ := d.Load()
	if len(got.Domains) != 1 || got.Domains[0].Pattern != "new.example.com" || len(got.VPNs) != 0 {
		t.Fatalf("got %+v, want only the second config", got)
	}
}

func TestOpenOrMigrateImportsAndSetsAsideTheYAML(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	legacy := config.DefaultConfig()
	legacy.Domains = []config.DomainRule{{Pattern: "legacy.example.com"}}
	if err := config.Save(yamlPath, legacy); err != nil {
		t.Fatal(err)
	}

	d, cfg, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	d.Close()
	if len(cfg.Domains) != 1 || cfg.Domains[0].Pattern != "legacy.example.com" {
		t.Fatalf("migrated domains = %+v", cfg.Domains)
	}
	if _, err := os.Stat(yamlPath); !os.IsNotExist(err) {
		t.Error("the YAML must be set aside so it is not read again")
	}
	if _, err := os.Stat(yamlPath + ".migrated"); err != nil {
		t.Error("the YAML must be kept as config.yaml.migrated, never deleted")
	}

	// A YAML that reappears (an installer copying its template) is ignored.
	other := config.DefaultConfig()
	other.Domains = []config.DomainRule{{Pattern: "template.example.com"}}
	if err := config.Save(yamlPath, other); err != nil {
		t.Fatal(err)
	}
	d, cfg, err = OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if cfg.Domains[0].Pattern != "legacy.example.com" {
		t.Fatalf("domains = %+v, want the database to win over a new YAML", cfg.Domains)
	}
}

// seed writes a config with one domain through OpenOrMigrate and returns the
// config path next to which the database lives.
func seed(t *testing.T, domain string) string {
	t.Helper()
	yamlPath := filepath.Join(t.TempDir(), "config.yaml")
	d, _, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: domain}}
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}
	d.Close()
	return yamlPath
}

func corrupt(t *testing.T, yamlPath string) {
	t.Helper()
	if err := os.WriteFile(PathFor(yamlPath), []byte("this is not a sqlite database, just text padding padding padding"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func asideFiles(t *testing.T, yamlPath string) []string {
	t.Helper()
	m, err := filepath.Glob(PathFor(yamlPath) + ".corrupt-*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestLoadRefusesAStoredConfigTheHelperMustNotActOn(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: "a.example.com"}}
	cfg.Daemon.LogFile = "/etc/evil.log"
	cfg.DNS.Servers = nil
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}

	_, found, err := d.Load()
	if !errors.Is(err, ErrInvalidConfig) || found {
		t.Fatalf("Load = found %v, err %v; want an ErrInvalidConfig refusal", found, err)
	}
	if IsCorrupt(err) {
		t.Error("an invalid config is not corruption and must never be moved aside")
	}
}

func TestOpenOrMigrateRefusesAnInvalidConfigAndLeavesTheFileAlone(t *testing.T) {
	yamlPath := seed(t, "a.example.com")
	d, err := Open(PathFor(yamlPath))
	if err != nil {
		t.Fatal(err)
	}
	bad := config.DefaultConfig()
	bad.Domains = []config.DomainRule{{Pattern: "a.example.com"}}
	bad.DNS.Servers = []string{"not-an-ip"}
	if err := d.Save(bad); err != nil {
		t.Fatal(err)
	}
	d.Close()

	if _, _, err := OpenOrMigrate(yamlPath); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("OpenOrMigrate = %v, want the invalid config refused", err)
	}
	if got := asideFiles(t, yamlPath); len(got) != 0 {
		t.Errorf("an invalid config must not be moved aside: %v", got)
	}
}

func TestASeededStoreWithNoDomainsYetLoads(t *testing.T) {
	yamlPath := filepath.Join(t.TempDir(), "config.yaml")
	d, cfg, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if cfg.PatternCount() != 0 {
		t.Fatalf("seeded config = %+v, want the defaults", cfg)
	}
	d, cfg, err = OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatalf("a seeded store must reopen: %v", err)
	}
	d.Close()
}

func TestEverySaveRefreshesAPrivateBackup(t *testing.T) {
	yamlPath := seed(t, "first.example.com")
	backup := PathFor(yamlPath) + BackupSuffix
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatalf("no backup after a save: %v", err)
	}
	if !testenv.HasPerm(info, 0o600) {
		t.Errorf("backup mode = %o, want 0600", info.Mode().Perm())
	}

	d, _, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	next := config.DefaultConfig()
	next.Domains = []config.DomainRule{{Pattern: "second.example.com"}}
	if err := d.Save(next); err != nil {
		t.Fatal(err)
	}
	d.Close()

	b, err := Open(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	got, found, err := b.Load()
	if err != nil || !found || got.Domains[0].Pattern != "second.example.com" {
		t.Fatalf("backup = %+v found=%v err=%v, want the latest save", got, found, err)
	}
	if left, _ := filepath.Glob(PathFor(yamlPath) + "*.tmp"); len(left) != 0 {
		t.Errorf("temporary backup files left behind: %v", left)
	}
}

func TestACorruptDatabaseIsRestoredFromItsBackup(t *testing.T) {
	yamlPath := seed(t, "kept.example.com")
	corrupt(t, yamlPath)

	d, cfg, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatalf("a corrupt database must not stop the helper: %v", err)
	}
	defer d.Close()
	if len(cfg.Domains) != 1 || cfg.Domains[0].Pattern != "kept.example.com" {
		t.Fatalf("config = %+v, want the backup's content", cfg.Domains)
	}
	notice := d.RecoveryNotice()
	if !strings.Contains(notice, "corrupt") || !strings.Contains(notice, BackupSuffix) {
		t.Errorf("notice = %q, want the reason and the source", notice)
	}
	aside := asideFiles(t, yamlPath)
	if len(aside) != 1 {
		t.Fatalf("moved-aside files = %v, want exactly one", aside)
	}
	if data, _ := os.ReadFile(aside[0]); !strings.HasPrefix(string(data), "this is not a sqlite") {
		t.Error("the damaged file must be kept intact for inspection")
	}
	info, _ := os.Stat(PathFor(yamlPath))
	if info == nil || !testenv.HasPerm(info, 0o600) {
		t.Errorf("restored database mode = %v, want 0600", info)
	}

	// The next start is clean.
	d2, _, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if d2.RecoveryNotice() != "" {
		t.Errorf("a healthy database reported %q", d2.RecoveryNotice())
	}
}

func TestACorruptDatabaseWithoutABackupIsRebuiltFromTheMigratedYAML(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	legacy := config.DefaultConfig()
	legacy.Domains = []config.DomainRule{{Pattern: "legacy.example.com"}}
	if err := config.Save(yamlPath, legacy); err != nil {
		t.Fatal(err)
	}
	d, _, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	corrupt(t, yamlPath)
	if err := os.Remove(PathFor(yamlPath) + BackupSuffix); err != nil {
		t.Fatal(err)
	}

	d, cfg, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatalf("OpenOrMigrate: %v", err)
	}
	defer d.Close()
	if len(cfg.Domains) != 1 || cfg.Domains[0].Pattern != "legacy.example.com" {
		t.Fatalf("config = %+v, want config.yaml.migrated's content", cfg.Domains)
	}
	if !strings.Contains(d.RecoveryNotice(), "config.yaml.migrated") {
		t.Errorf("notice = %q, want it to name the migrated YAML", d.RecoveryNotice())
	}
	if _, err := os.Stat(yamlPath + ".migrated"); err != nil {
		t.Error("the migrated YAML must stay where it is")
	}
}

func TestACorruptDatabaseWithNothingToRestoreStartsFromDefaults(t *testing.T) {
	yamlPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(PathFor(yamlPath), []byte("garbage garbage garbage garbage garbage garbage garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	d, cfg, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatalf("the helper must start: %v", err)
	}
	defer d.Close()
	if cfg.PatternCount() != 0 || len(cfg.DNS.Servers) == 0 {
		t.Errorf("config = %+v, want the defaults", cfg)
	}
	if n := d.RecoveryNotice(); !strings.Contains(n, "defaults") {
		t.Errorf("notice = %q, want it to say the defaults were used", n)
	}
	if len(asideFiles(t, yamlPath)) != 1 {
		t.Error("the damaged file must be kept")
	}
}

func TestACorruptBackupFallsThroughToTheNextSource(t *testing.T) {
	yamlPath := seed(t, "x.example.com")
	corrupt(t, yamlPath)
	if err := os.WriteFile(PathFor(yamlPath)+BackupSuffix, []byte("also not a database, also padding padding padding"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, cfg, err := OpenOrMigrate(yamlPath)
	if err != nil {
		t.Fatalf("OpenOrMigrate: %v", err)
	}
	defer d.Close()
	if cfg.PatternCount() != 0 {
		t.Errorf("config = %+v, want the defaults after both files proved unusable", cfg)
	}
}

func TestANewerSchemaIsReportedAndNeverMovedAside(t *testing.T) {
	yamlPath := seed(t, "x.example.com")
	d, err := Open(PathFor(yamlPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec(`UPDATE meta SET value = '99' WHERE key = 'schema_version'`); err != nil {
		t.Fatal(err)
	}
	d.Close()

	if _, _, err := OpenOrMigrate(yamlPath); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("OpenOrMigrate = %v, want ErrNewerSchema", err)
	}
	if got := asideFiles(t, yamlPath); len(got) != 0 {
		t.Errorf("a newer database must stay put: %v", got)
	}
}

func TestADatabasePathWithURISpecialCharactersOpens(t *testing.T) {
	// Windows refuses '?' in a file name, and the rest still need URI escaping.
	dir := "odd?name#1%"
	if runtime.GOOS == "windows" {
		dir = "odd#name%1"
	}
	path := filepath.Join(t.TempDir(), dir, FileName)
	d, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()
	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: "a.example.com"}}
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the database must be created at the exact path: %v", err)
	}
}

func TestHistorySettingsRoundTripAndOldDatabasesGetDefaults(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: "a.example.com"}}
	cfg.History = config.HistoryConfig{Enabled: false, RetentionDays: 30}
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}
	got, _, err := d.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.History.Enabled || got.History.RetentionDays != 30 {
		t.Fatalf("History = %+v, want it stored", got.History)
	}

	// A database written before history existed has neither key.
	if _, err := d.db.Exec(`DELETE FROM settings WHERE key LIKE 'history.%'`); err != nil {
		t.Fatal(err)
	}
	got, _, err = d.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !got.History.Enabled || got.History.RetentionDays != 7 {
		t.Fatalf("History = %+v, want the defaults when the keys are missing", got.History)
	}

	// A hand-edited out-of-range value is refused, not trusted.
	if _, err := d.db.Exec(`INSERT INTO settings (key, value) VALUES ('history.retention_days', '5000')`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Load(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestConcurrentBackupRefreshesStayPrivateAndSucceed(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Save(config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	backup := d.Path() + BackupSuffix

	const writers, rounds = 8, 25
	errs := make(chan error, writers*rounds)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if err := d.writeBackup(); err != nil {
					errs <- err
					continue
				}
				// A reader must never see the backup readable by others.
				if info, err := os.Stat(backup); err != nil {
					errs <- err
				} else if !testenv.HasPerm(info, 0o600) {
					errs <- fmt.Errorf("backup mode = %o, want 0600", info.Mode().Perm())
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if left, _ := filepath.Glob(backup + ".*.tmp"); len(left) != 0 {
		t.Errorf("temporary backup files left behind: %v", left)
	}
}

func TestTelemetrySettingsRoundTripAndOldDatabasesGetDefaults(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: "example.com"}}
	cfg.Telemetry = config.TelemetryConfig{DSN: "https://k@h.example/5", Errors: true, Logs: false, Traces: true, TracesSampleRate: 0.4}
	if err := d.Save(cfg); err != nil {
		t.Fatal(err)
	}
	got, _, err := d.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Telemetry != cfg.Telemetry {
		t.Errorf("telemetry = %+v, want %+v", got.Telemetry, cfg.Telemetry)
	}

	// A database written before the telemetry rows existed reads as defaults.
	if _, err := d.db.Exec(`DELETE FROM settings WHERE key LIKE 'telemetry.%'`); err != nil {
		t.Fatal(err)
	}
	got, _, err = d.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Telemetry.DSN != "" || got.Telemetry.TracesSampleRate != config.DefaultTracesSampleRate {
		t.Errorf("old database telemetry = %+v", got.Telemetry)
	}
}
