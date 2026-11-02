package main

import (
	"github.com/quocln/routewise/internal/platform"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/testenv"
)

func TestSystemdUnitRunsTheForegroundDaemonAfterTheNetworkAndResolver(t *testing.T) {
	unit := systemdUnit("/usr/lib/routewise/routewise", "/etc/routewise/config.yaml")
	for _, want := range []string{
		"ExecStart=/usr/lib/routewise/routewise start --foreground --config /etc/routewise/config.yaml\n",
		"Type=simple\n",
		"Restart=on-failure\n",
		"After=network-online.target systemd-resolved.service\n",
		"Wants=network-online.target\n",
		"WantedBy=multi-user.target\n",
		"NoNewPrivileges=yes\n",
		"ProtectSystem=strict\n",
		"ReadWritePaths=/etc/routewise /var/lib/routewise /var/log/routewise /run\n",
		"ProtectHome=read-only\n",
		"PrivateTmp=yes\n",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
}

func TestStarterConfigLoadsAsAValidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	logFile := filepath.Join(platform.LogDir(), "routewise.log")
	content := starterConfig("/run/routewise.pid", logFile)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("starter config does not load: %v", err)
	}
	if cfg.Daemon.PidFile != "/run/routewise.pid" || cfg.Daemon.LogFile != logFile {
		t.Errorf("daemon paths = %q, %q", cfg.Daemon.PidFile, cfg.Daemon.LogFile)
	}
	if cfg.Routing.Mode != config.RoutingModeInverted {
		t.Errorf("routing mode = %q", cfg.Routing.Mode)
	}
}

func TestInstallExecutableCopiesAndReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "lib", "routewise")
	if err := os.WriteFile(src, []byte("v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installExecutable(src, dst); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("v2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installExecutable(src, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "v2" {
		t.Fatalf("installed content = %q, %v", got, err)
	}
	if info, _ := os.Stat(dst); !testenv.HasPerm(info, 0o755) {
		t.Errorf("mode = %o, want 755", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(dst))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestInstallExecutableRefusesSymlinksAndNonRegularSources(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	for name, src := range map[string]string{"symlink": link, "directory": dir, "missing": filepath.Join(dir, "none")} {
		if err := installExecutable(src, dst); err == nil {
			t.Errorf("%s source was accepted", name)
		}
	}
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		t.Errorf("a refused install left %s behind: %v", dst, err)
	}
}

func TestSeedConfigKeepsAnExistingConfigOrDatabase(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "etc", "config.yaml")
	dbPath := filepath.Join(dir, "lib", "routewise.db")

	seeded, err := seedConfig(configPath, dbPath, "fresh: 1\n")
	if err != nil || !seeded {
		t.Fatalf("seed on empty system = %v, %v", seeded, err)
	}
	if info, _ := os.Stat(configPath); !testenv.HasPerm(info, 0o644) {
		t.Errorf("config mode = %o, want 644", info.Mode().Perm())
	}

	if err := os.WriteFile(configPath, []byte("mine: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if seeded, err := seedConfig(configPath, dbPath, "fresh: 1\n"); err != nil || seeded {
		t.Fatalf("seed over an existing config = %v, %v", seeded, err)
	}
	if got, _ := os.ReadFile(configPath); string(got) != "mine: 1\n" {
		t.Errorf("existing config was overwritten: %q", got)
	}

	// Once the helper has run, the database holds the configuration and the
	// imported config.yaml is gone: seeding must not bring a starter back.
	os.Remove(configPath)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if seeded, err := seedConfig(configPath, dbPath, "fresh: 1\n"); err != nil || seeded {
		t.Fatalf("seed beside an existing database = %v, %v", seeded, err)
	}
	if _, err := os.Lstat(configPath); !os.IsNotExist(err) {
		t.Errorf("a starter config was written beside an existing database: %v", err)
	}
}
