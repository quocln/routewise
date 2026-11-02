package main

import (
	"fmt"
	"os"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/configdb"
	"github.com/quocln/routewise/internal/daemon"
	"github.com/quocln/routewise/internal/telemetry"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the VPN routing daemon",
	Long: `Start the VPN routing daemon in the foreground.

The daemon will:
1. Monitor VPN interface (utun*) for connection changes
2. Resolve configured domain patterns to IP addresses
3. Add routes for those IPs through the VPN gateway
4. Periodically refresh DNS to handle IP changes

Requires root privileges for route manipulation.

Examples:
  sudo routewise start
  sudo routewise start --config /path/to/config.yaml`,
	RunE: runStart,
}

var foreground bool

// daemonIgnoresTermSignals is set by a service host that stops the daemon
// itself, so SIGTERM (which Windows raises on user logoff) does not.
var daemonIgnoresTermSignals bool

func init() {
	rootCmd.AddCommand(startCmd)
	startCmd.Flags().BoolVarP(&foreground, "foreground", "f", false, "run in foreground (default, for launchd)")
}

// helperStart brings the daemon up and returns it with the function that
// releases what it opened (the config database). It is separate from waiting
// for shutdown so a service host can report progress to its manager around it.
type helperStart func() (*daemon.Daemon, func(), error)

func runStart(cmd *cobra.Command, args []string) error {
	// A panic on this goroutine is reported, flushed, and still crashes the
	// helper so launchd restarts it.
	defer telemetry.RepanicAfterCapture()
	telemetry.Default.SetBuild(Version, environment())

	// Check if running as root
	if !isPrivileged() {
		fmt.Fprintln(os.Stderr, "Warning: Running without root privileges. Route manipulation may fail.")
	}

	return runSupervised(startHelper)
}

// runForeground starts the daemon and blocks until a shutdown signal, then
// stops it cleanly.
func runForeground(start helperStart) error {
	d, release, err := start()
	if err != nil {
		return err
	}
	defer release()

	// Wait for shutdown signal
	d.Wait()
	d.Stop()

	return nil
}

func startHelper() (*daemon.Daemon, func(), error) {
	configPath := getConfigPath()
	dbPath := configdb.PathFor(configPath)

	if err := protectRuntimeDirs(dbPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, fmt.Errorf("runtime directory check failed")
	}

	// Validate config security unless bypassed: the database, and the legacy
	// YAML it may still import from.
	if !insecureConfig {
		for _, path := range []string{dbPath, configPath} {
			if err := config.ValidateConfigSecurity(path); err != nil {
				fmt.Fprintln(os.Stderr, err)
				fmt.Fprintln(os.Stderr, "\nUse --insecure-config to bypass (not recommended for production)")
				return nil, nil, fmt.Errorf("config security check failed")
			}
		}
	}

	// Open the config database. On first start it imports config.yaml and
	// sets it aside as config.yaml.migrated.
	db, cfg, err := configdb.OpenOrMigrate(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	// A corrupt database was rebuilt rather than left to crash-loop under
	// launchd. Say so on stderr, which launchd captures, and in the daemon log.
	recovery := db.RecoveryNotice()
	if recovery != "" {
		fmt.Fprintln(os.Stderr, "WARNING: "+recovery)
	}

	if verbose {
		cfg.Daemon.LogLevel = "debug"
	}

	// Create daemon
	d, err := daemon.New(cfg, db)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("init daemon: %w", err)
	}
	d.NoteConfigRecovery(recovery)
	// Built-in VPN credentials and per-user app preferences live in the same
	// database, in their own tables.
	d.SetSecretStore(db)
	d.SetPrefStore(db)
	// The access history and the activity log are tables of that database too.
	// They are disposable: a failure to open them is logged and never stops
	// the helper.
	d.OpenHistory(db)

	if daemonIgnoresTermSignals {
		d.IgnoreTermSignals()
	}

	// Start daemon
	if err := d.Start(); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("start daemon: %w", err)
	}

	fmt.Printf("Daemon started (pid %d)\n", os.Getpid())
	fmt.Printf("Monitoring %d domain patterns (config: %s)\n", cfg.PatternCount(), db.Path())
	fmt.Println("Press Ctrl+C to stop")

	return d, func() { db.Close() }, nil
}
