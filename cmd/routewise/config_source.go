package main

import (
	"fmt"
	"os"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/configdb"
)

// readStored reads what the helper would use: the SQLite database next to the
// config path once it holds a configuration, otherwise the legacy YAML. found
// is false only when nothing has ever been stored; every other failure is an
// error, so callers can tell "no config yet" from "the config could not be
// read".
func readStored() (cfg *config.Config, found bool, err error) {
	dbPath := configdb.PathFor(getConfigPath())
	switch _, statErr := os.Stat(dbPath); {
	case statErr == nil:
		db, err := configdb.Open(dbPath)
		if err != nil {
			return nil, false, err
		}
		defer db.Close()
		cfg, found, err := db.Load()
		if err != nil {
			return nil, false, err
		}
		if found {
			return cfg, true, nil
		}
	case !os.IsNotExist(statErr):
		return nil, false, statErr
	}

	switch _, statErr := os.Stat(getConfigPath()); {
	case statErr == nil:
		cfg, err := config.Load(getConfigPath())
		if err != nil {
			return nil, false, err
		}
		return cfg, true, nil
	case os.IsNotExist(statErr):
		return nil, false, nil
	default:
		return nil, false, statErr
	}
}

// loadConfig reads the configuration the helper uses. With nothing stored it
// returns the error config.Load reports for a missing or empty config.
func loadConfig() (*config.Config, error) {
	cfg, found, err := readStored()
	if err != nil {
		return nil, err
	}
	if !found {
		return config.Load(getConfigPath())
	}
	return cfg, nil
}

// loadConfigForUpdate reads the configuration a read-modify-write command is
// about to change and save. It falls back to the defaults only when nothing
// has ever been stored. Any other failure (a locked or damaged database, a
// newer schema, an invalid config) is returned: saving defaults plus one edit
// over it would erase every list and the allowlist.
func loadConfigForUpdate() (*config.Config, error) {
	cfg, found, err := readStored()
	if err != nil {
		return nil, fmt.Errorf("load config (nothing was changed): %w", err)
	}
	if !found {
		return config.DefaultConfig(), nil
	}
	return cfg, nil
}

// saveConfig writes the configuration while no helper is running, importing
// the legacy YAML into the database first if that has not happened yet.
func saveConfig(cfg *config.Config) error {
	db, _, err := configdb.OpenOrMigrate(getConfigPath())
	if err != nil {
		return err
	}
	defer db.Close()
	if notice := db.RecoveryNotice(); notice != "" {
		fmt.Fprintln(os.Stderr, "WARNING: "+notice)
	}
	return db.Save(cfg)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
