//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/quocln/routewise/internal/platform"
)

// protectRuntimeDirs gives the helper's data, log and run directories the
// access lists the install uses, and refuses to go on when one cannot be
// trusted. The helper may be the one that creates them (a foreground start with
// no install, or a restart after the folder was deleted), and a directory
// created under %ProgramData% inherits permissions that let every user read the
// database and plant files in it. An existing directory is repaired when
// SYSTEM or Administrators own it and refused when anyone else does; the
// database's journal files are held to the same owner rule.
//
// An unelevated helper is left alone: it cannot route, and it cannot own a
// directory SYSTEM and Administrators would trust.
func protectRuntimeDirs(dbPath string) error {
	if !isPrivileged() {
		return nil
	}
	plan, err := installPlan()
	if err != nil {
		return err
	}
	for _, dir := range plan.Dirs {
		if err := ensureProtectedDir(dir.Path, dir.SDDL); err != nil {
			return fmt.Errorf("the helper's folder is not safe to use: %w", err)
		}
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		path := dbPath + suffix
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := platform.CheckFileSecurity(path); err != nil {
			return err
		}
	}
	return nil
}
