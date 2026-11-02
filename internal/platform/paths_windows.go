//go:build windows

package platform

import (
	"os"

	"golang.org/x/sys/windows"
)

// Where the helper keeps its files on Windows (see windowsLayout). The values
// are computed once because the ProgramData location comes from the system, not
// from a constant.
var (
	layout = windowsLayout(resolveProgramData(
		func() (string, error) {
			return windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
		},
		os.Getenv,
	))

	configDir = layout.root
	dataDir   = layout.root
	logDir    = layout.logDir
	runDir    = layout.runDir
	logRoots  = layout.logRoots
)

const (
	logFileName = "routewise.log"
	// rootGroupName is the group that owns the helper's files; it only appears
	// in hints on Unix.
	rootGroupName = "Administrators"
)
