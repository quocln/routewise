package main

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/quocln/routewise/internal/ipc"
)

// The Windows service install, reduced to data: what is registered, where the
// executable goes, which directories are created with which access list. The
// Win32 calls that carry it out are in service_install_windows.go; this file
// has none so the plan can be checked on any OS.

const (
	helperServiceName        = ipc.ServiceName
	helperServiceDisplayName = "RouteWise Helper"
	helperServiceDescription = "Routes listed domains and addresses through the chosen VPN (RouteWise helper)."
	installedExeName         = "routewise.exe"
	installedDirName         = "RouteWise"
)

// SDDL access lists for the helper's directories. Both are protected (nothing
// is inherited from ProgramData, whose default lets any user create files) and
// give SYSTEM and Administrators full control that flows to children.
//
// 0x1200a9 is FILE_GENERIC_READ | FILE_GENERIC_EXECUTE: Users may list and read
// but not modify.
const (
	// dataDirSDDL is for the data directory, which holds the database and the
	// configuration, including built-in VPN credentials. Users get read and
	// traverse on the directory itself only, not on its contents, so the logs and
	// run directories can be reached while the database stays private.
	dataDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)"
	// sharedDirSDDL is for the logs and run directories, which Users may read
	// (the app opens the log folder; the pid file is not secret).
	sharedDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
)

// protectedDir is a directory the install creates, or tightens when it already
// exists, with the given SDDL.
type protectedDir struct {
	Path string
	SDDL string
}

type windowsInstallPlan struct {
	InstallDir string
	ExePath    string
	// Args are the service's command-line arguments after the executable.
	Args []string
	// Dirs are ordered parents first, so each is created inside one that
	// already carries the right access list.
	Dirs []protectedDir
}

// newWindowsInstallPlan lays out the install: the executable under programFiles
// (writable only by administrators by default), and the data, log and run
// directories under the paths the helper itself uses.
func newWindowsInstallPlan(programFiles, dataDir, logDir, runDir, configPath string) windowsInstallPlan {
	installDir := filepath.Join(programFiles, installedDirName)
	return windowsInstallPlan{
		InstallDir: installDir,
		ExePath:    filepath.Join(installDir, installedExeName),
		Args:       []string{"start", "--foreground", "--config", configPath},
		Dirs: []protectedDir{
			{dataDir, dataDirSDDL},
			{logDir, sharedDirSDDL},
			{runDir, sharedDirSDDL},
		},
	}
}

// helperServiceDependencies are the services that must be running before the
// helper starts: the network store interface (routes) and the DNS client (the
// split-DNS rules it reloads).
var helperServiceDependencies = []string{"Nsi", "Dnscache"}

// withDependencies returns have with every service in need added, keeping the
// ones an administrator put there.
func withDependencies(have, need []string) []string {
	out := slices.Clone(have)
	for _, n := range need {
		if !slices.ContainsFunc(out, func(h string) bool { return strings.EqualFold(h, n) }) {
			out = append(out, n)
		}
	}
	return out
}
