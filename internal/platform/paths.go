package platform

import (
	"path/filepath"
	"strings"
)

// ConfigDir is the directory holding the helper's configuration.
func ConfigDir() string { return configDir }

// ConfigFile is the default config.yaml location.
func ConfigFile() string { return filepath.Join(configDir, "config.yaml") }

// DataDir is the directory holding routewise.db.
func DataDir() string { return dataDir }

// LogDir is the directory the helper's log file is created in.
func LogDir() string { return logDir }

// LogFile is the default log file path.
func LogFile() string { return filepath.Join(logDir, logFileName) }

// RunDir is the directory for runtime state: the pid file (and the socket where
// the transport is a file).
func RunDir() string { return runDir }

// PidFile is the default pid file path.
func PidFile() string { return filepath.Join(runDir, "routewise.pid") }

// LogRoots lists the directories a configured log file must live under. The
// helper runs as root, so a log path anywhere else is refused.
func LogRoots() []string { return append([]string(nil), logRoots...) }

// RootOwner is the owner:group spelling that makes a file root-owned on this
// OS, for chown hints.
func RootOwner() string { return rootGroupName }

// LogPathAllowed reports whether dir is one of the log roots or inside one. The
// match is on whole path elements ("/var/logs" is not under "/var/log") and
// ignores case on Windows, whose file system does.
func LogPathAllowed(dir string) bool {
	for _, root := range logRoots {
		if withinRoot(dir, root, filepath.Separator == '\\') {
			return true
		}
	}
	return false
}

// withinRoot reports whether dir equals root or is below it. fold selects
// Windows rules: '/' and '\' both separate elements and case is ignored.
func withinRoot(dir, root string, fold bool) bool {
	if fold {
		dir = strings.ToLower(strings.ReplaceAll(dir, "/", `\`))
		root = strings.ToLower(strings.ReplaceAll(root, "/", `\`))
		root = strings.TrimRight(root, `\`)
		return dir == root || strings.HasPrefix(dir, root+`\`)
	}
	root = strings.TrimRight(root, "/")
	return dir == root || strings.HasPrefix(dir, root+"/")
}
