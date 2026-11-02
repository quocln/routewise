//go:build darwin

package platform

// Where the helper keeps its files on macOS. The configuration database sits
// beside config.yaml, so the data directory is the config directory.
const (
	configDir     = "/Library/Application Support/RouteWise"
	dataDir       = configDir
	logDir        = "/var/log"
	logFileName   = "routewise.log"
	runDir        = "/var/run"
	rootGroupName = "root:wheel"
)

// logRoots are the directories the helper's log file may live under.
var logRoots = []string{"/var/log", "/tmp"}
