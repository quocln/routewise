//go:build !darwin && !linux && !windows

package platform

// No layout is defined for this OS yet. The values keep the macOS shape so the
// shared code still builds; the helper does not run here.
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
