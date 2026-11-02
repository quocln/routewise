//go:build linux

package platform

// Where the helper keeps its files on Linux, following the FHS: settings under
// /etc, the database under /var/lib, logs under /var/log and the socket and pid
// file in /run.
const (
	configDir     = "/etc/routewise"
	dataDir       = "/var/lib/routewise"
	logDir        = "/var/log/routewise"
	logFileName   = "routewise.log"
	runDir        = "/run"
	rootGroupName = "root:root"
)

// logRoots are the directories the helper's log file may live under.
var logRoots = []string{"/var/log", "/tmp"}
