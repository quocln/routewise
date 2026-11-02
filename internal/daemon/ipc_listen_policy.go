package daemon

import "runtime"

// ipcListenFailureIsFatal is true where the IPC endpoint's name is shared by
// every user and creatable by any of them: a Windows named pipe another process
// already holds. A Unix socket lives in a root-owned directory, so its bind
// failing is a fault of this machine, and the helper keeps routing for the CLI.
var ipcListenFailureIsFatal = runtime.GOOS == "windows"
