//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/quocln/routewise/internal/configdb"
	"github.com/quocln/routewise/internal/platform"
	"github.com/quocln/routewise/internal/telemetry"
)

// serviceLogName is the file in the log directory that receives what the
// helper prints (startup messages and errors) while it runs as a service,
// where there is no console to show them.
const serviceLogName = "service.log"

// stopWaitHint is how long the manager is told a stop may take: the daemon
// removes its routes and DNS rules before it exits.
const stopWaitHint = 30 * time.Second

// runSupervised runs the daemon under the service control manager when the
// process was started by it, and in the foreground (a console, or a scheduled
// task) otherwise.
func runSupervised(start helperStart) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect service mode: %w", err)
	}
	if !isService {
		return runForeground(start)
	}
	// The log directory is created (with its access list) before the log is
	// opened in it, so the service never makes it with ProgramData's defaults.
	protectErr := protectRuntimeDirs(configdb.PathFor(getConfigPath()))
	closeLog := redirectOutputToServiceLog()
	defer closeLog()
	if protectErr != nil {
		fmt.Fprintf(os.Stderr, "%s start failed: %v\n", time.Now().Format(time.RFC3339), protectErr)
		return protectErr
	}
	// Only the service manager's stop request ends the helper: the runtime turns
	// every user logoff into SIGTERM, which must not.
	daemonIgnoresTermSignals = true
	return svc.Run(helperServiceName, &serviceHandler{start: start})
}

// redirectOutputToServiceLog points stdout and stderr at the service log so
// the messages the daemon prints survive, as launchd and systemd capture them.
// It returns the function that closes the file; when the log cannot be opened
// the handles are left alone and the messages are lost. It does not create the
// log directory, which protectRuntimeDirs owns.
func redirectOutputToServiceLog() func() {
	path := filepath.Join(platform.LogDir(), serviceLogName)
	// The log is only appended to, so a long-lived install would grow it for
	// ever; keep the last run's worth beside the current one.
	if info, err := os.Stat(path); err == nil && info.Size() > maxServiceLogBytes {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return func() {}
	}
	fmt.Fprintf(f, "%s service starting\n", time.Now().Format(time.RFC3339))
	os.Stdout, os.Stderr = f, f
	// A fatal runtime error or unrecovered panic is written to the original
	// stderr handle, not the os.Stderr variable, so point it at the log too.
	_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	return func() { f.Close() }
}

// serviceHandler maps the service control manager's requests onto the daemon:
// Stop and Shutdown run the daemon's own graceful stop.
type serviceHandler struct {
	start helperStart
}

// startFailureExitCode is the service-specific exit code reported when the
// daemon fails to start; the reason is in the service log.
const startFailureExitCode = 1

// unexpectedExitCode is the service-specific exit code reported when the daemon
// ends without being asked to. A non-zero code is what makes the service
// manager count the exit as a failure and run its restart actions.
const unexpectedExitCode = 2

// maxServiceLogBytes is the size past which the next start moves the service
// log aside.
const maxServiceLogBytes = 10 << 20

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	// A panic here is on a goroutine the service library started, so it needs
	// its own capture before it crashes the process for the manager to restart.
	defer telemetry.RepanicAfterCapture()

	status <- svc.Status{State: svc.StartPending, WaitHint: uint32(stopWaitHint / time.Millisecond)}
	d, release, err := h.start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s start failed: %v\n", time.Now().Format(time.RFC3339), err)
		return true, startFailureExitCode
	}
	defer release()

	// Pre-shutdown gives the stop the manager's longer pre-shutdown allowance,
	// not the short budget a plain shutdown notice gets.
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown}

	// The daemon can also end on its own (its context is cancelled); the
	// service then stops, as a failure, instead of lingering with nothing
	// behind it.
	ended := make(chan struct{})
	go func() { d.Wait(); close(ended) }()

	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopWaitHint / time.Millisecond)}
				d.Stop()
				return false, 0
			}
		case <-ended:
			status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopWaitHint / time.Millisecond)}
			d.Stop()
			fmt.Fprintf(os.Stderr, "%s the daemon ended on its own; exiting with an error so the service restarts\n", time.Now().Format(time.RFC3339))
			return true, unexpectedExitCode
		}
	}
}
