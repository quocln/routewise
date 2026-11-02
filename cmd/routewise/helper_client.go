package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/daemon"
)

// helperSocketPath is where the helper listens. It is a variable so tests can
// point the commands at a fake helper.
var helperSocketPath = daemon.SocketPath

// errHelperNotRunning is what a command that needs the helper reports when
// nothing is listening on its socket.
var errHelperNotRunning = errors.New("the RouteWise helper is not running")

// commandContext returns the command's context, which cobra leaves nil when a
// command is run without one.
func commandContext(cmd *cobra.Command) context.Context {
	if cmd != nil && cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}

// callHelper makes one request over a single connection. running is false only
// when nothing could be reached, so the caller can tell "no helper" apart from
// a helper that answered with an error. There is no separate probe: the
// connection attempt is the probe.
func callHelper(ctx context.Context, method string, params, out interface{}) (running bool, err error) {
	err = api.NewClient(helperSocketPath).CallContext(ctx, method, params, out)
	if api.IsUnavailable(err) {
		return false, nil
	}
	return true, err
}

// requireHelper is callHelper for commands that cannot work without a helper.
func requireHelper(ctx context.Context, method string, params, out interface{}) error {
	running, err := callHelper(ctx, method, params, out)
	if !running {
		return errHelperNotRunning
	}
	return err
}

// errHelperUnreachable explains why the CLI will not fall back to editing the
// config file itself. A running helper is the config's single writer and holds
// its own in-memory copy, so a direct edit would be silently overwritten by the
// helper's next write.
func errHelperUnreachable() error {
	return fmt.Errorf("the helper is running but its socket is not answering; " +
		"editing the config directly would be overwritten — restart it with `sudo routewise restart`")
}

// helperOwnsConfig reports that a helper process is alive, whether or not its
// socket is currently answering.
func helperOwnsConfig() bool {
	cfg, err := loadConfig()
	if err != nil {
		cfg = config.DefaultConfig()
	}
	_, running := daemon.CheckPIDFile(cfg.Daemon.PidFile)
	return running
}

// rpcOrDirect sends a config change through the helper when one is listening,
// so the process that owns the config file makes the change. viaHelper reports
// that it did, and err is then the helper's answer. When nothing is listening
// the CLI is the only writer and the caller edits the stored config itself
// (viaHelper false, err nil) - unless a helper process is alive with a dead
// socket, which is an error because its next write would undo a direct edit.
func rpcOrDirect(ctx context.Context, method string, params, out interface{}) (viaHelper bool, err error) {
	running, err := callHelper(ctx, method, params, out)
	if running {
		return true, err
	}
	if helperOwnsConfig() {
		return false, errHelperUnreachable()
	}
	return false, nil
}
