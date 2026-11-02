package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/testenv"
)

// fakeHelper answers JSON-RPC requests on a temporary Unix socket and records
// each request, so command tests see exactly what the CLI sent.
type fakeHelper struct {
	mu       sync.Mutex
	requests []api.Request
}

// startFakeHelper points the CLI at a fake helper whose handler returns the
// result (or the JSON-RPC error) for each request.
func startFakeHelper(t *testing.T, handler func(api.Request) (result interface{}, rpcErr *api.Error)) *fakeHelper {
	t.Helper()
	l, sock := testenv.ListenLocal(t)

	f := &fakeHelper{}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req api.Request
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				f.mu.Lock()
				f.requests = append(f.requests, req)
				f.mu.Unlock()
				result, rpcErr := handler(req)
				_ = json.NewEncoder(conn).Encode(&api.Response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rpcErr})
			}()
		}
	}()

	old := helperSocketPath
	helperSocketPath = sock
	t.Cleanup(func() { helperSocketPath = old })
	return f
}

func (f *fakeHelper) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var m []string
	for _, r := range f.requests {
		m = append(m, r.Method)
	}
	return m
}

// noHelper points the CLI at a socket nothing listens on.
func noHelper(t *testing.T) {
	t.Helper()
	old := helperSocketPath
	helperSocketPath = filepath.Join(t.TempDir(), "absent.sock")
	t.Cleanup(func() { helperSocketPath = old })
}

// isolatedConfig gives the CLI a config location whose PID file is private to
// the test, so a helper running on the developer's machine is never consulted.
func isolatedConfig(t *testing.T) (pidFile string) {
	t.Helper()
	useConfigDir(t)
	pidFile = filepath.Join(t.TempDir(), "routewise.pid")
	cfg := config.DefaultConfig()
	cfg.Daemon.PidFile = pidFile
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	return pidFile
}

// captureStdout returns what fn prints to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	return <-done
}

func TestRequireHelperReportsAMissingHelper(t *testing.T) {
	noHelper(t)
	if err := requireHelper(context.Background(), "status.get", nil, nil); !errors.Is(err, errHelperNotRunning) {
		t.Fatalf("error = %v, want %v", err, errHelperNotRunning)
	}
}

func TestRequireHelperPassesTheHelpersOwnError(t *testing.T) {
	startFakeHelper(t, func(api.Request) (interface{}, *api.Error) {
		return nil, &api.Error{Code: api.ErrCodeUnauthorized, Message: "not authorized"}
	})
	err := requireHelper(context.Background(), "domains.add", nil, nil)
	var rpcErr *api.RPCError
	if !errors.As(err, &rpcErr) || err.Error() != "not authorized" {
		t.Fatalf("error = %v, want the helper's typed error with its text", err)
	}
}

func TestCommandsUseOneConnectionPerCall(t *testing.T) {
	var conns int
	var mu sync.Mutex
	l, sock := testenv.ListenLocal(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns++
			mu.Unlock()
			go func() {
				defer c.Close()
				var req api.Request
				if json.NewDecoder(c).Decode(&req) == nil {
					_ = json.NewEncoder(c).Encode(&api.Response{JSONRPC: "2.0", ID: req.ID, Result: []api.Domain{{Pattern: "a.example.com"}}})
				}
			}()
		}
	}()
	old := helperSocketPath
	helperSocketPath = sock
	t.Cleanup(func() { helperSocketPath = old })

	if _, err := configuredDomains(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if conns != 1 {
		t.Errorf("connections = %d, want exactly one (no separate availability probe)", conns)
	}
}

func TestRPCOrDirect(t *testing.T) {
	t.Run("through a running helper", func(t *testing.T) {
		isolatedConfig(t)
		h := startFakeHelper(t, func(api.Request) (interface{}, *api.Error) { return api.SuccessResult{Success: true}, nil })
		via, err := rpcOrDirect(context.Background(), "domains.add", api.AddDomainParams{Pattern: "a.example.com"}, nil)
		if !via || err != nil {
			t.Fatalf("via=%v err=%v, want the helper to take the change", via, err)
		}
		if got := h.methods(); len(got) != 1 || got[0] != "domains.add" {
			t.Errorf("requests = %v", got)
		}
	})
	t.Run("helper error is returned, not retried directly", func(t *testing.T) {
		isolatedConfig(t)
		startFakeHelper(t, func(api.Request) (interface{}, *api.Error) {
			return nil, &api.Error{Code: -32602, Message: "invalid pattern"}
		})
		via, err := rpcOrDirect(context.Background(), "domains.add", nil, nil)
		if !via || err == nil || err.Error() != "invalid pattern" {
			t.Fatalf("via=%v err=%v", via, err)
		}
	})
	t.Run("no helper edits directly", func(t *testing.T) {
		isolatedConfig(t)
		noHelper(t)
		via, err := rpcOrDirect(context.Background(), "domains.add", nil, nil)
		if via || err != nil {
			t.Fatalf("via=%v err=%v, want a direct edit", via, err)
		}
	})
	t.Run("live process with a dead socket refuses a direct edit", func(t *testing.T) {
		pidFile := isolatedConfig(t)
		noHelper(t)
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			t.Fatal(err)
		}
		via, err := rpcOrDirect(context.Background(), "domains.add", nil, nil)
		if via || err == nil || !strings.Contains(err.Error(), "socket is not answering") {
			t.Fatalf("via=%v err=%v, want errHelperUnreachable", via, err)
		}
	})
}

func TestDomainCommandsThroughTheHelper(t *testing.T) {
	isolatedConfig(t)
	h := startFakeHelper(t, func(r api.Request) (interface{}, *api.Error) {
		if r.Method == "domains.list" {
			return []api.Domain{{Pattern: "a.example.com"}, {Pattern: "*.b.example.com"}}, nil
		}
		return api.SuccessResult{Success: true}, nil
	})
	out := captureStdout(t, func() {
		if err := runAddDomain(addDomainCmd, []string{"New.Example.com"}); err != nil {
			t.Error(err)
		}
		if err := runRemoveDomain(removeDomainCmd, []string{"old.example.com"}); err != nil {
			t.Error(err)
		}
		if err := runListDomains(listDomainsCmd, nil); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{"Added domain pattern:", "Removed domain pattern: old.example.com",
		"Configured domain patterns (2):", "  a.example.com", "  *.b.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if got := strings.Join(h.methods(), ","); got != "domains.add,domains.remove,domains.list" {
		t.Errorf("methods = %s", got)
	}
}

func TestDomainCommandsEditTheStoredConfigWithoutAHelper(t *testing.T) {
	isolatedConfig(t)
	noHelper(t)
	out := captureStdout(t, func() {
		for _, step := range []func() error{
			func() error { return runAddDomain(addDomainCmd, []string{"direct.example.com"}) },
			func() error { return runAddDomain(addDomainCmd, []string{"direct.example.com"}) },
			func() error { return runListDomains(listDomainsCmd, nil) },
			func() error { return runRemoveDomain(removeDomainCmd, []string{"direct.example.com"}) },
			func() error { return runRemoveDomain(removeDomainCmd, []string{"direct.example.com"}) },
			func() error { return runListDomains(listDomainsCmd, nil) },
		} {
			if err := step(); err != nil {
				t.Error(err)
			}
		}
	})
	for _, want := range []string{"Added domain pattern: direct.example.com", "Pattern already exists: direct.example.com",
		"Configured domain patterns (1):", "Removed domain pattern: direct.example.com",
		"Pattern not found: direct.example.com", "No domain patterns configured"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestAddDomainRejectsAnInvalidEntryBeforeAnyCall(t *testing.T) {
	h := startFakeHelper(t, func(api.Request) (interface{}, *api.Error) { return api.SuccessResult{}, nil })
	if err := runAddDomain(addDomainCmd, []string{"not a domain!"}); err == nil {
		t.Fatal("an invalid entry must be rejected")
	}
	if len(h.methods()) != 0 {
		t.Errorf("the helper was called for an invalid entry: %v", h.methods())
	}
}

func TestConfigExportAndImportThroughTheHelper(t *testing.T) {
	isolatedConfig(t)
	h := startFakeHelper(t, func(r api.Request) (interface{}, *api.Error) {
		if r.Method == "config.export" {
			return config.Export{Format: config.ExportFormat, Version: config.ExportVersion, Domains: []string{"x.example.com"}}, nil
		}
		return api.ImportConfigResult{RestartRequired: true}, nil
	})
	dir := t.TempDir()
	file := filepath.Join(dir, "export.json")
	if err := runConfigExport(configExportCmd, []string{file}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(data), "x.example.com") {
		t.Fatalf("export file = %q, %v", data, err)
	}
	if info, _ := os.Stat(file); !testenv.HasPerm(info, 0o600) {
		t.Errorf("export mode = %o, want 0600", info.Mode().Perm())
	}
	out := captureStdout(t, func() {
		if err := runConfigImport(configImportCmd, []string{file}); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "Imported 1 domain patterns and 0 VPN clients.") || !strings.Contains(out, "sudo routewise restart") {
		t.Errorf("import output = %q", out)
	}
	if got := strings.Join(h.methods(), ","); got != "config.export,config.import" {
		t.Errorf("methods = %s", got)
	}
}

func TestConfigImportWithoutAHelperSavesTheStoredConfig(t *testing.T) {
	isolatedConfig(t)
	noHelper(t)
	file := filepath.Join(t.TempDir(), "in.json")
	src := config.DefaultConfig()
	src.Domains = []config.DomainRule{{Pattern: "imported.example.com"}}
	data, err := json.Marshal(config.NewExport(src, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runConfigImport(configImportCmd, []string{file}); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "Start the helper to apply them.") {
		t.Errorf("output = %q", out)
	}
	cfg, err := loadConfig()
	if err != nil || len(cfg.Domains) != 1 || cfg.Domains[0].Pattern != "imported.example.com" {
		t.Fatalf("stored config = %+v, %v", cfg, err)
	}
	// Export now reads the same stored config.
	out = captureStdout(t, func() {
		if err := runConfigExport(configExportCmd, nil); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "imported.example.com") {
		t.Errorf("export = %q", out)
	}
}

func TestActivityNeedsAHelper(t *testing.T) {
	noHelper(t)
	for name, run := range map[string]func() error{
		"activity": func() error { return runActivity(activityCmd, nil) },
		"history":  func() error { return runHistory(historyCmd, nil) },
		"check":    func() error { return runCheck(checkCmd, []string{"example.com"}) },
		"profile":  func() error { return runProfileList(profileListCmd, nil) },
	} {
		if err := run(); err == nil || err.Error() != "the RouteWise helper is not running" {
			t.Errorf("%s: error = %v, want the shared helper-not-running text", name, err)
		}
	}
}

func TestActivityPrintsEventsWithVerdicts(t *testing.T) {
	at := time.Date(2026, 10, 28, 9, 5, 7, 0, time.Local)
	startFakeHelper(t, func(api.Request) (interface{}, *api.Error) {
		return api.ActivityResult{Latest: 2, Events: []activity.Event{{
			Time: at, Kind: "dns", Name: "a.example.com",
			Addresses: []activity.Address{{IP: "10.0.0.1", Verdict: activity.ViaVPN}, {IP: "1.1.1.1", Verdict: activity.Direct}},
		}}}, nil
	})
	old := activityFollow
	activityFollow = false
	t.Cleanup(func() { activityFollow = old })
	out := captureStdout(t, func() {
		if err := runActivity(activityCmd, nil); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "10.0.0.1=VPN") || !strings.Contains(out, "1.1.1.1=DIRECT") {
		t.Errorf("output = %q", out)
	}
}

func TestActivityFollowLongPollsFromTheLatestEvent(t *testing.T) {
	var mu sync.Mutex
	var seen []api.ActivityParams
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFakeHelper(t, func(r api.Request) (interface{}, *api.Error) {
		var p api.ActivityParams
		_ = json.Unmarshal(r.Params, &p)
		mu.Lock()
		seen = append(seen, p)
		n := len(seen)
		mu.Unlock()
		if n == 3 {
			cancel()
		}
		return api.ActivityResult{Latest: uint64(n * 10)}, nil
	})
	old := activityFollow
	activityFollow = true
	t.Cleanup(func() { activityFollow = old })
	cmd := *activityCmd
	cmd.SetContext(ctx)
	err := runActivity(&cmd, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want the follow loop to end with the cancelled context", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 3 || seen[0].WaitMs != 0 || seen[1].Since != 10 || seen[1].WaitMs != followWaitMs || seen[2].Since != 20 {
		t.Errorf("requests = %+v, want a plain first call then long polls continuing from latest", seen)
	}
}

func TestFollowLoopStopsOnErrorAndOnCancel(t *testing.T) {
	boom := errors.New("boom")
	n := 0
	if err := followLoop(context.Background(), func(context.Context) error {
		if n++; n == 3 {
			return boom
		}
		return nil
	}); !errors.Is(err, boom) || n != 3 {
		t.Errorf("err = %v after %d steps", err, n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := followLoop(ctx, func(context.Context) error { t.Error("step ran after cancel"); return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestVerdictLabel(t *testing.T) {
	if verdictLabel(true) != "VPN" || verdictLabel(false) != "DIRECT" {
		t.Error("verdict labels changed")
	}
}

func TestCheckPrintsVerdicts(t *testing.T) {
	startFakeHelper(t, func(api.Request) (interface{}, *api.Error) {
		return api.HostCheck{Host: "h.example.com", MatchedPatterns: []string{"*.example.com"}, VPNInterface: "utun4",
			Addresses: []api.HostAddress{{IP: "10.0.0.1", Verdict: "vpn", Interface: "utun4"}, {IP: "1.1.1.1", Verdict: "direct", Interface: "en0", Gateway: "192.168.1.1"}}}, nil
	})
	out := captureStdout(t, func() {
		if err := runCheck(checkCmd, []string{"h.example.com"}); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{"Host:    h.example.com", "Matches: *.example.com", "VPN     10.0.0.1", "DIRECT  1.1.1.1", "via en0 (192.168.1.1)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestStatusReportsHelperStateOrUnknown(t *testing.T) {
	isolatedConfig(t)
	startFakeHelper(t, func(r api.Request) (interface{}, *api.Error) {
		if r.Method == "status.get" {
			return api.StatusResult{VPNConnected: true, VPNInterface: "utun4", RouteCount: 3}, nil
		}
		return []api.Domain{{Pattern: "a.example.com"}}, nil
	})
	out := captureStdout(t, func() {
		if err := runStatus(statusCmd, nil); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{"Daemon:  stopped", "VPN:     connected (utun4)", "Routes:  3 managed", "Domains: 1 patterns configured"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	noHelper(t)
	out = captureStdout(t, func() { _ = runStatus(statusCmd, nil) })
	if !strings.Contains(out, "VPN:     unknown (start the helper to see live status)") {
		t.Errorf("output = %q", out)
	}
}

// A per-VPN list is not in the Any VPN list the CLI reads, so the count has to
// come from the helper: reading 0 here is what hid four routed patterns.
func TestStatusCountsEveryDomainListTheHelperReports(t *testing.T) {
	isolatedConfig(t)
	startFakeHelper(t, func(r api.Request) (interface{}, *api.Error) {
		if r.Method == "status.get" {
			return api.StatusResult{DomainCount: 4}, nil
		}
		return []api.Domain{}, nil
	})
	out := captureStdout(t, func() {
		if err := runStatus(statusCmd, nil); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "Domains: 4 patterns configured") {
		t.Errorf("output = %q", out)
	}
}

func TestStatusSaysWhereOtherTrafficGoes(t *testing.T) {
	tests := []struct {
		name   string
		status *api.DefaultVPNStatus
		want   []string
	}{
		{"primary", &api.DefaultVPNStatus{State: api.DefaultVPNPrimary, ActiveClient: "SG", ActiveInterface: "utun7"}, []string{"other traffic goes through SG (utun7)"}},
		{"fallback", &api.DefaultVPNStatus{State: api.DefaultVPNFallback, ActiveClient: "Work", ActiveInterface: "utun6"}, []string{"goes through fallback Work (utun6)"}},
		{"direct", &api.DefaultVPNStatus{State: api.DefaultVPNDirect, Problem: "Work cannot be the default VPN"}, []string{"other traffic goes direct", "Work cannot be the default VPN"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureStdout(t, func() { printDefaultVPN(tt.status) })
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("output = %q, want %q", out, want)
				}
			}
		})
	}
	if out := captureStdout(t, func() { printDefaultVPN(nil) }); out != "" {
		t.Errorf("output with no default VPN = %q", out)
	}
}

func TestProfileActionResolvesThenActs(t *testing.T) {
	h := startFakeHelper(t, func(r api.Request) (interface{}, *api.Error) {
		if r.Method == "profiles.list" {
			return []api.ProfileInfo{{ID: "ab12", Name: "Office", Kind: "wireguard"}}, nil
		}
		return api.SuccessResult{Success: true}, nil
	})
	out := captureStdout(t, func() {
		if err := runProfileAction("profiles.connect", "Connected", "office"); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "Connected Office (ab12)") {
		t.Errorf("output = %q", out)
	}
	if got := strings.Join(h.methods(), ","); got != "profiles.list,profiles.connect" {
		t.Errorf("methods = %s", got)
	}
}

// The child of the stop tests: a process whose command name contains
// "routewise" (the test binary is routewise.test) that waits for SIGTERM.
func TestMain(m *testing.M) {
	if os.Getenv("ROUTEWISE_TEST_SLEEP_CHILD") == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func startChild(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "ROUTEWISE_TEST_SLEEP_CHILD=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

// startUnrelatedChild starts a long-running process whose name is not routewise.
func startUnrelatedChild(t *testing.T) *exec.Cmd {
	t.Helper()
	if runtime.GOOS == "windows" {
		return startChild(t, "ping", "-n", "60", "127.0.0.1")
	}
	return startChild(t, "/bin/sleep", "60")
}

func TestStopDaemon(t *testing.T) {
	t.Run("no pid file", func(t *testing.T) {
		out, _, err := stopDaemon(filepath.Join(t.TempDir(), "none.pid"))
		if out != daemonNotRunning || err != nil {
			t.Fatalf("outcome=%v err=%v", out, err)
		}
	})
	t.Run("a pid that is not routewise is removed, never signalled", func(t *testing.T) {
		other := startUnrelatedChild(t)
		pidFile := filepath.Join(t.TempDir(), "r.pid")
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(other.Process.Pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		out, _, err := stopDaemon(pidFile)
		if out != daemonStalePID || err != nil {
			t.Fatalf("outcome=%v err=%v", out, err)
		}
		if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
			t.Error("the stale PID file must be removed")
		}
		// Windows has no signal 0 to probe with; its stop path only ever kills
		// what passed the name check above.
		if runtime.GOOS != "windows" {
			if err := other.Process.Signal(syscall.Signal(0)); err != nil {
				t.Errorf("the unrelated process was signalled: %v", err)
			}
		}
	})
	t.Run("a routewise process gets SIGTERM and is waited for", func(t *testing.T) {
		old := stopPollInterval
		stopPollInterval = 20 * time.Millisecond
		t.Cleanup(func() { stopPollInterval = old })

		child := startChild(t, os.Args[0], "-test.run=NONE")
		exited := make(chan struct{})
		go func() { _ = child.Wait(); close(exited) }()
		pidFile := filepath.Join(t.TempDir(), "r.pid")
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		out, pid, err := stopDaemon(pidFile)
		if out != daemonSignalled || pid != child.Process.Pid || err != nil {
			t.Fatalf("outcome=%v pid=%d err=%v", out, pid, err)
		}
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Fatal("the daemon did not exit after SIGTERM")
		}
		if !waitForDaemonExit(pidFile, 10) {
			t.Error("waitForDaemonExit must see the daemon gone")
		}
	})
}

func TestManualRestartKeepsTheConfigFlag(t *testing.T) {
	old := cfgFile
	t.Cleanup(func() { cfgFile = old })
	cfgFile = ""
	if got := strings.Join(manualStartArgs(), " "); got != "start" {
		t.Errorf("args = %q", got)
	}
	cfgFile = "/tmp/custom/config.yaml"
	if got := strings.Join(manualStartArgs(), " "); got != "start --config /tmp/custom/config.yaml" {
		t.Errorf("args = %q", got)
	}
}
