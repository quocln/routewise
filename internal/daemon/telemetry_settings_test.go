package daemon

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/telemetry"
)

const telemetryTestDSN = "https://secretkey123@rustrak.example.test/9"

func newTelemetryDaemon(t *testing.T) (*Daemon, *syncBuffer) {
	t.Helper()
	d, err := New(newTestDaemonConfig(t.TempDir()), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(telemetry.Close)
	var logs syncBuffer
	d.logger = slog.New(slog.NewTextHandler(&logs, nil))
	return d, &logs
}

func TestSetTelemetryIsPartialValidatedAndNeverLogsTheDSN(t *testing.T) {
	d, logs := newTelemetryDaemon(t)
	dsn := telemetryTestDSN
	on := true
	if err := d.SetTelemetry(api.SetTelemetryParams{DSN: &dsn, Errors: &on, Logs: &on}); err != nil {
		t.Fatal(err)
	}
	off := false
	if err := d.SetTelemetry(api.SetTelemetryParams{Logs: &off}); err != nil {
		t.Fatal(err)
	}
	got := d.Telemetry()
	if got.DSN != dsn || got.Logs || !got.Errors || got.TracesSampleRate != config.DefaultTracesSampleRate {
		t.Errorf("telemetry = %+v", got)
	}

	bad := "ftp://nope"
	rate := 2.0
	for _, p := range []api.SetTelemetryParams{{DSN: &bad}, {TracesSampleRate: &rate}} {
		err := d.SetTelemetry(p)
		if err == nil || !errorsIsRejected(err) {
			t.Errorf("SetTelemetry(%+v) = %v, want a rejection", p, err)
		}
	}
	if d.Telemetry().DSN != dsn {
		t.Error("a rejected change altered the stored DSN")
	}
	if strings.Contains(logs.String(), "secretkey123") || strings.Contains(logs.String(), "rustrak") {
		t.Errorf("log holds the DSN: %s", logs.String())
	}
}

func errorsIsRejected(err error) bool { return strings.Contains(err.Error(), api.ErrRejected.Error()) }

func TestSetTelemetryCommitTurnsReportingOnAndOff(t *testing.T) {
	d, _ := newTelemetryDaemon(t)
	dsn := telemetryTestDSN
	on := true
	if err := d.SetTelemetry(api.SetTelemetryParams{DSN: &dsn, Errors: &on}); err != nil {
		t.Fatal(err)
	}
	if !telemetry.Default.Active() {
		t.Error("a DSN with kinds on must start reporting")
	}
	empty := ""
	if err := d.SetTelemetry(api.SetTelemetryParams{DSN: &empty}); err != nil {
		t.Fatal(err)
	}
	if telemetry.Default.Active() {
		t.Error("clearing the DSN must stop reporting")
	}
}

func TestExportOmitsTheDSNAndImportKeepsIt(t *testing.T) {
	d, _ := newTelemetryDaemon(t)
	dsn := telemetryTestDSN
	if err := d.SetTelemetry(api.SetTelemetryParams{DSN: &dsn}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(d.ExportConfig())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secretkey123") || strings.Contains(strings.ToLower(string(raw)), "dsn") {
		t.Errorf("export carries the DSN: %s", raw)
	}
	if _, err := d.ImportConfig(d.ExportConfig()); err != nil {
		t.Fatal(err)
	}
	if d.Telemetry().DSN != dsn {
		t.Error("an import without a DSN cleared the stored one")
	}
}

func TestSettingsGetDoesNotExposeTheDSN(t *testing.T) {
	d, _ := newTelemetryDaemon(t)
	dsn := telemetryTestDSN
	if err := d.SetTelemetry(api.SetTelemetryParams{DSN: &dsn}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(d.Settings())
	if strings.Contains(string(raw), "secretkey123") {
		t.Errorf("settings: %s", raw)
	}
}

// The audit line names the method and the peer, never the request body.
func TestAuditLineForTelemetrySetHasNoDSN(t *testing.T) {
	var logs syncBuffer
	server := &SocketServer{logger: slog.New(slog.NewTextHandler(&logs, nil))}
	req := &api.Request{
		JSONRPC: "2.0", Method: api.MethodTelemetrySet, ID: 1,
		Params: json.RawMessage(`{"dsn":"` + telemetryTestDSN + `"}`),
	}
	for _, denied := range []bool{false, true} {
		resp := &api.Response{JSONRPC: "2.0"}
		if denied {
			resp.Error = &api.Error{Code: api.ErrCodeUnauthorized, Message: "denied"}
		}
		server.auditMutation(req, resp, api.Peer{UID: 501, Verified: true})
	}
	out := logs.String()
	if !strings.Contains(out, "telemetry.set") || strings.Contains(out, "secretkey123") || strings.Contains(out, "rustrak") {
		t.Errorf("audit output: %s", out)
	}
}
