package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/quocln/routewise/internal/testenv"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortSocketDir returns a short-lived scratch directory for a Unix socket.
// t.TempDir() embeds the full test name, which for a table of subtests
// routinely exceeds macOS's ~104 byte sun_path limit and fails bind with
// "invalid argument" - so this deliberately uses a short, test-name-free
// path instead.
func shortSocketDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "rwapi")
	if err != nil {
		t.Fatalf("create scratch dir for unix socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// startTestServer listens on a short-lived local endpoint and answers exactly
// one JSON-RPC request with the response the caller's handler builds from
// it. It exists so Client can be exercised against a real socket without
// touching the daemon's hardcoded production path.
func startTestServer(t *testing.T, handler func(Request) Response) string {
	t.Helper()

	listener, socketPath := testenv.ListenLocal(t)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var req Request
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		resp := handler(req)
		_ = json.NewEncoder(conn).Encode(&resp)
	}()

	return socketPath
}

func TestClient_AvailableIsFalseWithNoListener(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "does-not-exist.sock")
	c := NewClient(socketPath)

	if c.Available() {
		t.Error("Available must be false when nothing is listening")
	}
}

func TestClient_AvailableIsTrueWithAListener(t *testing.T) {
	listener, socketPath := testenv.ListenLocal(t)

	// Drain any connection Available's dial makes so it never blocks.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	c := NewClient(socketPath)
	if !c.Available() {
		t.Error("Available must be true once a helper is listening")
	}
}

func TestClient_CallDecodesTheResultIntoOut(t *testing.T) {
	socketPath := startTestServer(t, func(req Request) Response {
		if req.JSONRPC != "2.0" {
			t.Errorf("request jsonrpc = %q, want 2.0", req.JSONRPC)
		}
		if req.Method != "status.get" {
			t.Errorf("request method = %q, want status.get", req.Method)
		}
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  StatusResult{Running: true, VPNInterface: "utun4", RouteCount: 3},
		}
	})

	c := NewClient(socketPath)
	var out StatusResult
	if err := c.Call("status.get", nil, &out); err != nil {
		t.Fatalf("Call failed: %v", err)
	}
	if !out.Running || out.VPNInterface != "utun4" || out.RouteCount != 3 {
		t.Errorf("decoded result = %+v, want Running=true VPNInterface=utun4 RouteCount=3", out)
	}
}

func TestClient_CallEncodesParams(t *testing.T) {
	var gotParams AddDomainParams
	socketPath := startTestServer(t, func(req Request) Response {
		if err := json.Unmarshal(req.Params, &gotParams); err != nil {
			t.Errorf("server could not decode params: %v", err)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: SuccessResult{Success: true}}
	})

	c := NewClient(socketPath)
	var out SuccessResult
	err := c.Call("domains.add", AddDomainParams{Pattern: "*.example.com"}, &out)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}
	if gotParams.Pattern != "*.example.com" {
		t.Errorf("server observed pattern %q, want *.example.com", gotParams.Pattern)
	}
	if !out.Success {
		t.Error("decoded result should report success")
	}
}

// TestClient_CallSurfacesAJSONRPCErrorAsAGoError proves a helper-reported
// rejection (e.g. an unauthorized peer or an invalid pattern) reaches the
// caller as an error rather than silently decoding into a zero value.
func TestClient_CallSurfacesAJSONRPCErrorAsAGoError(t *testing.T) {
	socketPath := startTestServer(t, func(req Request) Response {
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &Error{Code: ErrCodeUnauthorized, Message: "not authorized to change routing"},
		}
	})

	c := NewClient(socketPath)
	err := c.Call("domains.add", AddDomainParams{Pattern: "example.com"}, nil)
	if err == nil {
		t.Fatal("expected the JSON-RPC error to surface as a Go error")
	}
	if err.Error() != "not authorized to change routing" {
		t.Errorf("error = %q, want the helper's message passed through", err.Error())
	}
}

// TestClient_CallWithNilOutIgnoresTheResult covers a fire-and-forget mutation
// call where the caller does not care about the result payload.
func TestClient_CallWithNilOutIgnoresTheResult(t *testing.T) {
	socketPath := startTestServer(t, func(req Request) Response {
		return Response{JSONRPC: "2.0", ID: req.ID, Result: SuccessResult{Success: true}}
	})

	c := NewClient(socketPath)
	if err := c.Call("domains.remove", RemoveDomainParams{Pattern: "example.com"}, nil); err != nil {
		t.Fatalf("Call with nil out should not fail decoding the result, got: %v", err)
	}
}

func TestClient_CallFailsWhenNoHelperIsListening(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "absent.sock")
	c := NewClient(socketPath)

	err := c.Call("status.get", nil, nil)
	if err == nil {
		t.Fatal("expected Call to fail connecting to an absent helper")
	}
}

// TestClient_CallTimesOutOnAServerThatNeverResponds proves the client does not
// hang forever against a helper that accepted the connection but stalled, since
// clientTimeout bounds the whole exchange via conn.SetDeadline.
func TestClient_CallTimesOutOnAServerThatNeverResponds(t *testing.T) {
	listener, socketPath := testenv.ListenLocal(t)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Deliberately never write a response; hold the connection open past
		// what a caller should ever wait.
		<-time.After(30 * time.Second)
		conn.Close()
	}()

	c := NewClient(socketPath)
	start := time.Now()
	err := c.Call("status.get", nil, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Call to fail against a server that never responds")
	}
	if elapsed > 15*time.Second {
		t.Errorf("Call took %s, want it bounded well under the 30s stall", elapsed)
	}
}

// startSlowServer answers one request after delay.
func startSlowServer(t *testing.T, delay time.Duration) string {
	t.Helper()
	listener, socketPath := testenv.ListenLocal(t)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req Request
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		time.Sleep(delay)
		_ = json.NewEncoder(conn).Encode(&Response{JSONRPC: "2.0", ID: req.ID, Result: SuccessResult{Success: true}})
	}()
	return socketPath
}

// TestClient_LongPollDeadlineCoversTheRequestedWait proves a request that asks
// the helper to hold it (waitMs) is not cut off by the base timeout, while the
// same delay without a wait is.
func TestClient_LongPollDeadlineCoversTheRequestedWait(t *testing.T) {
	c := NewClient(startSlowServer(t, 400*time.Millisecond))
	c.timeout = 150 * time.Millisecond
	var out SuccessResult
	if err := c.Call("activity.list", ActivityParams{WaitMs: 500}, &out); err != nil {
		t.Fatalf("a long poll within its wait must succeed: %v", err)
	}
	if !out.Success {
		t.Error("result not decoded")
	}

	c = NewClient(startSlowServer(t, 400*time.Millisecond))
	c.timeout = 150 * time.Millisecond
	if err := c.Call("activity.list", ActivityParams{}, &out); err == nil {
		t.Fatal("a slow answer with no requested wait must time out")
	}
}

func TestClient_CallContextStopsWhenCancelled(t *testing.T) {
	c := NewClient(startSlowServer(t, 5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.CallContext(ctx, "activity.list", ActivityParams{WaitMs: 60000}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want the context deadline", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("cancellation took %s", time.Since(start))
	}

	c = NewClient(startSlowServer(t, 5*time.Second))
	ctx, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel2)
	if err := c.CallContext(ctx, "activity.list", nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestClient_RPCErrorIsTyped(t *testing.T) {
	socketPath := startTestServer(t, func(req Request) Response {
		return Response{JSONRPC: "2.0", ID: req.ID, Error: &Error{Code: ErrCodeUnauthorized, Message: "nope"}}
	})
	err := NewClient(socketPath).Call("domains.add", nil, nil)
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("error %T is not an *RPCError", err)
	}
	if rpcErr.Code != ErrCodeUnauthorized || rpcErr.Message != "nope" || err.Error() != "nope" {
		t.Errorf("RPCError = %+v, Error() = %q", rpcErr, err.Error())
	}
	if IsUnavailable(err) {
		t.Error("a helper's own error is not an unavailable helper")
	}
}

func TestClient_AbsentHelperIsUnavailable(t *testing.T) {
	err := NewClient(filepath.Join(shortSocketDir(t), "absent.sock")).Call("status.get", nil, nil)
	if !IsUnavailable(err) {
		t.Fatalf("error %v must report an unavailable helper", err)
	}
	if got := err.Error(); len(got) < 19 || got[:19] != "connect to helper: " {
		t.Errorf("error text = %q, want the connect prefix kept", got)
	}
}

func TestClient_PrefsGet(t *testing.T) {
	var gotMethod string
	socketPath := startTestServer(t, func(req Request) Response {
		gotMethod = req.Method
		return Response{JSONRPC: "2.0", ID: req.ID, Result: PrefsResult{Prefs: map[string]json.RawMessage{"keepOnTop": json.RawMessage(`true`)}}}
	})
	prefs, err := NewClient(socketPath).Prefs()
	if err != nil || gotMethod != MethodPrefsGet || string(prefs["keepOnTop"]) != "true" {
		t.Fatalf("Prefs = %v, %v (method %s)", prefs, err, gotMethod)
	}
}

func TestClient_SetPrefSendsTheKeyAndTheJSONValue(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  string
	}{{map[string]int{"at": 7}, `{"at":7}`}, {true, `true`}, {nil, `null`}} {
		var gotMethod string
		var gotSet PrefsSetParams
		socketPath := startTestServer(t, func(req Request) Response {
			gotMethod = req.Method
			if err := json.Unmarshal(req.Params, &gotSet); err != nil {
				t.Errorf("server could not decode params: %v", err)
			}
			return Response{JSONRPC: "2.0", ID: req.ID, Result: SuccessResult{Success: true}}
		})
		if err := NewClient(socketPath).SetPref("lastUpdateCheck", tc.value); err != nil {
			t.Fatal(err)
		}
		if gotMethod != MethodPrefsSet || gotSet.Key != "lastUpdateCheck" || string(gotSet.Value) != tc.want {
			t.Errorf("server saw %s %+v, want value %s", gotMethod, gotSet, tc.want)
		}
	}
}
