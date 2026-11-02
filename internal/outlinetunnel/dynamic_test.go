package outlinetunnel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ssconfURL turns the TLS test server URL into the ssconf:// form.
func ssconfURL(srv *httptest.Server, path string) string {
	return "ssconf://" + strings.TrimPrefix(srv.URL, "https://") + path
}

func TestFetchDynamicKeyJSON(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/conf/abc" || r.URL.Fragment != "" {
			t.Errorf("unexpected request URL %v", r.URL)
		}
		_, _ = w.Write([]byte(`{"server":"203.0.113.9","server_port":"8388","password":"pw1","method":"chacha20-ietf-poly1305","prefix":"POST "}`))
	}))
	defer srv.Close()

	k, err := FetchDynamicKey(context.Background(), srv.Client(), ssconfURL(srv, "/conf/abc#name"))
	if err != nil {
		t.Fatal(err)
	}
	if k.Host != "203.0.113.9" || k.Port != 8388 || k.Password != "pw1" || k.Method != CipherChaCha20 || string(k.Prefix) != "POST " {
		t.Fatalf("got %+v", k)
	}
}

func TestFetchDynamicKeySSBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("\nss://" + b64url("aes-128-gcm:pw2") + "@h.test:443/?prefix=%16#x\nignored\n"))
	}))
	defer srv.Close()

	k, err := FetchDynamicKey(context.Background(), srv.Client(), ssconfURL(srv, "/k"))
	if err != nil {
		t.Fatal(err)
	}
	if k.Method != CipherAES128 || k.Password != "pw2" || k.Host != "h.test" || k.Port != 443 || len(k.Prefix) != 1 {
		t.Fatalf("got %+v", k)
	}
}

func TestFetchDynamicKeyRejectsNonHTTPS(t *testing.T) {
	for _, u := range []string{"http://example.com/k", "ss://x@h:1", "ssconf:/missing", "ftp://h/k", "ssconf://"} {
		if _, err := FetchDynamicKey(context.Background(), http.DefaultClient, u); err == nil {
			t.Errorf("%q: expected error", u)
		}
	}
}

func TestFetchDynamicKeyRefusesHTTPRedirect(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("plain HTTP target was contacted")
	}))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer srv.Close()

	_, err := FetchDynamicKey(context.Background(), srv.Client(), ssconfURL(srv, "/k"))
	if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchDynamicKeyOversizedBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"server":"` + strings.Repeat("a", maxDynamicKeyBody) + `"}`))
	}))
	defer srv.Close()

	_, err := FetchDynamicKey(context.Background(), srv.Client(), ssconfURL(srv, "/k"))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchDynamicKeyTimeout(t *testing.T) {
	old := dynamicKeyTimeout
	dynamicKeyTimeout = 100 * time.Millisecond
	defer func() { dynamicKeyTimeout = old }()

	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	_, err := FetchDynamicKey(context.Background(), srv.Client(), ssconfURL(srv, "/secret-token"))
	if err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaks the dynamic key URL: %q", err)
	}
}

func TestFetchDynamicKeyBadResponses(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		want   string
	}{
		"http error":  {500, "boom", "HTTP 500"},
		"empty":       {200, "  ", "empty"},
		"bad json":    {200, `{"server":`, "JSON"},
		"bad port":    {200, `{"server":"h.test","server_port":0,"password":"p","method":"aes-128-gcm"}`, "server_port"},
		"bad cipher":  {200, `{"server":"h.test","server_port":1,"password":"p","method":"rc4"}`, "unsupported cipher"},
		"no password": {200, `{"server":"h.test","server_port":1,"method":"aes-128-gcm"}`, "password"},
		"bad ss line": {200, "ss://garbage", "legacy"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := FetchDynamicKey(context.Background(), srv.Client(), ssconfURL(srv, "/k"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}
