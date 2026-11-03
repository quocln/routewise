package proxyclient

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHTTPProxy is a CONNECT proxy on loopback that echoes what a tunnel carries.
type fakeHTTPProxy struct {
	listener net.Listener
	// username and password, when set, are required.
	username, password string
	// status, when set, is the answer to every CONNECT.
	status int
	// early is sent in the same write as the 200, as a proxy may.
	early string
	// silent reads the request and never answers. flood answers without end.
	silent, flood bool

	mu       sync.Mutex
	requests []*http.Request
}

func startHTTPProxy(t *testing.T, configure func(*fakeHTTPProxy)) *fakeHTTPProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &fakeHTTPProxy{listener: l}
	if configure != nil {
		configure(p)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go p.serve(conn)
		}
	}()
	return p
}

func (p *fakeHTTPProxy) dialer(username, password string) *HTTPDialer {
	return NewHTTPDialer(Config{Username: username, Password: password}, p.listener.Addr().(*net.TCPAddr).AddrPort())
}

func (p *fakeHTTPProxy) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	req, err := http.ReadRequest(r)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.requests = append(p.requests, req)
	p.mu.Unlock()
	switch {
	case p.silent:
		_, _ = io.Copy(io.Discard, r)
		return
	case p.flood:
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n")
		line := []byte("X-Fill: " + strings.Repeat("x", 1024) + "\r\n")
		for {
			if _, err := conn.Write(line); err != nil {
				return
			}
		}
	case p.status != 0:
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n\r\n", p.status, http.StatusText(p.status))
		return
	case p.username != "" && req.Header.Get("Proxy-Authorization") !=
		"Basic "+base64.StdEncoding.EncodeToString([]byte(p.username+":"+p.password)):
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n")
		return
	}
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"+p.early)
	_, _ = io.Copy(conn, r)
}

func (p *fakeHTTPProxy) lastRequest(t *testing.T) *http.Request {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.requests) == 0 {
		t.Fatal("the proxy got no request")
	}
	return p.requests[len(p.requests)-1]
}

func TestParseHTTPURL(t *testing.T) {
	c, err := ParseURL(HTTP, "  http://me:p%40ss@proxy.example.com:8080/\n")
	if err != nil || c != (Config{Host: "proxy.example.com", Port: 8080, Username: "me", Password: "p@ss"}) {
		t.Errorf("ParseURL = %+v, %v", c, err)
	}
	for _, in := range []string{
		"https://proxy.example.com:8080",
		"socks5://proxy.example.com:1080",
		"http://proxy.example.com",
		"http://a%3Ab:p@proxy.example.com:8080",
	} {
		if _, err := ParseURL(HTTP, in); err == nil {
			t.Errorf("ParseURL(%q) was accepted", in)
		}
	}
	if _, err := ParseURL(SOCKS5, "http://proxy.example.com:8080"); err == nil {
		t.Error("a SOCKS5 profile took an http:// address")
	}
}

func TestHTTPStreamWithAndWithoutAPassword(t *testing.T) {
	for _, tt := range []struct {
		name               string
		proxyUser, proxyPw string
	}{
		{name: "no password"},
		{name: "a password", proxyUser: "me", proxyPw: "p:ss"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := startHTTPProxy(t, func(p *fakeHTTPProxy) { p.username, p.password = tt.proxyUser, tt.proxyPw })
			conn, err := p.dialer(tt.proxyUser, tt.proxyPw).DialStream(ctxFor(t), "203.0.113.9:443")
			if err != nil {
				t.Fatalf("DialStream: %v", err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("read = %q, %v", buf, err)
			}
			req := p.lastRequest(t)
			if req.Method != http.MethodConnect || req.Host != "203.0.113.9:443" {
				t.Errorf("request = %s %s", req.Method, req.Host)
			}
			if got := req.Header.Get("Proxy-Authorization") != ""; got != (tt.proxyUser != "") {
				t.Errorf("Proxy-Authorization sent = %v", got)
			}
		})
	}
}

// Bytes a proxy sends with its answer are the start of the stream, and losing them
// would corrupt whatever the destination spoke first, as an SSH or mail server does.
func TestHTTPKeepsBytesThatArriveWithTheAnswer(t *testing.T) {
	p := startHTTPProxy(t, func(p *fakeHTTPProxy) { p.early = "banner" })
	conn, err := p.dialer("", "").DialStream(ctxFor(t), "203.0.113.9:22")
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 6)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "banner" {
		t.Fatalf("read = %q, %v", buf, err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Errorf("CloseWrite: %v", err)
	}
}

func TestHTTPSaysWhyItCouldNotConnect(t *testing.T) {
	needsLogin := func(p *fakeHTTPProxy) { p.username, p.password = "me", "right" }
	withStatus := func(status int) func(*fakeHTTPProxy) { return func(p *fakeHTTPProxy) { p.status = status } }
	for _, tt := range []struct {
		name      string
		configure func(*fakeHTTPProxy)
		user, pw  string
		want      error
	}{
		{"no login", needsLogin, "", "", ErrAuthRequired},
		{"a wrong login", needsLogin, "me", "wrong", ErrAuthRefused},
		{"a plain web server", withStatus(http.StatusMethodNotAllowed), "", "", ErrConnectUnsupported},
		{"no CONNECT at all", withStatus(http.StatusNotImplemented), "", "", ErrConnectUnsupported},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := startHTTPProxy(t, tt.configure)
			_, err := p.dialer(tt.user, tt.pw).DialStream(ctxFor(t), "203.0.113.9:443")
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestHTTPCheck(t *testing.T) {
	withStatus := func(status int) func(*fakeHTTPProxy) { return func(p *fakeHTTPProxy) { p.status = status } }
	for _, tt := range []struct {
		name      string
		configure func(*fakeHTTPProxy)
		healthy   bool
	}{
		{"it connects", nil, true},
		{"it forbids the target", withStatus(http.StatusForbidden), true},
		{"it cannot reach the target", withStatus(http.StatusBadGateway), true},
		{"it times out on the target", withStatus(http.StatusGatewayTimeout), true},
		{"it fails", withStatus(http.StatusInternalServerError), false},
		{"it wants a login", func(p *fakeHTTPProxy) { p.username, p.password = "me", "right" }, false},
		{"it is a web server", withStatus(http.StatusMethodNotAllowed), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := startHTTPProxy(t, tt.configure)
			err := p.dialer("", "").Check(ctxFor(t))
			if (err == nil) != tt.healthy {
				t.Errorf("Check = %v, want healthy %v", err, tt.healthy)
			}
		})
	}
}

func TestHTTPCheckNamesARefusal(t *testing.T) {
	for _, tt := range []struct {
		name     string
		status   int
		user, pw string
		want     error
	}{
		{"407 with no login", http.StatusProxyAuthRequired, "", "", ErrAuthRequired},
		{"407 with a login", http.StatusProxyAuthRequired, "me", "wrong", ErrAuthRefused},
		{"401 with no login, as tinyproxy answers", http.StatusUnauthorized, "", "", ErrAuthRequired},
		{"401 with a login, as tinyproxy answers", http.StatusUnauthorized, "me", "wrong", ErrAuthRefused},
		{"a web server", http.StatusNotImplemented, "", "", ErrConnectUnsupported},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := startHTTPProxy(t, func(p *fakeHTTPProxy) { p.status = tt.status })
			err := p.dialer(tt.user, tt.pw).Check(ctxFor(t))
			if !errors.Is(err, tt.want) || !IsRefusal(err) {
				t.Fatalf("Check = %v, want %v as a refusal", err, tt.want)
			}
			if strings.Contains(err.Error(), "did not answer") {
				t.Errorf("a proxy that refused is reported as silent: %v", err)
			}
		})
	}
}

func TestHTTPProxyThatIsNotHTTPFailsTheCheck(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err == nil {
			_, _ = conn.Write([]byte{5, 0xFF})
			_ = conn.Close()
		}
	}()
	d := NewHTTPDialer(Config{}, l.Addr().(*net.TCPAddr).AddrPort())
	if err := d.Check(ctxFor(t)); err == nil {
		t.Error("something that is not an HTTP proxy passed the check")
	}
}

// The context bounds the handshake and the stream outlives it, as with SOCKS5.
func TestHTTPStreamOutlivesItsContextAndAHangEndsWithIt(t *testing.T) {
	p := startHTTPProxy(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	conn, err := p.dialer("", "").DialStream(ctx, "203.0.113.9:443")
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer conn.Close()
	cancel()
	time.Sleep(200 * time.Millisecond)
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write after the context ended: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("read after the context ended = %q, %v", buf, err)
	}

	hung := startHTTPProxy(t, func(p *fakeHTTPProxy) { p.silent = true })
	ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	d := hung.dialer("", "")
	done := make(chan error, 1)
	go func() { done <- d.Check(ctx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a proxy that never answers passed the check")
		}
	case <-time.After(CheckTimeout / 2):
		t.Fatal("Check did not end with its context")
	}
}

// A proxy is someone else's machine, and what it sends is read by a root process.
func TestHTTPAnswerThatNeverEndsIsCutOff(t *testing.T) {
	p := startHTTPProxy(t, func(p *fakeHTTPProxy) { p.flood = true })
	if _, err := p.dialer("", "").DialStream(ctxFor(t), "203.0.113.9:443"); err == nil {
		t.Error("an endless answer opened a stream")
	}
}

// DNS works through a proxy with no way to relay UDP, and other UDP says why it cannot.
func TestHTTPCarriesDNSAndRefusesOtherUDP(t *testing.T) {
	p := startHTTPProxy(t, nil)
	pc, err := p.dialer("", "").ListenPacket(ctxFor(t))
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 443}); !errors.Is(err, ErrUDPUnsupported) {
		t.Errorf("other UDP = %v, want ErrUDPUnsupported", err)
	}

	dnsFlow, err := p.dialer("", "").ListenPacket(ctxFor(t))
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer dnsFlow.Close()
	if _, err := dnsFlow.WriteTo([]byte("query"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.0.0.1:53"))); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 64)
	n, from, err := dnsFlow.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	// The fake proxy echoes the TCP framing, so the reply is the query's own bytes.
	if string(buf[:n]) != "query" || from.String() != "1.0.0.1:53" {
		t.Errorf("reply = %q from %v", buf[:n], from)
	}
}
