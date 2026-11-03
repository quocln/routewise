package proxyclient

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport/socks5"
)

// fakeProxy is a SOCKS5 server on loopback. Like a real one, it reads the method offer
// and answers before it reads anything else, so it would notice a client that assumed
// otherwise, and it closes a connection whose offer it refuses.
type fakeProxy struct {
	t        *testing.T
	listener net.Listener
	// username and password, when set, are required. noAuthOnly refuses to accept
	// credentials at all, as a proxy with none configured does.
	username, password string
	noAuthOnly         bool
	// reply is the code a CONNECT gets; zero connects to the echo behaviour below.
	reply byte
	// silent accepts the method offer and then never answers the request.
	silent bool
	// udpRelay turns on UDP ASSOCIATE; off, the command is refused.
	udpRelay bool

	mu      sync.Mutex
	targets []string
	offers  [][]byte
}

func startProxy(t *testing.T, configure func(*fakeProxy)) *fakeProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &fakeProxy{t: t, listener: l}
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

func (p *fakeProxy) addr() netip.AddrPort { return p.listener.Addr().(*net.TCPAddr).AddrPort() }

func (p *fakeProxy) dialer(t *testing.T, username, password string) *SOCKS5Dialer {
	t.Helper()
	d, err := NewSOCKS5Dialer(Config{Username: username, Password: password}, p.addr())
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	return d
}

func (p *fakeProxy) dialed() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func (p *fakeProxy) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}
	p.mu.Lock()
	p.offers = append(p.offers, methods)
	p.mu.Unlock()

	offered := func(m byte) bool { return strings.IndexByte(string(methods), m) >= 0 }
	switch {
	case p.username != "" && offered(2):
		_, _ = conn.Write([]byte{5, 2})
		if !p.checkPassword(r, conn) {
			return
		}
	case p.username == "" && offered(0):
		_, _ = conn.Write([]byte{5, 0})
	default:
		_, _ = conn.Write([]byte{5, 0xFF})
		return
	}
	if p.silent {
		_, _ = io.Copy(io.Discard, r)
		return
	}

	var req [4]byte
	if _, err := io.ReadFull(r, req[:]); err != nil {
		return
	}
	target := p.readAddr(r, req[3])
	switch req[1] {
	case 1:
		p.mu.Lock()
		p.targets = append(p.targets, target)
		p.mu.Unlock()
		if p.reply != 0 {
			_, _ = conn.Write(replyBytes(p.reply, netip.AddrPort{}))
			return
		}
		_, _ = conn.Write(replyBytes(0, netip.AddrPort{}))
		if strings.HasSuffix(target, ":53") {
			serveTCPDNS(r, conn)
			return
		}
		_, _ = io.Copy(conn, r)
	case 3:
		if !p.udpRelay {
			_, _ = conn.Write(replyBytes(7, netip.AddrPort{}))
			return
		}
		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return
		}
		defer relay.Close()
		_, _ = conn.Write(replyBytes(0, relay.LocalAddr().(*net.UDPAddr).AddrPort()))
		go echoUDP(relay)
		_, _ = io.Copy(io.Discard, r)
	default:
		_, _ = conn.Write(replyBytes(7, netip.AddrPort{}))
	}
}

func (p *fakeProxy) checkPassword(r io.Reader, w io.Writer) bool {
	read := func() string {
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return ""
		}
		b := make([]byte, n[0])
		_, _ = io.ReadFull(r, b)
		return string(b)
	}
	var version [1]byte
	if _, err := io.ReadFull(r, version[:]); err != nil {
		return false
	}
	if read() != p.username || read() != p.password {
		_, _ = w.Write([]byte{1, 1})
		return false
	}
	_, _ = w.Write([]byte{1, 0})
	return true
}

func (p *fakeProxy) readAddr(r io.Reader, kind byte) string {
	var size int
	switch kind {
	case 1:
		size = 4
	case 4:
		size = 16
	default:
		p.t.Errorf("the tunnel gave the proxy an address of kind %d, not an IP", kind)
		return ""
	}
	b := make([]byte, size+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return ""
	}
	addr, _ := netip.AddrFromSlice(b[:size])
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(b[size:])).String()
}

func replyBytes(code byte, bound netip.AddrPort) []byte {
	out := []byte{5, code, 0, 1}
	if !bound.IsValid() {
		return append(out, 0, 0, 0, 0, 0, 0)
	}
	a := bound.Addr().As4()
	return binary.BigEndian.AppendUint16(append(out, a[:]...), bound.Port())
}

// serveTCPDNS answers one framed query with its bytes and the response bit set.
func serveTCPDNS(r io.Reader, w io.Writer) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return
	}
	body := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(r, body); err != nil {
		return
	}
	_, _ = w.Write(append(n[:], append([]byte("answer:"), body...)[:len(body)]...))
}

// echoUDP returns each relayed datagram to its sender as is, header included, which is
// the form a reply through a relay takes.
func echoUDP(relay *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, from, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = relay.WriteToUDP(buf[:n], from)
	}
}

func ctxFor(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestParseURL(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want Config
	}{
		{"socks5://127.0.0.1:1080", Config{Host: "127.0.0.1", Port: 1080}},
		{"  socks5h://proxy.example.com:1080/\n", Config{Host: "proxy.example.com", Port: 1080}},
		{"SOCKS5://u:p@[::1]:1080", Config{Host: "::1", Port: 1080, Username: "u", Password: "p"}},
		{"socks5://us%40er:p%3Ass%2Fw%40rd@h.example.com:1", Config{Host: "h.example.com", Port: 1, Username: "us@er", Password: "p:ss/w@rd"}},
	} {
		got, err := ParseURL(SOCKS5, tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ParseURL(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
	}
}

// A bad address can hold the password, and an error ends up in logs and RPC replies.
func TestParseURLRefusesBadAddressesWithoutRepeatingThem(t *testing.T) {
	const password = "hunter2secret"
	for _, in := range []string{
		"http://u:" + password + "@h.example.com:1080",
		"socks4://u:" + password + "@h.example.com:1080",
		"h.example.com:1080",
		"socks5://u:" + password + "@h.example.com",
		"socks5://u:" + password + "@h.example.com:0",
		"socks5://u:" + password + "@h.example.com:70000",
		"socks5://:" + password + "@h.example.com:1080",
		"socks5://u:" + password + "@:1080",
		"socks5://u:" + password + "@h.example.com:1080/path",
		"socks5://u:" + password + "@h.example.com:1080?x=1",
		"socks5://u:" + password + "%zz@h.example.com:1080",
		"socks5://" + strings.Repeat("u", 256) + ":p@h.example.com:1080",
	} {
		_, err := ParseURL(SOCKS5, in)
		if err == nil {
			t.Errorf("ParseURL(%q) was accepted", in)
			continue
		}
		if strings.Contains(err.Error(), password) {
			t.Errorf("the error for %q repeats the password: %v", in, err)
		}
	}
	if _, err := ParseURL(SOCKS5, "socks5://onlyuser@h.example.com:1080"); err == nil {
		t.Error("a username with no password was accepted")
	}
}

func TestHostPortHoldsNoCredentials(t *testing.T) {
	c, err := ParseURL(SOCKS5, "socks5://user:secret@[2001:db8::1]:1080")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.HostPort(); got != "[2001:db8::1]:1080" {
		t.Errorf("HostPort = %q", got)
	}
}

func TestStreamsWithAndWithoutAPassword(t *testing.T) {
	for _, tt := range []struct {
		name               string
		proxyUser, proxyPw string
		user, pw           string
	}{
		{name: "a proxy with no password"},
		{name: "a proxy with a password", proxyUser: "u", proxyPw: "p", user: "u", pw: "p"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := startProxy(t, func(p *fakeProxy) { p.username, p.password = tt.proxyUser, tt.proxyPw })
			conn, err := p.dialer(t, tt.user, tt.pw).DialStream(ctxFor(t), "203.0.113.9:443")
			if err != nil {
				t.Fatalf("DialStream: %v", err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("read = %q, %v", buf, err)
			}
			if got := p.dialed(); len(got) != 1 || got[0] != "203.0.113.9:443" {
				t.Errorf("proxy was asked for %v", got)
			}
		})
	}
}

// Credentials given for a proxy that wants none still connect, and later flows skip
// the refused offer. This also holds noAcceptableMethod to what the SDK really says.
func TestCredentialsAProxyDoesNotWantStillConnect(t *testing.T) {
	p := startProxy(t, nil)
	d := p.dialer(t, "u", "p")
	for range 2 {
		conn, err := d.DialStream(ctxFor(t), "203.0.113.9:443")
		if err != nil {
			t.Fatalf("DialStream: %v", err)
		}
		_ = conn.Close()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.offers) != 3 {
		t.Errorf("the proxy saw %d offers, want the refused one and one per flow: %v", len(p.offers), p.offers)
	}
}

func TestNoPasswordForAProxyThatWantsOneSaysSo(t *testing.T) {
	p := startProxy(t, func(p *fakeProxy) { p.username, p.password = "u", "p" })
	_, err := p.dialer(t, "", "").DialStream(ctxFor(t), "203.0.113.9:443")
	if !errors.Is(err, ErrAuthRequired) {
		t.Errorf("err = %v, want ErrAuthRequired", err)
	}
}

func TestAWrongPasswordSaysSoAndDoesNotRepeatIt(t *testing.T) {
	p := startProxy(t, func(p *fakeProxy) { p.username, p.password = "u", "right-password" })
	_, err := p.dialer(t, "u", "wrong-password").DialStream(ctxFor(t), "203.0.113.9:443")
	if !errors.Is(err, ErrAuthRefused) {
		t.Fatalf("err = %v, want ErrAuthRefused", err)
	}
	if strings.Contains(err.Error(), "wrong-password") {
		t.Errorf("the error repeats the password: %v", err)
	}
}

func TestCheck(t *testing.T) {
	for _, tt := range []struct {
		name      string
		configure func(*fakeProxy)
		user, pw  string
		healthy   bool
	}{
		{"it connects", nil, "", "", true},
		{"it may not go there", func(p *fakeProxy) { p.reply = byte(socks5.ErrConnectionNotAllowedByRuleset) }, "", "", true},
		{"it cannot reach there", func(p *fakeProxy) { p.reply = byte(socks5.ErrHostUnreachable) }, "", "", true},
		{"it fails", func(p *fakeProxy) { p.reply = byte(socks5.ErrGeneralServerFailure) }, "", "", false},
		{"it refuses the login", func(p *fakeProxy) { p.username, p.password = "u", "p" }, "u", "wrong", false},
		{"it wants a login", func(p *fakeProxy) { p.username, p.password = "u", "p" }, "", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := startProxy(t, tt.configure)
			err := p.dialer(t, tt.user, tt.pw).Check(ctxFor(t))
			if (err == nil) != tt.healthy {
				t.Errorf("Check = %v, want healthy %v", err, tt.healthy)
			}
		})
	}
}

func TestCheckNamesARefusedLogin(t *testing.T) {
	for _, tt := range []struct {
		name     string
		user, pw string
		want     error
	}{
		{"no login", "", "", ErrAuthRequired},
		{"the wrong login", "u", "wrong", ErrAuthRefused},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := startProxy(t, func(p *fakeProxy) { p.username, p.password = "u", "p" })
			err := p.dialer(t, tt.user, tt.pw).Check(ctxFor(t))
			if !errors.Is(err, tt.want) || !IsRefusal(err) {
				t.Fatalf("Check = %v, want %v as a refusal", err, tt.want)
			}
			if strings.Contains(err.Error(), "did not answer") {
				t.Errorf("a proxy that refused is reported as silent: %v", err)
			}
		})
	}
}

func TestCheckOfAProxyThatHangsEndsWithItsContext(t *testing.T) {
	p := startProxy(t, func(p *fakeProxy) { p.silent = true })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	d := p.dialer(t, "", "")
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

// The context bounds the handshake, and callers cancel it once the stream is open, so
// a stream must survive that.
func TestAStreamOutlivesTheContextThatOpenedIt(t *testing.T) {
	p := startProxy(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	conn, err := p.dialer(t, "", "").DialStream(ctx, "203.0.113.9:443")
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
}

func TestAStreamToAProxyThatHangsEndsWithItsContext(t *testing.T) {
	p := startProxy(t, func(p *fakeProxy) { p.silent = true })
	ctx, cancel := context.WithCancel(context.Background())
	d := p.dialer(t, "", "")
	done := make(chan error, 1)
	go func() {
		_, err := d.DialStream(ctx, "203.0.113.9:443")
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a proxy that never answers opened a stream")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DialStream ignored its cancellation")
	}
}

func TestCheckOfAProxyThatIsGoneFails(t *testing.T) {
	p := startProxy(t, nil)
	d := p.dialer(t, "", "")
	_ = p.listener.Close()
	if err := d.Check(ctxFor(t)); err == nil {
		t.Error("a proxy that is gone passed the check")
	}
}

// DNS is carried over TCP, so lookups work through the many proxies with no UDP.
func TestDNSGoesOverTCPThroughAProxyWithNoUDP(t *testing.T) {
	p := startProxy(t, nil)
	pc, err := p.dialer(t, "", "").ListenPacket(ctxFor(t))
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	server := &net.UDPAddr{IP: net.IPv4(1, 0, 0, 1), Port: 53}
	if _, err := pc.WriteTo([]byte("0123456789abcdef"), server); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 512)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "answer:") || n != 16 {
		t.Errorf("reply = %q", buf[:n])
	}
	if from.String() != "1.0.0.1:53" {
		t.Errorf("reply from %v", from)
	}
	if got := p.dialed(); len(got) != 1 || got[0] != "1.0.0.1:53" {
		t.Errorf("proxy was asked for %v", got)
	}
}

func TestOtherUDPGoesThroughTheRelay(t *testing.T) {
	p := startProxy(t, func(p *fakeProxy) { p.udpRelay = true })
	pc, err := p.dialer(t, "", "").ListenPacket(ctxFor(t))
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	target := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 443}
	if _, err := pc.WriteTo([]byte("quic"), target); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 512)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "quic" || from.String() != "203.0.113.9:443" {
		t.Errorf("reply = %q from %v", buf[:n], from)
	}
}

func TestUDPThroughAProxyWithNoRelaySaysSo(t *testing.T) {
	p := startProxy(t, nil)
	pc, err := p.dialer(t, "", "").ListenPacket(ctxFor(t))
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	_, err = pc.WriteTo([]byte("quic"), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 443})
	if !errors.Is(err, ErrUDPUnsupported) {
		t.Errorf("err = %v, want ErrUDPUnsupported", err)
	}
}

// The tunnel ends a flow by closing it from another goroutine, which must free a reader
// whatever the flow is waiting on, and Close must not wait for the proxy.
func TestClosingAFlowFreesItsReader(t *testing.T) {
	for _, tt := range []struct {
		name  string
		write func(net.PacketConn)
	}{
		{"nothing sent yet", func(net.PacketConn) {}},
		{"a query the proxy never answers", func(pc net.PacketConn) {
			_, _ = pc.WriteTo([]byte("query"), &net.UDPAddr{IP: net.IPv4(1, 0, 0, 1), Port: 53})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := startProxy(t, func(p *fakeProxy) { p.silent = true })
			pc, err := p.dialer(t, "", "").ListenPacket(ctxFor(t))
			if err != nil {
				t.Fatalf("ListenPacket: %v", err)
			}
			tt.write(pc)
			read := make(chan error, 1)
			go func() {
				_, _, err := pc.ReadFrom(make([]byte, 64))
				read <- err
			}()
			if err := pc.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
			select {
			case err := <-read:
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("read after close = %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the reader was not freed")
			}
			if _, err := pc.WriteTo([]byte("late"), &net.UDPAddr{IP: net.IPv4(1, 0, 0, 1), Port: 53}); !errors.Is(err, net.ErrClosed) {
				t.Errorf("write after close = %v", err)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	literal, err := (Config{Host: "203.0.113.9", Port: 1080}).Resolve(ctxFor(t), failingResolver{})
	if err != nil || literal.String() != "203.0.113.9:1080" {
		t.Errorf("an IP literal = %v, %v", literal, err)
	}
	named, err := (Config{Host: "p.example.com", Port: 1080}).Resolve(ctxFor(t), fixedResolver{
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("203.0.113.10"),
	})
	if err != nil || named.String() != "203.0.113.10:1080" {
		t.Errorf("a name = %v, %v; want IPv4 first", named, err)
	}
	if _, err := (Config{Host: "p.example.com", Port: 1080}).Resolve(ctxFor(t), failingResolver{}); err == nil {
		t.Error("a failed lookup was accepted")
	}
	if _, err := (Config{Host: "p.example.com", Port: 1080}).Resolve(ctxFor(t), fixedResolver{}); err == nil {
		t.Error("a lookup with no addresses was accepted")
	}
}

type failingResolver struct{}

func (failingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("no such host")
}

type fixedResolver []netip.Addr

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r, nil
}
