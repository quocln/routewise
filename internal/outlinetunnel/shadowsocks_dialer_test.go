package outlinetunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport/shadowsocks"
)

// socksTarget splits a SOCKS5-style IPv4 address ("\x01" + 4 bytes + 2-byte
// port) off the front of b.
func socksTarget(t *testing.T, b []byte) (string, []byte) {
	t.Helper()
	if len(b) < 7 || b[0] != 1 {
		t.Errorf("unexpected target header % x", b)
		return "", nil
	}
	ip := netip.AddrFrom4([4]byte(b[1:5]))
	port := uint16(b[5])<<8 | uint16(b[6])
	return netip.AddrPortFrom(ip, port).String(), b[7:]
}

// TestShadowsocksDialerAgainstSDKServer checks that the production dialer
// speaks real Shadowsocks: cipher mapping, target addressing for streams and
// packets, and the salt prefix.
func TestShadowsocksDialerAgainstSDKServer(t *testing.T) {
	key := Key{Method: CipherChaCha20, Password: "pw-for-test", Host: "127.0.0.1", Port: 1, Prefix: []byte("POST ")}
	ek, err := key.encryptionKey()
	if err != nil {
		t.Fatal(err)
	}

	// TCP server: first plaintext bytes are the target, the rest is echoed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	targets := make(chan string, 1)
	sawPrefix := make(chan bool, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// The prefix replaces the start of the salt, so it is visible on the wire.
		var first bytes.Buffer
		r := shadowsocks.NewReader(io.TeeReader(c, &first), ek)
		hdr := make([]byte, 7)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return
		}
		sawPrefix <- bytes.HasPrefix(first.Bytes(), []byte("POST "))
		addr, _ := socksTarget(t, hdr)
		targets <- addr
		w := shadowsocks.NewWriter(c, ek)
		buf := make([]byte, 64)
		n, _ := r.Read(buf)
		_, _ = w.Write(buf[:n])
	}()

	server := netip.MustParseAddrPort(ln.Addr().String())
	d, err := NewShadowsocksDialer(key, server)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := d.DialStream(ctx, "203.0.113.50:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := io.ReadAtLeast(conn, buf, 5)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("echo = %q, %v", buf[:n], err)
	}
	if got := <-targets; got != "203.0.113.50:443" {
		t.Fatalf("server saw target %q", got)
	}
	if !<-sawPrefix {
		t.Fatal("salt prefix not on the wire")
	}

	// UDP server: decrypt, check target, reply from the same target.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	udpTargets := make(chan string, 1)
	go func() {
		buf := make([]byte, 2048)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		plain, err := shadowsocks.Unpack(nil, buf[:n], ek)
		if err != nil {
			return
		}
		addr, payload := socksTarget(t, plain)
		udpTargets <- addr
		reply := append(append([]byte{}, plain[:7]...), bytes.ToUpper(payload)...)
		out, err := shadowsocks.Pack(make([]byte, 2048), reply, ek)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(out, from)
	}()
	ud, err := NewShadowsocksDialer(key, netip.MustParseAddrPort(pc.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := ud.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pkt.Close()
	if _, err := pkt.WriteTo([]byte("dgram"), &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 5300}); err != nil {
		t.Fatal(err)
	}
	_ = pkt.SetReadDeadline(time.Now().Add(5 * time.Second))
	rb := make([]byte, 64)
	n, from, err := pkt.ReadFrom(rb)
	if err != nil || string(rb[:n]) != "DGRAM" || from.String() != "198.51.100.7:5300" {
		t.Fatalf("udp reply = %q from %v, %v", rb[:n], from, err)
	}
	if got := <-udpTargets; got != "198.51.100.7:5300" {
		t.Fatalf("server saw udp target %q", got)
	}
}

func TestEncryptionKeyRejectsUnknownCipher(t *testing.T) {
	if _, err := NewShadowsocksDialer(Key{Method: "rc4", Password: "x"}, netip.MustParseAddrPort("1.2.3.4:5")); err == nil {
		t.Fatal("expected error")
	}
}
