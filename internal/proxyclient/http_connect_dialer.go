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

	"golang.getoutline.org/sdk/transport"
)

// maxConnectResponse bounds what a proxy may send before its tunnel opens. The helper
// runs as root and the proxy is someone else's machine.
const maxConnectResponse = 64 * 1024

// ErrConnectUnsupported means the server answers HTTP but will not open tunnels, as a
// plain web server or a proxy for plain HTTP only does.
var ErrConnectUnsupported = errors.New("the proxy does not support CONNECT tunnels")

// ConnectStatusError is the proxy's answer when it would not open a tunnel.
type ConnectStatusError struct{ Status int }

func (e ConnectStatusError) Error() string {
	return fmt.Sprintf("the proxy answered CONNECT with status %d", e.Status)
}

// HTTPDialer opens flows through an HTTP proxy with the CONNECT method. A proxy can
// tunnel only TCP, and many allow only port 443.
type HTTPDialer struct {
	endpoint transport.TCPEndpoint
	// authorization is the Proxy-Authorization value, empty with no credentials.
	authorization string
}

// NewHTTPDialer builds the dialer for a proxy whose host was resolved to server.
func NewHTTPDialer(c Config, server netip.AddrPort) *HTTPDialer {
	d := &HTTPDialer{endpoint: transport.TCPEndpoint{Address: server.String()}}
	if c.Username != "" {
		d.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
	}
	return d
}

// DialStream opens a TCP stream through the proxy to addr (ip:port). ctx bounds opening
// it, and the stream outlives ctx.
func (d *HTTPDialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	conn, err := d.endpoint.ConnectStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the HTTP proxy: %w", err)
	}
	h := &handshake{}
	h.watch(ctx, conn)
	defer h.finish()
	stream, err := d.openTunnel(conn, addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return stream, nil
}

func (d *HTTPDialer) openTunnel(conn transport.StreamConn, addr string) (transport.StreamConn, error) {
	request := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if d.authorization != "" {
		request += "Proxy-Authorization: " + d.authorization + "\r\n"
	}
	if _, err := io.WriteString(conn, request+"\r\n"); err != nil {
		return nil, fmt.Errorf("could not send CONNECT to the proxy: %w", err)
	}

	limited := &io.LimitedReader{R: conn, N: maxConnectResponse}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("could not read the proxy's answer to CONNECT: %w", err)
	}
	// A failure's body says nothing more, and the connection closes with it.
	switch status := response.StatusCode; {
	case status >= 200 && status < 300:
	// tinyproxy asks for a login on CONNECT with 401, not the 407 a proxy should send.
	case (status == http.StatusProxyAuthRequired || status == http.StatusUnauthorized) && d.authorization == "":
		return nil, ErrAuthRequired
	case status == http.StatusProxyAuthRequired || status == http.StatusUnauthorized:
		return nil, ErrAuthRefused
	case status == http.StatusMethodNotAllowed, status == http.StatusNotImplemented,
		status == http.StatusBadRequest, status == http.StatusNotFound:
		return nil, ErrConnectUnsupported
	default:
		return nil, ConnectStatusError{Status: status}
	}

	// What arrived with the answer already belongs to the stream.
	if early := reader.Buffered(); early > 0 {
		leftover := make([]byte, early)
		if _, err := io.ReadFull(reader, leftover); err != nil {
			return nil, err
		}
		return &startedStream{StreamConn: conn, leftover: leftover}, nil
	}
	return conn, nil
}

// startedStream is a stream whose first bytes were read along with the proxy's answer.
type startedStream struct {
	transport.StreamConn
	leftover []byte
}

func (s *startedStream) Read(b []byte) (int, error) {
	if len(s.leftover) > 0 {
		n := copy(b, s.leftover)
		s.leftover = s.leftover[n:]
		return n, nil
	}
	return s.StreamConn.Read(b)
}

// ListenPacket opens a UDP flow, of which only DNS can get through: an HTTP proxy has
// no way to relay UDP.
func (d *HTTPDialer) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return newPacketConn(ctx, d, func(context.Context) (net.PacketConn, error) { return nil, ErrUDPUnsupported })
}

// Check proves the proxy answers and accepts the credentials: see proxy_check.go. A
// proxy that forbids the target, or reports it cannot reach it, has done its job, while
// any other failure counts as down.
func (d *HTTPDialer) Check(ctx context.Context) error {
	return check(ctx, d, func(err error) bool {
		var answered ConnectStatusError
		if !errors.As(err, &answered) {
			return false
		}
		switch answered.Status {
		case http.StatusForbidden, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
		return false
	})
}
