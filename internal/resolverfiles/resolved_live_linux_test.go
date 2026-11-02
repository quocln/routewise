package resolverfiles

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The live tests drive the real dummy link and systemd-resolved, so they need
// root and a running resolved; elsewhere they skip.
func requireResolved(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to manage network links")
	}
	if _, err := os.Stat("/run/systemd/resolve/io.systemd.Resolve"); err != nil {
		t.Skip("systemd-resolved is not running")
	}
}

// answerServer answers every A query with 192.0.2.53 on 127.0.0.1:port.
func answerServer(t *testing.T, port int) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		for _, q := range req.Question {
			if q.Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
					A:   net.ParseIP("192.0.2.53"),
				})
			}
		}
		w.WriteMsg(resp)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })
}

func lookupViaSystem(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return (&net.Resolver{}).LookupHost(ctx, name)
}

func TestSystemdResolvedRoutesOnlyListedDomains(t *testing.T) {
	requireResolved(t)
	const port = 53981
	answerServer(t, port)

	c := NewSystem("127.0.0.1", port)
	t.Cleanup(func() { c.RemoveAll() })
	if _, err := c.Apply([]string{"routewise-live.test"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := net.InterfaceByName(LinkName); err != nil {
		t.Fatalf("link %s missing after Apply: %v", LinkName, err)
	}

	addrs, err := lookupViaSystem("a.routewise-live.test")
	if err != nil || len(addrs) != 1 || addrs[0] != "192.0.2.53" {
		t.Errorf("listed domain resolved to %v, %v; want the forwarder's answer", addrs, err)
	}
	// A name outside the set must not reach the forwarder: it either resolves
	// elsewhere or fails, but is never the forwarder's catch-all answer.
	if addrs, err := lookupViaSystem("routewise-other.invalid"); err == nil {
		t.Errorf("an unlisted domain resolved to %v through the forwarder", addrs)
	}

	// Applying again is idempotent, and a smaller set drops the old domain.
	if _, err := c.Apply([]string{"routewise-live.test"}); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if _, err := c.Apply([]string{"routewise-live2.test"}); err != nil {
		t.Fatalf("third Apply: %v", err)
	}
	if addrs, err := lookupViaSystem("a.routewise-live.test"); err == nil {
		t.Errorf("a dropped domain still resolved to %v", addrs)
	}
	if addrs, err := lookupViaSystem("a.routewise-live2.test"); err != nil || len(addrs) != 1 {
		t.Errorf("replacement domain resolved to %v, %v", addrs, err)
	}

	if err := c.RemoveAll(); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if _, err := net.InterfaceByName(LinkName); err == nil {
		t.Errorf("link %s still exists after RemoveAll", LinkName)
	}
	if err := c.RemoveAll(); err != nil {
		t.Errorf("RemoveAll twice: %v", err)
	}
}

func TestSystemdResolvedRemoveAllClearsALeftBehindLink(t *testing.T) {
	requireResolved(t)
	first := NewSystem("127.0.0.1", 53981)
	if _, err := first.Apply([]string{"routewise-live.test"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// A second process (a restarted daemon) knows nothing of the first's state.
	if err := NewSystem("127.0.0.1", 53981).RemoveAll(); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	defer first.RemoveAll()
	if _, err := net.InterfaceByName(LinkName); err == nil {
		t.Errorf("link %s survived a fresh process's RemoveAll", LinkName)
	}
}
