//go:build darwin || linux

package ipc

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestPeerUIDReportsTheConnectingUser(t *testing.T) {
	l, path := listenTemp(t)
	server := make(chan uint32, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			server <- ^uint32(0)
			return
		}
		defer c.Close()
		uid, ok := PeerUID(c)
		if !ok {
			uid = ^uint32(0)
		}
		server <- uid
	}()

	conn, err := Dial(context.Background(), path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case uid := <-server:
		if int(uid) != os.Geteuid() {
			t.Errorf("PeerUID = %d, want %d", uid, os.Geteuid())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no connection accepted")
	}
}

func TestPeerUIDRejectsNonUnixConnections(t *testing.T) {
	c1, c2 := netPipe()
	defer c1.Close()
	defer c2.Close()
	if _, ok := PeerUID(c1); ok {
		t.Error("a non-Unix connection has no kernel-reported peer")
	}
}

func netPipe() (net.Conn, net.Conn) { return net.Pipe() }
