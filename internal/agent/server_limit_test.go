package agent

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	sshagent "golang.org/x/crypto/ssh/agent"
)

type connectionListener struct {
	accepted chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

func (l *connectionListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accepted:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *connectionListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *connectionListener) Addr() net.Addr { return &net.UnixAddr{Name: "test", Net: "unix"} }

func TestListenerLimitsConnectionsWithoutDisruptingExistingClients(t *testing.T) {
	l := &connectionListener{accepted: make(chan net.Conn), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeListener(ctx, l, NewProtected(nil)) }()
	clients := make([]net.Conn, 0, maxAgentConnections)
	peers := make([]sshagent.ExtendedAgent, 0, maxAgentConnections)
	defer func() {
		cancel()
		for _, client := range clients {
			client.Close()
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("listener failed to stop")
		}
	}()
	for range maxAgentConnections {
		server, client := net.Pipe()
		clients = append(clients, client)
		l.accepted <- server
		client.SetDeadline(time.Now().Add(time.Second))
		peer := sshagent.NewClient(client)
		peers = append(peers, peer)
		if _, err := peer.List(); err != nil {
			t.Fatal(err)
		}
		client.SetDeadline(time.Time{})
	}
	server, overflow := net.Pipe()
	defer overflow.Close()
	l.accepted <- server
	overflow.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := overflow.Read(b[:]); err != nil {
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("excess connection retained")
		}
	} else {
		t.Fatal("excess connection accepted")
	}
	clients[0].SetDeadline(time.Now().Add(time.Second))
	if _, err := peers[0].List(); err != nil {
		t.Fatalf("existing connection disrupted: %v", err)
	}
}
