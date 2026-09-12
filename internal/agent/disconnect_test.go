package agent_test

import (
	"context"
	"net"
	"testing"
	"time"

	protected "github.com/alvnukov/ssh-key-control/internal/agent"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// This audit regression uses an ephemeral key and an in-memory protocol connection.
// It expects a vanished client to cancel its pending approval, without stopping the service.
func TestAuditPeerDisconnectCancelsApproval(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	p := protected.NewProtected(func(ctx context.Context, _ protected.SigningRequest) (bool, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return false, ctx.Err()
	})
	server, client := net.Pipe()
	serviceCtx, stopService := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Serve(serviceCtx, server) }()
	defer func() {
		stopService()
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("service failed to stop during cleanup")
		}
	}()
	key, signer := protectedKey(t)
	peer := sshagent.NewClient(client)
	if err := peer.Add(sshagent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	signDone := make(chan error, 1)
	go func() { _, err := peer.Sign(signer.PublicKey(), []byte("audit cancellation fixture")); signDone <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("approval did not start")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-signDone:
	case <-time.After(time.Second):
		t.Fatal("closed client still waiting for signature")
	}
	select {
	case <-cancelled:
	case <-time.After(500 * time.Millisecond):
		t.Error("client disconnected but approval context remained live; only whole-service cancellation releases it")
	}
}
