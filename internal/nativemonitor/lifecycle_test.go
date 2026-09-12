package nativemonitor

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func TestNativeMonitorDoesNotClaimEmptyWhenAnotherKeyAppears(t *testing.T) {
	ring := &recordingAgent{Agent: agent.NewKeyring()}
	if err := ring.Add(agent.AddedKey{PrivateKey: testKey(t)}); err != nil {
		t.Fatal(err)
	}
	other := testKey(t)
	ring.afterRemove = func() { _ = ring.Add(agent.AddedKey{PrivateKey: other}) }
	m := Monitor{Directory: t.TempDir(), Connect: isolated(t, ring)}
	m.Step(context.Background())
	if m.state.Status != "keys_present" || m.state.Removed != 1 {
		t.Fatalf("state=%+v", m.state)
	}
}
func TestNativeMonitorRestartPreservesUndeliveredCountersAndStops(t *testing.T) {
	dir := t.TempDir()
	if err := SaveState(dir, State{Session: "previous", Removed: 2, Failed: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := Monitor{Directory: dir, Connect: func(context.Context) (net.Conn, error) { cancel(); return nil, ErrUnavailable }}
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop")
	}
	state, err := ReadState(dir)
	if err != nil || state.Session != "previous" || state.Removed != 2 || state.Failed != 1 || state.Status != "stopped" {
		t.Fatalf("%+v %v", state, err)
	}
}
