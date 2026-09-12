package nativemonitor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type recordingAgent struct {
	agent.Agent
	deny        bool
	fakeSuccess bool
	lists       int
	removes     int
	afterRemove func()
}

func (a *recordingAgent) List() ([]*agent.Key, error) { a.lists++; return a.Agent.List() }
func (a *recordingAgent) Remove(key ssh.PublicKey) error {
	a.removes++
	if a.deny {
		return errors.New("locked")
	}
	if a.fakeSuccess {
		return nil
	}
	err := a.Agent.Remove(key)
	if a.afterRemove != nil {
		a.afterRemove()
	}
	return err
}
func isolated(t *testing.T, a agent.Agent) func(context.Context) (net.Conn, error) {
	t.Helper()
	return func(ctx context.Context) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		client, server := net.Pipe()
		go func() { defer server.Close(); _ = agent.ServeAgent(a, server) }()
		return client, nil
	}
}
func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private
}
func TestNativeMonitorDefaultAndPersistentOptOut(t *testing.T) {
	dir := t.TempDir()
	if p, err := ReadPolicy(dir); err != nil || !p.Enabled {
		t.Fatalf("new default = %+v %v", p, err)
	}
	if err := SavePolicy(dir, Policy{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	connected := false
	monitor := Monitor{Directory: dir, Connect: func(context.Context) (net.Conn, error) { connected = true; return nil, errors.New("unexpected") }}
	monitor.Step(context.Background())
	if connected {
		t.Fatal("disabled monitor connected")
	}
	p, err := ReadPolicy(dir)
	if err != nil || p.Enabled {
		t.Fatal("explicit opt-out was not preserved")
	}
	state, err := ReadState(dir)
	if err != nil || state.Enabled || state.Status != "disabled" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}
func TestNativeMonitorRemovesAndVerifiesEachIdentity(t *testing.T) {
	key := testKey(t)
	ring := &recordingAgent{Agent: agent.NewKeyring()}
	if err := ring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	var events []Event
	monitor := Monitor{Directory: t.TempDir(), Connect: isolated(t, ring), Record: func(e Event) { events = append(events, e) }}
	monitor.Step(context.Background())
	if ring.removes != 1 || ring.lists != 2 {
		t.Fatalf("removes=%d lists=%d", ring.removes, ring.lists)
	}
	if len(events) != 1 || events[0].Outcome != "native_removed" || events[0].Fingerprint == "" {
		t.Fatalf("events=%+v", events)
	}
	if keys, _ := ring.Agent.List(); len(keys) != 0 {
		t.Fatal("key remains")
	}
	monitor.Step(context.Background())
	if len(events) != 1 {
		t.Fatal("empty agent produced duplicate event")
	}
	// A newly loaded copy is a new incident, even with the same fingerprint.
	if err := ring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	monitor.Step(context.Background())
	if len(events) != 2 || monitor.state.Removed != 2 {
		t.Fatal("reload was lost")
	}
}
func TestNativeMonitorFailureIsNotSuccessAndIsDeduplicated(t *testing.T) {
	for _, fakeSuccess := range []bool{false, true} {
		t.Run(map[bool]string{false: "refused", true: "dishonest-success"}[fakeSuccess], func(t *testing.T) {
			ring := &recordingAgent{Agent: agent.NewKeyring(), deny: !fakeSuccess, fakeSuccess: fakeSuccess}
			if err := ring.Add(agent.AddedKey{PrivateKey: testKey(t)}); err != nil {
				t.Fatal(err)
			}
			var events []Event
			m := Monitor{Directory: t.TempDir(), Connect: isolated(t, ring), Record: func(e Event) { events = append(events, e) }}
			m.Step(context.Background())
			m.Step(context.Background())
			if m.state.Removed != 0 || m.state.Failed != 1 || len(events) != 1 || events[0].Outcome != "native_remove_failed" {
				t.Fatalf("state=%+v events=%+v", m.state, events)
			}
			ring.deny = false
			ring.fakeSuccess = false
			m.Step(context.Background())
			if m.state.Removed != 1 || len(events) != 2 || events[1].Outcome != "native_removed" {
				t.Fatal("recovery not recorded")
			}
		})
	}
}
func TestNativeMonitorHonorsOptOutBeforeRemoval(t *testing.T) {
	dir := t.TempDir()
	ring := agent.NewKeyring()
	if err := ring.Add(agent.AddedKey{PrivateKey: testKey(t)}); err != nil {
		t.Fatal(err)
	}
	connect := isolated(t, ring)
	m := Monitor{Directory: dir, Connect: func(ctx context.Context) (net.Conn, error) {
		if err := SavePolicy(dir, Policy{Enabled: false}); err != nil {
			t.Fatal(err)
		}
		return connect(ctx)
	}}
	m.Step(context.Background())
	if keys, _ := ring.List(); len(keys) != 1 {
		t.Fatal("removed after setting was disabled")
	}
}
func TestNativeMonitorBoundedProtocolAndCancellation(t *testing.T) {
	for _, mode := range []string{"oversized", "hang"} {
		t.Run(mode, func(t *testing.T) {
			m := Monitor{Directory: t.TempDir(), Connect: func(context.Context) (net.Conn, error) {
				c, s := net.Pipe()
				go func() {
					defer s.Close()
					req := make([]byte, 5)
					if _, err := io.ReadFull(s, req); err != nil {
						return
					}
					if mode == "oversized" {
						var header [4]byte
						binary.BigEndian.PutUint32(header[:], maxPacket+1)
						_, _ = s.Write(header[:])
					} else {
						_, _ = io.Copy(io.Discard, s)
					}
				}()
				return c, nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			start := time.Now()
			m.Step(ctx)
			if time.Since(start) > time.Second || m.state.Removed != 0 || m.state.Status != "error" {
				t.Fatalf("state=%+v elapsed=%v", m.state, time.Since(start))
			}
		})
	}
}
func TestNativeMonitorRejectsUnsafePolicyFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("{\"enabled\":true}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, PolicyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPolicy(dir); err == nil {
		t.Fatal("accepted symlink")
	}
}
