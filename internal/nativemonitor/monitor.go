package nativemonitor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

var ErrUnavailable = errors.New("native SSH agent socket is unavailable")

const interval = time.Second
const operationTimeout = 750 * time.Millisecond
const maxPacket = 256 << 10

type Event struct{ Outcome, Fingerprint string }
type Monitor struct {
	Directory string
	// Connect must identify Apple's endpoint and exclude the protected agent.
	// All List/Remove/verification requests use this one validated connection.
	Connect       func(context.Context) (net.Conn, error)
	Record        func(Event)
	ReportError   func(error)
	state         State
	failures      map[string]bool
	lastPublished time.Time
}

func (m *Monitor) Run(ctx context.Context) {
	m.state = State{Session: time.Now().UTC().Format(time.RFC3339Nano), Status: "disabled"}
	// Preserve notification counters across backend restarts. The menu app may
	// be temporarily stopped while an incident is recorded.
	if previous, err := ReadState(m.Directory); err == nil && previous.Session != "" {
		m.state.Session, m.state.Removed, m.state.Failed = previous.Session, previous.Removed, previous.Failed
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer func() { m.state.Status = "stopped"; m.publish(true) }()
	for {
		if ctx.Err() != nil {
			return
		}
		m.Step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Step is serial; a cancelled or expired operation cannot leave a worker running.
func (m *Monitor) Step(ctx context.Context) {
	if m.state.Session == "" {
		m.state.Session = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if m.failures == nil {
		m.failures = map[string]bool{}
	}
	previous := m.state
	policy, err := ReadPolicy(m.Directory)
	m.state.Enabled = policy.Enabled
	if err != nil {
		m.state.Status = "settings_error"
		m.report(err)
	} else if !policy.Enabled {
		m.state.Status = "disabled"
		clear(m.failures)
	} else {
		m.check(ctx)
	}
	changed := previous.Status != m.state.Status || previous.Enabled != m.state.Enabled || previous.Removed != m.state.Removed || previous.Failed != m.state.Failed
	m.publish(changed)
}
func (m *Monitor) publish(force bool) {
	if !force && time.Since(m.lastPublished) < 5*time.Second {
		return
	}
	m.state.CheckedAt = time.Now().UTC()
	if err := SaveState(m.Directory, m.state); err != nil {
		m.report(err)
		return
	}
	m.lastPublished = time.Now()
}
func (m *Monitor) report(err error) {
	if m.ReportError != nil {
		m.ReportError(err)
	}
}
func (m *Monitor) event(outcome, fp string) {
	if m.Record != nil {
		m.Record(Event{Outcome: outcome, Fingerprint: fp})
	}
}
func (m *Monitor) check(ctx context.Context) {
	op, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	c, err := m.Connect(op)
	if errors.Is(err, ErrUnavailable) {
		m.state.Status = "waiting"
		return
	}
	if err != nil {
		m.failure("")
		return
	}
	defer c.Close()
	stop := context.AfterFunc(op, func() { _ = c.Close() })
	defer stop()
	deadline, _ := op.Deadline()
	if err = c.SetDeadline(deadline); err != nil {
		m.failure("")
		return
	}
	before, err := list(c)
	if err != nil {
		m.failure("")
		return
	}
	delete(m.failures, "")
	m.state.Status = "clear"
	seen := make(map[string]bool, len(before))
	remaining := len(before)
	for _, key := range before {
		fp := ssh.FingerprintSHA256(key)
		seen[fp] = true
		// Re-read the policy immediately before each destructive operation. A
		// concurrently disabled setting must not drain the rest of this batch.
		p, err := ReadPolicy(m.Directory)
		if err != nil || !p.Enabled || op.Err() != nil {
			m.state.Status = "checking"
			return
		}
		// Even success is insufficient: another client can immediately re-add it.
		removed := remove(c, key.Marshal()) == nil
		after, verifyErr := list(c)
		if verifyErr != nil {
			m.failure(fp)
			return
		}
		remaining = len(after)
		remains := false
		for _, current := range after {
			if bytes.Equal(current.Marshal(), key.Marshal()) {
				remains = true
				break
			}
		}
		if !removed || remains {
			m.failure(fp)
			continue
		}
		delete(m.failures, fp)
		m.state.Removed++
		m.event("native_removed", fp)
	}
	if remaining > 0 && m.state.Status == "clear" {
		m.state.Status = "keys_present"
	}
	for fp := range m.failures {
		if fp != "" && !seen[fp] {
			delete(m.failures, fp)
		}
	}
}
func (m *Monitor) failure(fp string) {
	m.state.Status = "error"
	if fp != "" {
		m.state.Status = "removal_failed"
	}
	if m.failures[fp] {
		return
	}
	m.failures[fp] = true
	m.state.Failed++
	outcome := "native_unavailable"
	if fp != "" {
		outcome = "native_remove_failed"
	}
	m.event(outcome, fp)
}
func exchange(c net.Conn, payload []byte) ([]byte, error) {
	if len(payload) > maxPacket {
		return nil, errors.New("agent request too large")
	}
	packet := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(packet, uint32(len(payload)))
	copy(packet[4:], payload)
	n, err := c.Write(packet)
	if err != nil {
		return nil, err
	}
	if n != len(packet) {
		return nil, io.ErrShortWrite
	}
	var header [4]byte
	if _, err = io.ReadFull(c, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxPacket {
		return nil, errors.New("agent response exceeds limit")
	}
	response := make([]byte, int(size))
	_, err = io.ReadFull(c, response)
	return response, err
}
func takeString(data *[]byte) ([]byte, error) {
	if len(*data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	n := binary.BigEndian.Uint32((*data)[:4])
	*data = (*data)[4:]
	if uint64(n) > uint64(len(*data)) {
		return nil, io.ErrUnexpectedEOF
	}
	out := (*data)[:int(n)]
	*data = (*data)[int(n):]
	return out, nil
}
func list(c net.Conn) ([]ssh.PublicKey, error) {
	data, err := exchange(c, []byte{11})
	if err != nil {
		return nil, err
	}
	if len(data) < 5 || data[0] != 12 {
		return nil, errors.New("agent did not list identities")
	}
	n := binary.BigEndian.Uint32(data[1:5])
	data = data[5:]
	if n > 256 {
		return nil, errors.New("too many agent identities")
	}
	result := make([]ssh.PublicKey, 0, int(n))
	for range n {
		blob, err := takeString(&data)
		if err != nil {
			return nil, err
		}
		if _, err = takeString(&data); err != nil {
			return nil, err
		} // Ignore untrusted comments.
		key, err := ssh.ParsePublicKey(blob)
		if err != nil {
			return nil, err
		}
		result = append(result, key)
	}
	if len(data) != 0 {
		return nil, errors.New("trailing agent identities data")
	}
	return result, nil
}
func remove(c net.Conn, blob []byte) error {
	payload := make([]byte, 5+len(blob))
	payload[0] = 18
	binary.BigEndian.PutUint32(payload[1:5], uint32(len(blob)))
	copy(payload[5:], blob)
	data, err := exchange(c, payload)
	if err != nil {
		return err
	}
	if len(data) != 1 || data[0] != 6 {
		return fmt.Errorf("agent refused identity removal")
	}
	return nil
}
