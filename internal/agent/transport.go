package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const (
	maxAgentPacketBytes = 256 << 10
	agentIOTimeout      = 5 * time.Second
)

// packetTransport has exactly one socket reader. It keeps watching for EOF
// while ServeAgent is waiting for a human, and bounds frames before allocation.
// One queued request is enough for ordinary serial agent clients. Excess
// pipelining closes the connection rather than retaining an unbounded queue.
type packetTransport struct {
	net.Conn
	ctx     context.Context
	packets chan []byte
	pending []byte
}

func readAgentPacket(conn net.Conn, timeout time.Duration) ([]byte, error) {
	var header [4]byte
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// An idle connection has no deadline. Once a frame starts, it must finish.
	if _, err := io.ReadFull(conn, header[:1]); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, header[1:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxAgentPacketBytes {
		return nil, errors.New("agent: invalid packet size")
	}
	packet := make([]byte, 4+int(size))
	copy(packet, header[:])
	if _, err := io.ReadFull(conn, packet[4:]); err != nil {
		return nil, err
	}
	return packet, nil
}

func (t *packetTransport) receive(cancel context.CancelFunc, done chan<- struct{}) {
	defer close(done)
	defer cancel()
	defer t.Conn.Close()
	for {
		packet, err := readAgentPacket(t.Conn, agentIOTimeout)
		if err != nil {
			return
		}
		select {
		case <-t.ctx.Done():
			return
		case t.packets <- packet:
		default:
			return
		}
	}
}

func (t *packetTransport) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if err := t.ctx.Err(); err != nil {
		return 0, err
	}
	if len(t.pending) == 0 {
		select {
		case <-t.ctx.Done():
			return 0, t.ctx.Err()
		case t.pending = <-t.packets:
		}
	}
	n := copy(dst, t.pending)
	t.pending = t.pending[n:]
	return n, nil
}

func (t *packetTransport) Write(src []byte) (int, error) {
	if err := t.Conn.SetWriteDeadline(time.Now().Add(agentIOTimeout)); err != nil {
		return 0, err
	}
	return t.Conn.Write(src)
}
