package agent

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestPacketSizeRejectedBeforeBody(t *testing.T) {
	for _, size := range []uint32{0, maxAgentPacketBytes + 1, 0xffffffff} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { defer server.Close(); _, err := readAgentPacket(server, time.Second); done <- err }()
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		if _, err := client.Write(header[:]); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil {
			t.Fatal("invalid frame accepted")
		}
		client.Close()
	}
}

func TestPacketFragmentationAndIdleConnection(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		packet, err := readAgentPacket(server, 20*time.Millisecond)
		if err == nil && string(packet) != "\x00\x00\x00\x02\x0b\x01" {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	// The frame deadline must not apply to a connection with no request yet.
	time.Sleep(40 * time.Millisecond)
	for _, b := range []byte{0, 0, 0, 2, 11, 1} {
		if _, err := client.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestIncompletePacketTimesOut(t *testing.T) {
	for _, fragment := range [][]byte{{0}, {0, 0, 0, 2, 11}} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { defer server.Close(); _, err := readAgentPacket(server, 20*time.Millisecond); done <- err }()
		if _, err := client.Write(fragment); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				t.Fatalf("want timeout, got %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("incomplete packet retained connection")
		}
		client.Close()
	}
}

func TestExcessPipeliningClosesConnection(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport := &packetTransport{Conn: server, ctx: ctx, packets: make(chan []byte, 1)}
	done := make(chan struct{})
	go transport.receive(cancel, done)
	// No consumer: one frame may queue; a second must close the connection.
	for range 2 {
		if _, err := client.Write([]byte{0, 0, 0, 1, 11}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unbounded pipeline")
	}
	if ctx.Err() == nil {
		t.Fatal("pipeline overflow did not cancel confirmation")
	}
}
