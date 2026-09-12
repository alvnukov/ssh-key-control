package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type fuzzPacketConn struct{ reader *bytes.Reader }

func (c *fuzzPacketConn) Read(p []byte) (int, error)     { return c.reader.Read(p) }
func (*fuzzPacketConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*fuzzPacketConn) Close() error                     { return nil }
func (*fuzzPacketConn) LocalAddr() net.Addr              { return &net.UnixAddr{Name: "fuzz", Net: "unix"} }
func (*fuzzPacketConn) RemoteAddr() net.Addr             { return &net.UnixAddr{Name: "fuzz", Net: "unix"} }
func (*fuzzPacketConn) SetDeadline(time.Time) error      { return nil }
func (*fuzzPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*fuzzPacketConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzAgentPacketParsing(f *testing.F) {
	for _, seed := range [][]byte{{}, {11}, {13}, {17}, {18}, {19}, {22}, {23}, {25}, {27}, {0xff}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 4096 {
			return
		}
		var frame bytes.Buffer
		if err := binary.Write(&frame, binary.BigEndian, uint32(len(payload))); err != nil {
			t.Fatal(err)
		}
		if _, err := frame.Write(payload); err != nil {
			t.Fatal(err)
		}
		// No approver: arbitrary packets must never acquire signing authority.
		protected := NewProtected(nil)
		_ = protected.Serve(context.Background(), &fuzzPacketConn{reader: bytes.NewReader(frame.Bytes())})
	})
}

func FuzzSessionBindingParsing(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 4096 {
			return
		}
		connection := &protectedConnection{owner: NewProtected(nil), ctx: context.Background()}
		_, err := connection.Extension("session-bind@openssh.com", payload)
		if err != nil && !connection.tainted {
			t.Fatal("failed binding left connection eligible for signing")
		}
		if err == nil && (connection.binding == nil || connection.tainted) {
			t.Fatal("successful binding has inconsistent state")
		}
	})
}
