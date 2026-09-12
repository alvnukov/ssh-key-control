package cli

import (
	"errors"
	"net"
)

type stoppedListener struct{}

func (stoppedListener) Accept() (net.Conn, error) { return nil, errors.New("test listener stopped") }
func (stoppedListener) Close() error              { return nil }
func (stoppedListener) Addr() net.Addr            { return &net.UnixAddr{Name: "test", Net: "unix"} }
