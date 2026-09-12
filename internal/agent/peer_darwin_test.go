//go:build darwin && cgo

package agent

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNativePeerRejectsUntrustedProcess(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "skc-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	listener, err := net.Listen("unix", filepath.Join(dir, "socket"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if trustedLocalSSH(server) {
		t.Fatal("the Go test process was accepted as Apple's system SSH")
	}
	server.Close()
	if trustedLocalSSH(server) {
		t.Fatal("a closed socket retained local peer trust")
	}
}
