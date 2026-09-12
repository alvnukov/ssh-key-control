package cli

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/alvnukov/ssh-key-control/internal/nativemonitor"
)

func TestNativeMonitorNeverTargetsProtectedSocketOrAlias(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "skc-monitor-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "agent")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	for _, own := range []string{path, alias} {
		connector := nativeConnector{path: path, protected: []string{own}}
		// Exercise validation directly: no connection or protocol request is sent.
		if _, err := validateNativeEndpoint(connector.path, connector.protected); err == nil {
			t.Fatalf("accepted %s", own)
		}
	}
	if _, err := validateNativeEndpoint(alias, []string{path}); err == nil {
		t.Fatal("accepted symlink destination")
	}
}
func TestNativeMonitorCLISettingsPersist(t *testing.T) {
	h := newHarness(t)
	h.app.HistoryDir = t.TempDir()
	for _, enabled := range []bool{false, true, false} {
		action := "disable"
		if enabled {
			action = "enable"
		}
		if got := h.app.Run(context.Background(), []string{"native-agent-monitor", action}); got != 0 {
			t.Fatalf("exit %d", got)
		}
		p, err := nativemonitor.ReadPolicy(h.app.HistoryDir)
		if err != nil || p.Enabled != enabled {
			t.Fatalf("%+v %v", p, err)
		}
	}
}
