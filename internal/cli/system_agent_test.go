package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alvnukov/ssh-key-control/internal/agent"
)

func TestSystemAgentCommandsCannotChangeStartupPolicy(t *testing.T) {
	for _, action := range []string{"disable", "enable", "kill"} {
		h := newHarness(t)
		if code := h.run("system-agent", action); code != ExitUsage {
			t.Fatalf("%s exit=%d", action, code)
		}
		if len(h.launchd.Calls) != 0 || len(h.helper.requests) != 0 {
			t.Fatal("obsolete action changed the system")
		}
	}
	h := newHarness(t)
	if code := h.run("system-agent", "status"); code != ExitOK {
		t.Fatal(h.err.String())
	}
	for _, call := range h.launchd.Calls {
		if !strings.HasPrefix(call, "print") {
			t.Fatalf("status mutated system: %s", call)
		}
	}
}
func TestAgentIgnoresLegacySystemAgentPreference(t *testing.T) {
	h := newHarness(t)
	h.app.HistoryDir = t.TempDir()
	legacy := filepath.Join(h.app.HistoryDir, "system-agent-policy")
	if err := os.WriteFile(legacy, []byte("disable\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h.env[agent.SocketKey] = "/sock"
	h.env["SSH_ASKPASS"] = exe
	h.app.Run(context.Background(), []string{"agent"})
	for _, call := range h.launchd.Calls {
		if strings.Contains(call, "com.openssh.ssh-agent") && !strings.HasPrefix(call, "print ") {
			t.Fatalf("legacy choice executed: %s", call)
		}
	}
	after, err := os.ReadFile(legacy)
	if err != nil || string(after) != "disable\n" {
		t.Fatal("legacy user data was changed")
	}
}
