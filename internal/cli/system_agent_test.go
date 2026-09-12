package cli

import (
	"context"
	"strings"
	"testing"
)

func TestSystemAgentDisableRequiresProtectedAgent(t *testing.T) {
	h := newHarness(t)
	if code := h.app.Run(context.Background(), []string{"system-agent", "disable"}); code != ExitFailure {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(h.err.String(), "start the protected") {
		t.Fatal(h.err.String())
	}
	for _, call := range h.launchd.Calls {
		if strings.HasPrefix(call, "disable ") || strings.HasPrefix(call, "bootout ") {
			t.Fatalf("modified system service: %s", call)
		}
	}
	if len(h.helper.requests) != 0 {
		t.Fatal("accessed dialogs or Keychain")
	}
}

func TestSystemAgentRejectsArbitraryActions(t *testing.T) {
	for _, args := range [][]string{{"system-agent"}, {"system-agent", "kill"}, {"system-agent", "disable", "other-service"}} {
		h := newHarness(t)
		if code := h.app.Run(context.Background(), args); code != ExitUsage || len(h.launchd.Calls) != 0 {
			t.Fatalf("%v: exit=%d calls=%v", args, code, h.launchd.Calls)
		}
	}
}
