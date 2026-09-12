package cli

import (
	"strings"
	"testing"
)

func TestUninstallDoesNotRequireOrChangeSystemAgentPolicy(t *testing.T) {
	for _, state := range []string{"disabled", "unloaded"} {
		t.Run(state, func(t *testing.T) {
			h := newHarness(t)
			if h.run("install") != ExitOK {
				t.Fatal(h.err.String())
			}
			if state == "disabled" {
				h.launchd.AppleDisabled = true
			} else {
				h.launchd.Apple = ""
			}
			h.launchd.Calls = nil
			if h.run("uninstall") != ExitOK {
				t.Fatal(h.err.String())
			}
			for _, call := range h.launchd.Calls {
				if strings.Contains(call, "com.openssh.ssh-agent") && !strings.HasPrefix(call, "print ") {
					t.Fatalf("changed Apple's service: %s", call)
				}
			}
		})
	}
}
