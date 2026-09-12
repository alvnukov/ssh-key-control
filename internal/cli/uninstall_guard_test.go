package cli

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestUninstallRequiresSystemAgentRestoration(t *testing.T) {
	for _, failure := range []string{"disabled", "unloaded", "unknown"} {
		t.Run(failure, func(t *testing.T) {
			h := newHarness(t)
			if h.run("install") != ExitOK {
				t.Fatal(h.err.String())
			}
			original, err := os.ReadFile(h.app.SSHConfig)
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "disabled":
				h.launchd.AppleDisabled = true
			case "unloaded":
				h.launchd.Apple = ""
			case "unknown":
				h.launchd.Fail["print-disabled gui/501"] = errors.New("cannot read startup policy")
			}
			h.launchd.Calls = nil
			if h.run("uninstall") != ExitFailure {
				t.Fatal("removed protected setup before confirming system agent restoration")
			}
			after, err := os.ReadFile(h.app.SSHConfig)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("modified SSH routing on failed preflight")
			}
			for _, call := range h.launchd.Calls {
				if strings.HasPrefix(call, "bootout ") || strings.HasPrefix(call, "unsetenv ") {
					t.Fatalf("modified launchd on failed preflight: %s", call)
				}
			}
		})
	}
}
