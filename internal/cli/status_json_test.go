package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestStatusJSONIsAReadOnlyBoundedSummary(t *testing.T) {
	h := newHarness(t)
	h.env["SSH_ASKPASS"] = "not-for-the-ui-output"
	if code := h.app.Run(context.Background(), []string{"status", "--json"}); code != ExitOK {
		t.Fatalf("status: %d %s", code, h.err.String())
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(h.out.String()), &got); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"running", "installed", "pid", "menu_running", "menu_configured", "menu_pid", "menu_executable_available"} {
		if got[field] == nil {
			t.Fatalf("status lacks %q: %v", field, got)
		}
	}
	if len(got) != 7 || string(got["menu_executable_available"]) != "null" {
		t.Fatal(got)
	}
	if h.activations != 0 || len(h.helper.requests) != 0 {
		t.Fatal("status started a signing/UI operation")
	}
}

func TestLifecycleDetectsMissingRegisteredProcessesWithoutMutation(t *testing.T) {
	h := newHarness(t)
	if code := h.run("install"); code != ExitOK {
		t.Fatal(h.err.String())
	}
	h.launchd.Loaded = map[string]string{}
	h.launchd.Calls = nil
	h.out.Reset()
	h.err.Reset()

	if code := h.app.Run(context.Background(), []string{"lifecycle", "--json"}); code != ExitOK {
		t.Fatalf("lifecycle: %d %s", code, h.err.String())
	}
	var got struct {
		Healthy     bool `json:"healthy"`
		AgentReady  bool `json:"agent_ready"`
		MenuManaged bool `json:"menu_managed"`
	}
	if err := json.Unmarshal([]byte(h.out.String()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Healthy || got.AgentReady || got.MenuManaged {
		t.Fatalf("missing login services reported healthy: %+v", got)
	}
	for _, call := range h.launchd.Calls {
		if len(call) >= 9 && (call[:9] == "bootstrap" || call[:7] == "bootout") {
			t.Fatalf("read-only lifecycle check mutated launchd: %q", call)
		}
	}
}

func TestRepairRestoresAllLifecyclePostconditions(t *testing.T) {
	h := newHarness(t)
	const appExecutable = "/Applications/SSH Key Control.app/Contents/MacOS/ssh-key-control"
	const menuExecutable = "/Applications/SSH Key Control.app/Contents/MacOS/ssh-key-control-menubar"
	h.app.Executable = func() (string, error) { return appExecutable, nil }
	h.app.PlistDir = "/Users/me/Library/LaunchAgents"
	h.app.FS.(*memFS).files[menuExecutable] = true
	h.launchd.Program = appExecutable
	h.launchd.CompanionProgram = menuExecutable
	if code := h.app.Run(context.Background(), []string{"repair"}); code != ExitOK {
		t.Fatalf("repair: %d %s\n%s", code, h.err.String(), h.out.String())
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.app.Run(context.Background(), []string{"lifecycle", "--json"}); code != ExitOK {
		t.Fatalf("lifecycle after repair: %d %s", code, h.err.String())
	}
	var got struct {
		Healthy bool `json:"healthy"`
	}
	if err := json.Unmarshal([]byte(h.out.String()), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Healthy {
		t.Fatal("repair returned success without satisfying startup health")
	}
}

func TestRepairReportsFailedPostcondition(t *testing.T) {
	h := newHarness(t)
	const appExecutable = "/Applications/SSH Key Control.app/Contents/MacOS/ssh-key-control"
	const menuExecutable = "/Applications/SSH Key Control.app/Contents/MacOS/ssh-key-control-menubar"
	h.app.Executable = func() (string, error) { return appExecutable, nil }
	h.app.PlistDir = "/Users/me/Library/LaunchAgents"
	h.app.FS.(*memFS).files[menuExecutable] = true
	h.launchd.Program = appExecutable
	h.launchd.CompanionProgram = menuExecutable
	h.launchd.JobExports = false

	if code := h.app.Run(context.Background(), []string{"repair"}); code != ExitFailure {
		t.Fatalf("repair without exported socket returned %d", code)
	}
	if !strings.Contains(h.err.String(), "socket=false") {
		t.Fatalf("repair hid failed postcondition: %s", h.err.String())
	}
}
