package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallAutomaticallyConfiguresConfirmation(t *testing.T) {
	h := newHarness(t)
	original := []byte("# user's settings\nHost *\n    AddKeysToAgent no\n    AddKeysToAgent confirm\nHost example.invalid\n    Port 2222\n")
	if err := os.WriteFile(h.app.SSHConfig, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("install"); code != ExitOK {
		t.Fatalf("install: %d: %s", code, h.err.String())
	}
	data, err := os.ReadFile(h.app.SSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(data, original) || !bytes.HasSuffix(data, original) {
		t.Fatalf("install must prepend confirmation without changing existing settings:\n%s", data)
	}
	backup, err := os.ReadFile(h.app.SSHConfig + ".ssh-key-control.bak")
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatalf("original backup: %q, %v", backup, err)
	}
	link := filepath.Join(filepath.Dir(h.app.SSHConfig), "ssh-key-control.sock")
	if got, err := os.Readlink(link); err != nil || got != h.launchd.Socket {
		t.Fatalf("install did not publish stable socket: %q, %v", got, err)
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal("ssh is needed to verify effective configuration")
	}
	out, err := exec.Command(ssh, "-G", "-F", h.app.SSHConfig, "example.invalid").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "identityagent "+link+"\n") || !strings.Contains(string(out), "addkeystoagent confirm\n") || !strings.Contains(string(out), "port 2222\n") {
		t.Fatalf("confirmation or host settings not effective:\n%s", out)
	}
	if code := h.run("install"); code != ExitOK {
		t.Fatalf("reinstall: %d: %s", code, h.err.String())
	}
	again, err := os.ReadFile(h.app.SSHConfig)
	if err != nil || !bytes.Equal(again, data) {
		t.Fatalf("reinstall changed config: %v", err)
	}
	addition := []byte("\nHost later.invalid\n    Port 2200\n")
	if err := os.WriteFile(h.app.SSHConfig, append(data, addition...), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("uninstall"); code != ExitOK {
		t.Fatalf("uninstall: %d: %s", code, h.err.String())
	}
	restored, err := os.ReadFile(h.app.SSHConfig)
	if err != nil || !bytes.Equal(restored, append(original, addition...)) {
		t.Fatalf("uninstall lost user settings: %q, %v", restored, err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("uninstall left stable socket link: %v", err)
	}
}

func TestInstallConfigFailureDoesNotTouchAgent(t *testing.T) {
	h := newHarness(t)
	if err := os.Mkdir(h.app.SSHConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if code := h.run("install"); code != ExitFailure {
		t.Fatalf("install with config directory returned %d", code)
	}
	if len(h.launchd.Calls) != 0 {
		t.Fatalf("config failure touched launchd: %v", h.launchd.Calls)
	}
	if !strings.Contains(h.err.String(), "configuring SSH confirmation") {
		t.Fatalf("missing config error: %s", h.err.String())
	}
}

func TestUninstallPreservesEditedManagedSettingsAndAgent(t *testing.T) {
	h := newHarness(t)
	if code := h.run("install"); code != ExitOK {
		t.Fatalf("install: %d: %s", code, h.err.String())
	}
	data, err := os.ReadFile(h.app.SSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(data, []byte("AddKeysToAgent confirm"), []byte("AddKeysToAgent no"), 1)
	if err := os.WriteFile(h.app.SSHConfig, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	h.launchd.Calls = nil
	if code := h.run("uninstall"); code != ExitFailure {
		t.Fatalf("uninstall with edited block returned %d", code)
	}
	if len(h.launchd.Calls) != 0 {
		t.Fatalf("unsafe uninstall touched launchd: %v", h.launchd.Calls)
	}
	got, err := os.ReadFile(h.app.SSHConfig)
	if err != nil || !bytes.Equal(got, edited) {
		t.Fatalf("edited settings changed: %q, %v", got, err)
	}
}
