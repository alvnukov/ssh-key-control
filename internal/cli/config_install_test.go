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

func TestConfigMigrationRequiresExplicitCommandAndContinuesSetup(t *testing.T) {
	h := newHarness(t)
	const appExecutable = "/Applications/SSH Key Control.app/Contents/MacOS/ssh-key-control"
	const menuExecutable = "/Applications/SSH Key Control.app/Contents/MacOS/ssh-key-control-menubar"
	h.app.Executable = func() (string, error) { return appExecutable, nil }
	h.app.FS.(*memFS).files[menuExecutable] = true
	h.launchd.Program = appExecutable
	h.launchd.CompanionProgram = menuExecutable
	old := []byte("# BEGIN ssh-askpass managed config\nAddKeysToAgent confirm\n# END ssh-askpass managed config\nHost example.invalid\n  Port 2222\n")
	if err := os.WriteFile(h.app.SSHConfig, old, 0640); err != nil {
		t.Fatal(err)
	}

	if code := h.run("config-migration", "--json"); code != ExitOK || !strings.Contains(h.out.String(), `"state":"legacy"`) {
		t.Fatalf("preflight: %d out=%s err=%s", code, h.out.String(), h.err.String())
	}
	if got, err := os.ReadFile(h.app.SSHConfig); err != nil || !bytes.Equal(got, old) {
		t.Fatalf("preflight changed config: %v", err)
	}
	if len(h.launchd.Calls) != 0 {
		t.Fatalf("preflight touched launchd: %v", h.launchd.Calls)
	}

	if code := h.run("migrate-config"); code != ExitOK {
		t.Fatalf("migrate: %d: %s", code, h.err.String())
	}
	got, err := os.ReadFile(h.app.SSHConfig)
	if err != nil || !bytes.HasSuffix(got, []byte("Host example.invalid\n  Port 2222\n")) {
		t.Fatalf("migration lost user directives: %v", err)
	}
	if backup, err := os.ReadFile(h.app.SSHConfig + ".ssh-key-control.migration.bak"); err != nil || !bytes.Equal(backup, old) {
		t.Fatalf("migration backup: %v", err)
	}
	if !strings.Contains(h.out.String(), "Backup retained") {
		t.Fatalf("success omitted backup: %s", h.out.String())
	}
}

func TestConfigMigrationKeepsUnknownPrefixFailClosed(t *testing.T) {
	h := newHarness(t)
	original := []byte("# BEGIN other-tool managed config\nAddKeysToAgent confirm\n# END other-tool managed config\nHost *\n")
	if err := os.WriteFile(h.app.SSHConfig, original, 0600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("config-migration", "--json"); code != ExitOK || !strings.Contains(h.out.String(), `"state":"unknown"`) {
		t.Fatalf("preflight: %d out=%s err=%s", code, h.out.String(), h.err.String())
	}
	if code := h.run("migrate-config"); code != ExitFailure {
		t.Fatalf("unknown migration returned %d", code)
	}
	if got, err := os.ReadFile(h.app.SSHConfig); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("unknown prefix changed: %v", err)
	}
	if len(h.launchd.Calls) != 0 {
		t.Fatalf("unknown migration touched launchd: %v", h.launchd.Calls)
	}
}
