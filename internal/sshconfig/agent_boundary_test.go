package sshconfig_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alvnukov/ssh-key-control/internal/sshconfig"
)

func TestManagedAgentOverridesStaleEnvironmentAndHostSettings(t *testing.T) {
	dir := t.TempDir()
	included := filepath.Join(dir, "included")
	if err := os.WriteFile(included, []byte("IdentityAgent /unprotected/included.sock\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config")
	original := fmt.Sprintf("Include %q\nHost *\n  IdentityAgent /unprotected/host.sock\n", included)
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	config := sshconfig.ManagedConfig{Path: path}
	if err := config.Install(); err != nil {
		t.Fatal(err)
	}
	// A missing protected socket must not cause configuration to select the
	// stale Apple socket from the environment.
	t.Setenv("SSH_AUTH_SOCK", "/unprotected/apple.sock")
	for _, host := range []string{"example.invalid", "other.invalid"} {
		command := exec.Command("/usr/bin/ssh", "-G", "-F", path, host)
		out, err := command.Output()
		if err != nil {
			t.Fatal(err)
		}
		want := "identityagent " + config.SocketPath()
		if got := agentConfigLine(string(out)); got != want {
			t.Fatalf("%s: agent routing = %q, want %q", host, got, want)
		}
	}
}

func TestSSHCommandLineCanOverrideManagedAgent(t *testing.T) {
	// This is a boundary test, not a promise of system-wide enforcement.
	// A user-owned SSH configuration cannot prevent an explicit client override.
	path := filepath.Join(t.TempDir(), "config")
	if err := (sshconfig.ManagedConfig{Path: path}).Install(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/ssh", "-G", "-F", path,
		"-o", "IdentityAgent=/unprotected/explicit.sock", "example.invalid")
	out, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := agentConfigLine(string(out)); got != "identityagent /unprotected/explicit.sock" {
		t.Fatalf("unexpected OpenSSH precedence: %q", got)
	}
}

func agentConfigLine(config string) string {
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(line, "identityagent ") {
			return line
		}
	}
	return ""
}
