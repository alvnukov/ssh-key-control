package sshconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedRefusesUnknownManagedPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	original := []byte("# BEGIN previous-product managed config\nAddKeysToAgent confirm\n# END previous-product managed config\nHost *\n  IdentityAgent /old/agent\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	c := ManagedConfig{Path: path}
	if err := c.Install(); err == nil || !strings.Contains(err.Error(), "unknown managed SSH config prefix") {
		t.Fatalf("Install error = %v", err)
	}
	installed, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(installed, original) {
		t.Fatalf("unknown managed config changed: %q, %v", installed, err)
	}
}

func TestCheckNoBeforeConfirm(t *testing.T) {
	ds, err := Parse(strings.NewReader("Host *\nAddKeysToAgent no\nAddKeysToAgent confirm\n"))
	if err != nil {
		t.Fatal(err)
	}
	warnings := Check(ds)
	if len(warnings) != 1 || warnings[0].Line != 2 || !strings.Contains(warnings[0].Text, "not automatically added") {
		t.Fatalf("missed no overriding confirm: %v", warnings)
	}
}
