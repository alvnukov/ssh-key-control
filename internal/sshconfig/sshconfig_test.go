package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `# global
AddKeysToAgent confirm
UseKeychain=yes
IdentityAgent "$SSH_AUTH_SOCK"

Host work
    AddKeysToAgent yes
    IdentityAgent ~/.1password/agent.sock
    User = me

Match host *.example.com
	UseKeychain no
	AddKeysToAgent   confirm 1h
	IdentityAgent none
Include ~/.ssh/extra/*
`

func TestParse(t *testing.T) {
	ds, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	want := []Directive{
		{2, "addkeystoagent", "confirm", ""},
		{3, "usekeychain", "yes", ""},
		{4, "identityagent", "$SSH_AUTH_SOCK", ""},
		{6, "host", "work", "Host work"},
		{7, "addkeystoagent", "yes", "Host work"},
		{8, "identityagent", "~/.1password/agent.sock", "Host work"},
		{9, "user", "me", "Host work"},
		{11, "match", "host *.example.com", "Match host *.example.com"},
		{12, "usekeychain", "no", "Match host *.example.com"},
		{13, "addkeystoagent", "confirm 1h", "Match host *.example.com"},
		{14, "identityagent", "none", "Match host *.example.com"},
		{15, "include", "~/.ssh/extra/*", "Match host *.example.com"},
	}
	if len(ds) != len(want) {
		t.Fatalf("got %d directives, want %d: %+v", len(ds), len(want), ds)
	}
	for i := range want {
		if ds[i] != want[i] {
			t.Errorf("directive %d = %+v, want %+v", i, ds[i], want[i])
		}
	}
}

func TestCheck(t *testing.T) {
	ds, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	ws := Check(ds)
	got := make([]string, len(ws))
	for i, w := range ws {
		got[i] = w.String()
	}
	want := []string{
		"UseKeychain yes: ssh takes passphrases from the keychain by itself, so no dialog appears and keys loaded this way are used without confirmation; remove it (line 3)",
		"AddKeysToAgent yes: keys are added to the agent without per-use confirmation; use \"AddKeysToAgent confirm\" (line 7, Host work)",
		"IdentityAgent ~/.1password/agent.sock: ssh talks to that agent instead of the installed one (line 8, Host work)",
		"IdentityAgent none: ssh uses no agent at all here (line 14, Match host *.example.com)",
		"Include ~/.ssh/extra/*: not checked; look there for the same settings (line 15, Match host *.example.com)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("warnings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestCheckClean(t *testing.T) {
	ds, _ := Parse(strings.NewReader("Host *\n  AddKeysToAgent confirm\n  UseKeychain no\n  IdentityAgent SSH_AUTH_SOCK\n"))
	if ws := Check(ds); len(ws) != 0 {
		t.Errorf("unexpected warnings: %v", ws)
	}
}

func TestCheckFile(t *testing.T) {
	dir := t.TempDir()
	if ws, err := CheckFile(filepath.Join(dir, "missing")); err != nil || ws != nil {
		t.Errorf("missing file: %v, %v", ws, err)
	}
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("UseKeychain yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws, err := CheckFile(path)
	if err != nil || len(ws) != 1 || ws[0].Line != 1 {
		t.Errorf("CheckFile: %v, %v", ws, err)
	}
}

func TestDefaultPath(t *testing.T) {
	p, err := DefaultPath()
	if err != nil || !strings.HasSuffix(p, filepath.Join(".ssh", "config")) {
		t.Errorf("%q, %v", p, err)
	}
}
