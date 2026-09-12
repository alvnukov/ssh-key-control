package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/agent"
	"github.com/alvnukov/ssh-key-control/internal/launchd"
	"github.com/alvnukov/ssh-key-control/internal/launchd/launchdtest"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

// fakeHelper answers dialogs from fields and keeps the keychain in a map.
type fakeHelper struct {
	secret   ui.SecretAnswer
	text     string
	confirm  bool
	err      error
	store    map[string]string
	closed   bool
	requests []string
}

func (f *fakeHelper) Secret(_ context.Context, r ui.SecretRequest) (ui.SecretAnswer, error) {
	f.requests = append(f.requests, "secret:"+r.Title)
	return f.secret, f.err
}
func (f *fakeHelper) Text(_ context.Context, r ui.TextRequest) (string, error) {
	f.requests = append(f.requests, "text:"+r.Title)
	return f.text, f.err
}
func (f *fakeHelper) Confirm(_ context.Context, r ui.ConfirmRequest) (bool, error) {
	f.requests = append(f.requests, "confirm:"+r.Title)
	return f.confirm, f.err
}
func (f *fakeHelper) Notify(ctx context.Context, r ui.NotifyRequest) error {
	f.requests = append(f.requests, "notify:"+r.Title)
	<-ctx.Done()
	return nil
}
func (f *fakeHelper) Get(_ context.Context, account string) (string, error) {
	v, ok := f.store[account]
	if !ok {
		return "", ui.ErrNotFound
	}
	return v, nil
}
func (f *fakeHelper) Set(_ context.Context, account, secret string) error {
	f.store[account] = secret
	return nil
}
func (f *fakeHelper) Delete(_ context.Context, account string) error {
	if _, ok := f.store[account]; !ok {
		return ui.ErrNotFound
	}
	delete(f.store, account)
	return nil
}
func (f *fakeHelper) Close() error { f.closed = true; return nil }

type memFS struct{ files map[string]bool }

func (m *memFS) MkdirAll(string, os.FileMode) error { return nil }
func (m *memFS) WriteFile(p string, _ []byte, _ os.FileMode) error {
	m.files[p] = true
	return nil
}
func (m *memFS) Remove(p string) error {
	if !m.files[p] {
		return os.ErrNotExist
	}
	delete(m.files, p)
	return nil
}
func (m *memFS) Stat(p string) (os.FileInfo, error) {
	if !m.files[p] {
		return nil, os.ErrNotExist
	}
	return nil, nil
}

const exe = "/opt/ssh-key-control/bin/ssh-key-control"

type harness struct {
	app         *App
	helper      *fakeHelper
	launchd     *launchdtest.Fake
	env         map[string]string
	out, err    strings.Builder
	activations int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		helper:  &fakeHelper{store: map[string]string{}},
		launchd: launchdtest.New(agent.Label),
		env:     map[string]string{},
	}
	h.launchd.JobExports = true
	h.launchd.Program = exe
	h.app = &App{
		Stdout:       &h.out,
		Stderr:       &h.err,
		Getenv:       func(k string) string { return h.env[k] },
		Version:      "1.2.3",
		Executable:   func() (string, error) { return exe, nil },
		LocateHelper: func() (string, error) { return "/opt/ssh-key-control/libexec/ssh-key-control-ui", nil },
		StartHelper:  func(context.Context, string) (Helper, error) { return h.helper, nil },
		ActivateSocket: func(string) (net.Listener, error) {
			h.activations++
			return stoppedListener{}, nil
		},
		Launchctl: launchd.Client{Runner: h.launchd, Domain: "gui/501"},
		FS:        &memFS{files: map[string]bool{}},
		PlistDir:  "/Users/me/Library/LaunchAgents",
		SSHConfig: filepath.Join(t.TempDir(), "config"),
		Sleep:     func(time.Duration) {},
	}
	return h
}

func (h *harness) run(args ...string) int {
	h.out.Reset()
	h.err.Reset()
	return h.app.Run(context.Background(), args)
}

func TestUsage(t *testing.T) {
	h := newHarness(t)
	if code := h.run(); code != ExitUsage || !strings.Contains(h.err.String(), "usage:") {
		t.Errorf("no args: %d, %q", code, h.err.String())
	}
	if code := h.run("a", "b"); code != ExitUsage {
		t.Errorf("two stray args: %d", code)
	}
	if code := h.run("--bogus"); code != ExitUsage {
		t.Errorf("unknown flag: %d", code)
	}
	if code := h.run("status", "extra"); code != ExitUsage || !strings.Contains(h.err.String(), "takes no arguments") {
		t.Errorf("status extra: %d, %q", code, h.err.String())
	}
	if code := h.run("help"); code != ExitOK || !strings.Contains(h.out.String(), "usage:") {
		t.Errorf("help: %d", code)
	}
	if code := h.run("version"); code != ExitOK || h.out.String() != "ssh-key-control 1.2.3\n" {
		t.Errorf("version: %d, %q", code, h.out.String())
	}
	if code := h.run("--version"); code != ExitOK || h.out.String() != "ssh-key-control 1.2.3\n" {
		t.Errorf("--version: %d, %q", code, h.out.String())
	}
}

func TestAskpassPassphrase(t *testing.T) {
	h := newHarness(t)
	h.helper.secret = ui.SecretAnswer{Secret: "hunter2", Remember: true}
	code := h.run("Enter passphrase for key '/Users/me/.ssh/id_ed25519': ")
	if code != ExitOK || h.out.String() != "hunter2\n" {
		t.Errorf("code %d, out %q, err %q", code, h.out.String(), h.err.String())
	}
	if h.helper.store["/Users/me/.ssh/id_ed25519"] != "hunter2" {
		t.Errorf("not remembered: %v", h.helper.store)
	}
	if !h.helper.closed {
		t.Error("helper not closed")
	}
	// Second time the keychain answers and no dialog appears; the key file
	// does not exist so the passphrase cannot be checked and is trusted.
	h.helper.requests = nil
	if code := h.run("Enter passphrase for key '/Users/me/.ssh/id_ed25519': "); code != ExitOK || h.out.String() != "hunter2\n" {
		t.Errorf("second: %d, %q", code, h.out.String())
	}
	if len(h.helper.requests) != 0 {
		t.Errorf("dialog shown despite keychain: %v", h.helper.requests)
	}
}

func TestAskpassCancelled(t *testing.T) {
	h := newHarness(t)
	h.helper.err = ui.ErrCancelled
	if code := h.run("Enter passphrase for key '/k': "); code != ExitFailure || h.out.String() != "" || h.err.String() != "" {
		t.Errorf("code %d, out %q, err %q", code, h.out.String(), h.err.String())
	}
}

func TestAskpassConfirm(t *testing.T) {
	h := newHarness(t)
	h.env["SSH_ASKPASS_PROMPT"] = "confirm"
	h.helper.confirm = true
	if code := h.run("Allow use of key /k?\nKey fingerprint SHA256:abc."); code != ExitOK || h.out.String() != "yes\n" {
		t.Errorf("allow: %d, %q", code, h.out.String())
	}
	h.helper.confirm = false
	if code := h.run("Allow use of key /k?"); code != ExitFailure || h.out.String() != "" {
		t.Errorf("deny: %d, %q", code, h.out.String())
	}
}

func TestAskpassNotify(t *testing.T) {
	h := newHarness(t)
	h.env["SSH_ASKPASS_PROMPT"] = "none"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- h.app.Run(ctx, []string{"Confirm user presence for key ED25519-SK SHA256:x"}) }()
	select {
	case code := <-done:
		t.Fatalf("returned early with %d", code)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	if code := <-done; code != ExitOK || h.out.String() != "" {
		t.Errorf("code %d, out %q", code, h.out.String())
	}
}

func TestAskpassHelperFailures(t *testing.T) {
	h := newHarness(t)
	h.app.LocateHelper = func() (string, error) { return "", errors.New("no helper") }
	if code := h.run("x: "); code != ExitFailure || !strings.Contains(h.err.String(), "no helper") {
		t.Errorf("locate: %d, %q", code, h.err.String())
	}
	h.app.LocateHelper = func() (string, error) { return "/h", nil }
	h.app.StartHelper = func(context.Context, string) (Helper, error) { return nil, errors.New("cannot start") }
	if code := h.run("x: "); code != ExitFailure || !strings.Contains(h.err.String(), "cannot start") {
		t.Errorf("start: %d, %q", code, h.err.String())
	}
}

func TestInstallStatusUninstall(t *testing.T) {
	h := newHarness(t)
	if code := h.run("install"); code != ExitOK {
		t.Fatalf("install: %d, %q", code, h.err.String())
	}
	out := h.out.String()
	for _, want := range []string{"is running (pid 4242)", "Quit and reopen your terminal", "SSH key confirmation configured", "AddKeysToAgent confirm", "No manual SSH configuration or ssh-add step is needed"} {
		if !strings.Contains(out, want) {
			t.Errorf("install output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Warning") {
		t.Errorf("unexpected warning:\n%s", out)
	}
	if h.launchd.Loaded[agent.Label] != "/Users/me/Library/LaunchAgents/io.github.alvnukov.ssh-key-control.plist" {
		t.Errorf("loaded = %v", h.launchd.Loaded)
	}

	h.launchd.Env["SSH_ASKPASS"] = exe
	if code := h.run("status"); code != ExitOK {
		t.Fatalf("status: %d, %q", code, h.err.String())
	}
	out = h.out.String()
	for _, want := range []string{"plist:    /Users/me/Library/LaunchAgents/io.github.alvnukov.ssh-key-control.plist (present)", "service:  running, pid 4242", "program:  " + exe, "socket:   " + h.launchd.Socket, "SSH_AUTH_SOCK        " + h.launchd.Socket, "SSH_ASKPASS          " + exe, "SSH_ASKPASS_REQUIRE  -"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}

	if code := h.run("uninstall"); code != ExitOK || !strings.Contains(h.out.String(), "removed") {
		t.Fatalf("uninstall: %d, %q %q", code, h.out.String(), h.err.String())
	}
	if len(h.launchd.Loaded) != 0 || h.launchd.Env["SSH_AUTH_SOCK"] != h.launchd.Apple {
		t.Errorf("after uninstall: loaded %v env %v", h.launchd.Loaded, h.launchd.Env)
	}
	if code := h.run("status"); code != ExitOK || !strings.Contains(h.out.String(), "service:  not loaded") || !strings.Contains(h.out.String(), "(missing)") {
		t.Errorf("status after uninstall: %d\n%s", code, h.out.String())
	}
}

func TestInstallOptions(t *testing.T) {
	h := newHarness(t)
	if code := h.run("install", "--require", "never"); code != ExitUsage {
		t.Errorf("bad require: %d", code)
	}
	if code := h.run("install", "--nope"); code != ExitUsage {
		t.Errorf("bad flag: %d", code)
	}
	if code := h.run("install", "--require=prefer"); code != ExitOK {
		t.Fatalf("prefer: %d, %q", code, h.err.String())
	}
	h.app.LocateHelper = func() (string, error) { return "", errors.New("helper missing") }
	if code := h.run("install"); code != ExitFailure || !strings.Contains(h.err.String(), "install the helper first") {
		t.Errorf("without helper: %d, %q", code, h.err.String())
	}
	h.app.PlistDir = ""
	if code := h.run("install"); code != ExitFailure || !strings.Contains(h.err.String(), "home directory") {
		t.Errorf("no home: %d, %q", code, h.err.String())
	}
}

func TestInstallWarnsWhenNotExported(t *testing.T) {
	h := newHarness(t)
	h.launchd.JobExports = false
	if code := h.run("install"); code != ExitOK || !strings.Contains(h.out.String(), "Warning") {
		t.Errorf("%d\n%s", code, h.out.String())
	}
}

func TestDoctor(t *testing.T) {
	h := newHarness(t)
	if code := h.run("doctor"); code != ExitFailure {
		t.Errorf("fresh system must fail: %d\n%s", code, h.out.String())
	}
	out := h.out.String()
	for _, want := range []string{"ok    UI helper:", "FAIL  plist missing", "FAIL  launch agent io.github.alvnukov.ssh-key-control is not loaded"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}

	if code := h.run("install"); code != ExitOK {
		t.Fatal(h.err.String())
	}
	h.launchd.Env["SSH_ASKPASS"] = exe
	h.launchd.Env["SSH_ASKPASS_REQUIRE"] = "force"
	if code := h.run("doctor"); code != ExitOK {
		t.Errorf("installed but shell stale should still pass: %d\n%s", code, h.out.String())
	}
	out = h.out.String()
	for _, want := range []string{"ok    launch agent io.github.alvnukov.ssh-key-control is running (pid 4242)", "ok    login session: SSH_AUTH_SOCK is the agent's socket", "warn  this shell: SSH_AUTH_SOCK is -; it was started before the agent", "warn  this shell: SSH_ASKPASS is -", ": nothing in the way"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}

	h.env["SSH_AUTH_SOCK"] = h.launchd.Socket
	h.env["SSH_ASKPASS"] = exe
	if err := os.WriteFile(h.app.SSHConfig, []byte("UseKeychain yes\nHost x\n  AddKeysToAgent yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("doctor"); code != ExitOK {
		t.Errorf("config warnings are not failures: %d", code)
	}
	out = h.out.String()
	for _, want := range []string{"ok    this shell: SSH_AUTH_SOCK is the agent's socket", "warn  " + h.app.SSHConfig + ": UseKeychain yes", "AddKeysToAgent yes: keys are added to the agent without per-use confirmation"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "warn  this shell") {
		t.Errorf("shell warnings must be gone:\n%s", out)
	}

	h.launchd.Env["SSH_AUTH_SOCK"] = "/elsewhere"
	h.app.Executable = func() (string, error) { return "/other/ssh-key-control", nil }
	if code := h.run("doctor"); code != ExitFailure {
		t.Errorf("wrong session socket must fail: %d", code)
	}
	out = h.out.String()
	for _, want := range []string{"FAIL  login session: SSH_AUTH_SOCK is /elsewhere", "warn  the agent runs " + exe + ", this program is /other/ssh-key-control"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}
}

func TestForget(t *testing.T) {
	h := newHarness(t)
	if code := h.run("forget"); code != ExitUsage {
		t.Errorf("no account: %d", code)
	}
	h.helper.store["/k"] = "x"
	if code := h.run("forget", "/k", "/missing"); code != ExitOK {
		t.Errorf("forget: %d, %q", code, h.err.String())
	}
	if h.out.String() != "Forgot /k.\nNothing remembered for /missing.\n" {
		t.Errorf("out = %q", h.out.String())
	}
	if _, ok := h.helper.store["/k"]; ok || !h.helper.closed {
		t.Error("not deleted or helper not closed")
	}
}

func TestAgent(t *testing.T) {
	h := newHarness(t)
	if code := h.run("agent"); code != ExitFailure || !strings.Contains(h.err.String(), agent.SocketKey) {
		t.Errorf("outside launchd: %d, %q", code, h.err.String())
	}
	h.env[agent.SocketKey] = "/sock"
	h.env["SSH_ASKPASS"] = exe
	// The fake listener stops immediately instead of accepting real clients.
	if code := h.run("agent"); code != ExitFailure || h.activations != 1 {
		t.Errorf("agent: %d, activations %d, %q", code, h.activations, h.err.String())
	}
	if h.launchd.Env["SSH_AUTH_SOCK"] != "/sock" || h.launchd.Env["SSH_ASKPASS"] != exe {
		t.Errorf("env = %v", h.launchd.Env)
	}
}

func TestDefault(t *testing.T) {
	a := Default("v")
	if a.Version != "v" || a.PlistDir == "" || a.SSHConfig == "" || a.Launchctl.Domain == "" {
		t.Errorf("%+v", a)
	}
	exe, err := a.Executable()
	if err != nil || !filepath.IsAbs(exe) {
		t.Errorf("Executable = %q, %v", exe, err)
	}
	var out, errOut strings.Builder
	a.Stdout, a.Stderr = &out, &errOut
	if code := a.Run(context.Background(), []string{"version"}); code != ExitOK || out.String() != "ssh-key-control v\n" {
		t.Errorf("version through Default: %d, %q", code, out.String())
	}
}
