package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/ui"
)

// TestMain turns the test binary into a scripted helper when asked to, so the
// client is exercised against a real child process without any Swift.
func TestMain(m *testing.M) {
	if os.Getenv("SSH_KEY_CONTROL_FAKE_HELPER") == "1" {
		fakeHelper()
		return
	}
	os.Exit(m.Run())
}

// fakeHelper answers according to the op and, for keychain ops, an in-memory store.
func fakeHelper() {
	store := map[string]string{}
	in := bufio.NewScanner(os.Stdin)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var req map[string]any
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			fmt.Fprintln(os.Stderr, "bad json:", err)
			os.Exit(2)
		}
		if req["title"] == "raw response" {
			fmt.Fprintln(os.Stdout, req["message"])
			continue
		}
		fmt.Fprintln(os.Stderr, "got", in.Text())
		resp := map[string]any{"ok": true}
		switch req["op"] {
		case "secret":
			if req["title"] == "cancel me" {
				resp = map[string]any{"ok": false, "error": "cancelled"}
				break
			}
			resp["answer"] = "s3cret"
			resp["remember"] = req["remember"] != nil
			if req["title"] == "unexpected scope" {
				resp["scope"] = "day"
			}
		case "text":
			resp["answer"] = "yes"
		case "confirm":
			if req["title"] == "deny me" {
				resp["answer"] = "no"
			} else {
				resp["answer"] = "yes"
			}
			if req["title"] == "legacy" && req["destination"] != nil {
				resp = map[string]any{"ok": false, "error": "legacy requested timed choice"}
			}
			if req["title"] == "forced scope" || req["title"] == "deny me" {
				if scope, ok := req["message"]; ok {
					resp["scope"] = scope
				}
			}
			if req["title"] == "empty scope" {
				resp["scope"] = ""
			}
			if req["title"] == "scoped" {
				if req["destination"] != "alice@production" {
					resp = map[string]any{"ok": false, "error": "missing destination"}
				} else if scope, ok := req["message"]; ok {
					resp["scope"] = scope
				}
			}
		case "notify":
		case "keychain.get":
			v, ok := store[req["account"].(string)]
			if req["account"] == "denied" {
				resp = map[string]any{"ok": false, "error": "denied"}
			} else if !ok {
				resp = map[string]any{"ok": false, "error": "not-found"}
			} else {
				resp["answer"] = v
			}
		case "keychain.set":
			store[req["account"].(string)] = req["secret"].(string)
		case "keychain.delete":
			delete(store, req["account"].(string))
		case "garbage":
			fmt.Fprintln(os.Stdout, "this is not json")
			continue
		case "die":
			fmt.Fprintln(os.Stderr, "helper crashed on purpose")
			os.Exit(3)
		default:
			resp = map[string]any{"ok": false, "error": "unknown op"}
		}
		if err := out.Encode(resp); err != nil {
			os.Exit(2)
		}
	}
}

func start(t *testing.T) *Client {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_KEY_CONTROL_FAKE_HELPER", "1")
	c, err := Start(context.Background(), exe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestDialogs(t *testing.T) {
	c := start(t)
	ctx := context.Background()

	a, err := c.Secret(ctx, ui.SecretRequest{Title: "t", Message: "m", Remember: &ui.RememberOption{Label: "keep"}})
	if err != nil || a.Secret != "s3cret" || !a.Remember {
		t.Errorf("Secret with remember: %+v, %v", a, err)
	}
	a, err = c.Secret(ctx, ui.SecretRequest{Title: "t"})
	if err != nil || a.Secret != "s3cret" || a.Remember {
		t.Errorf("Secret without remember: %+v, %v", a, err)
	}
	if _, err := c.Secret(ctx, ui.SecretRequest{Title: "cancel me"}); !errors.Is(err, ui.ErrCancelled) {
		t.Errorf("cancelled: %v", err)
	}
	if s, err := c.Text(ctx, ui.TextRequest{Title: "host"}); err != nil || s != "yes" {
		t.Errorf("Text: %q, %v", s, err)
	}
	if ok, err := c.Confirm(ctx, ui.ConfirmRequest{Title: "allow me"}); err != nil || !ok {
		t.Errorf("Confirm allow: %v, %v", ok, err)
	}
	if ok, err := c.Confirm(ctx, ui.ConfirmRequest{Title: "deny me"}); err != nil || ok {
		t.Errorf("Confirm deny: %v, %v", ok, err)
	}
}

func TestConfirmScopedChoices(t *testing.T) {
	var dialogs ui.ScopedDialogs = start(t)
	for _, tc := range []struct {
		wire string
		want ui.GrantScope
	}{
		{"once", ui.GrantOnce}, {"5m", ui.Grant5Minutes},
		{"15m", ui.Grant15Minutes}, {"day", ui.GrantDay},
		{"", ui.GrantOnce}, // Older helpers omit scope.
	} {
		t.Run(tc.wire, func(t *testing.T) {
			got, err := dialogs.ConfirmScoped(context.Background(), ui.ConfirmRequest{
				Title: "scoped", Message: tc.wire, Destination: "alice@production",
			})
			if err != nil || got != (ui.Confirmation{Allowed: true, Scope: tc.want}) {
				t.Fatalf("ConfirmScoped = %+v, %v", got, err)
			}
		})
	}
}
func TestConfirmScopedDenialDurations(t *testing.T) {
	var dialogs ui.ScopedDialogs = start(t)
	ctx := context.Background()
	for _, tc := range []struct {
		wire string
		want ui.GrantScope
	}{
		{"deny5m", ui.Deny5Minutes}, {"deny1h", ui.Deny1Hour},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			got, err := dialogs.ConfirmScoped(ctx, ui.ConfirmRequest{
				Title: "deny me", Message: tc.wire, Destination: "alice@production",
			})
			if err != nil || got != (ui.Confirmation{Allowed: false, Scope: tc.want}) {
				t.Fatalf("ConfirmScoped = %+v, %v", got, err)
			}
		})
	}
	// A plain denial carries no scope and stays a one-shot refusal.
	got, err := dialogs.ConfirmScoped(ctx, ui.ConfirmRequest{Title: "deny me", Destination: "alice@production"})
	if err != nil || got != (ui.Confirmation{Allowed: false, Scope: ui.GrantOnce}) {
		t.Fatalf("plain deny = %+v, %v", got, err)
	}
}

func TestConfirmScopedRejectsMismatchedScopes(t *testing.T) {
	var dialogs ui.ScopedDialogs = start(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		title, message, destination string
	}{
		"deny duration on an allowed answer": {title: "forced scope", message: "deny5m"},
		"grant duration on a denied answer":  {title: "deny me", message: "5m"},
		"timed denial without destination":   {title: "deny me", message: "deny1h"},
		"unknown denial scope":               {title: "deny me", message: "bogus", destination: "alice@production"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := dialogs.ConfirmScoped(ctx, ui.ConfirmRequest{
				Title: tc.title, Message: tc.message, Destination: tc.destination,
			})
			if err == nil {
				t.Fatalf("ConfirmScoped = %+v, want error", got)
			}
		})
	}
}

func TestKeychain(t *testing.T) {
	c := start(t)
	ctx := context.Background()
	if _, err := c.Get(ctx, "k"); !errors.Is(err, ui.ErrNotFound) {
		t.Errorf("Get missing: %v", err)
	}
	if _, err := c.Get(ctx, "denied"); !errors.Is(err, ui.ErrDenied) {
		t.Errorf("Get denied: %v", err)
	}
	if err := c.Set(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Get(ctx, "k"); err != nil || v != "v" {
		t.Errorf("Get: %q, %v", v, err)
	}
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "k"); !errors.Is(err, ui.ErrNotFound) {
		t.Errorf("Get after delete: %v", err)
	}
}

func TestNotifyEndsWithContext(t *testing.T) {
	c := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Notify(ctx, ui.NotifyRequest{Title: "touch"}) }()
	select {
	case err := <-done:
		t.Fatalf("Notify returned before the context ended: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Notify did not return after cancel")
	}
	if err := c.Close(); err != nil {
		t.Errorf("helper exit after notify: %v", err)
	}
}

func TestHelperFailures(t *testing.T) {
	c := start(t)
	if _, err := c.call(request{Op: "bogus"}); err == nil || err.Error() != "unknown op" {
		t.Errorf("unknown op: %v", err)
	}
	if _, err := c.call(request{Op: "garbage"}); err == nil || err.Error() != "helper returned an invalid response" {
		t.Errorf("garbage: %v", err)
	}
	_, err := c.call(request{Op: "die"})
	if err == nil || !strings.Contains(err.Error(), "helper crashed on purpose") {
		t.Errorf("crash must surface the helper's stderr: %v", err)
	}
	if err := c.Close(); err == nil {
		t.Error("Close after a crash must report the exit status")
	}
}

func TestStartMissing(t *testing.T) {
	if _, err := Start(context.Background(), "/nonexistent/helper"); err == nil {
		t.Error("expected an error")
	}
}

func TestMapError(t *testing.T) {
	if !errors.Is(mapError("cancelled"), ui.ErrCancelled) || !errors.Is(mapError("not-found"), ui.ErrNotFound) || !errors.Is(mapError("denied"), ui.ErrDenied) {
		t.Error("known errors not mapped")
	}
	if mapError("").Error() == "" || mapError("boom").Error() != "boom" {
		t.Error("unknown errors not passed through")
	}
}

func TestLocate(t *testing.T) {
	t.Setenv(EnvVar, "/explicit/ui")
	if p, err := Locate(); err != nil || p != "/explicit/ui" {
		t.Errorf("env: %q, %v", p, err)
	}
	t.Setenv(EnvVar, "")
	// Next to the executable: the test binary's own directory is not writable
	// in general, so only check that the failure names the variable.
	if _, err := Locate(); err != nil && !strings.Contains(err.Error(), EnvVar) {
		t.Errorf("error must mention %s: %v", EnvVar, err)
	}
}

func TestLocateNextToProgram(t *testing.T) {
	// locateFrom is the part of Locate that depends on the executable path.
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	libexec := filepath.Join(dir, "libexec")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(libexec, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "ssh-key-control")
	if _, err := locateFrom(exe); err == nil {
		t.Error("nothing installed: expected an error")
	}
	if err := os.WriteFile(filepath.Join(libexec, Name), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if p, err := locateFrom(exe); err != nil || p != filepath.Join(libexec, Name) {
		t.Errorf("libexec: %q, %v", p, err)
	}
	if err := os.WriteFile(filepath.Join(bin, Name), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if p, err := locateFrom(exe); err != nil || p != filepath.Join(libexec, Name) {
		t.Errorf("libexec must win: %q, %v", p, err)
	}
	if err := os.Remove(filepath.Join(libexec, Name)); err != nil {
		t.Fatal(err)
	}
	if p, err := locateFrom(exe); err != nil || p != filepath.Join(bin, Name) {
		t.Errorf("same dir: %q, %v", p, err)
	}
}
