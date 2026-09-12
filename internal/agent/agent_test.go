package agent

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/alvnukov/ssh-key-control/internal/launchd"
)

type recorder struct {
	calls []string
	fail  map[string]error
}

func (r *recorder) Run(_ context.Context, args ...string) (string, error) {
	key := strings.Join(args, " ")
	r.calls = append(r.calls, key)
	return "", r.fail[key]
}

func runtimeWith(env map[string]string, rec *recorder, serve func(context.Context) error) Runtime {
	return Runtime{
		Getenv:    func(k string) string { return env[k] },
		Serve:     serve,
		Launchctl: launchd.Client{Runner: rec, Domain: "gui/501"},
		Log:       log.New(io.Discard, "", 0),
	}
}

func TestRunExportsAndServes(t *testing.T) {
	rec := &recorder{}
	served := false
	serve := func(context.Context) error {
		served = true
		return nil
	}
	env := map[string]string{
		SocketKey:  "/private/tmp/launchd-x/Listeners",
		EnvAskpass: "/usr/local/bin/ssh-key-control",
		EnvRequire: "force",
	}
	err := Run(context.Background(), runtimeWith(env, rec, serve))
	if err != nil || !served {
		t.Fatalf("protected service not run: %v", err)
	}
	want := []string{
		"setenv SSH_AUTH_SOCK /private/tmp/launchd-x/Listeners",
		"setenv SSH_ASKPASS /usr/local/bin/ssh-key-control",
		"setenv SSH_ASKPASS_REQUIRE force",
	}
	if strings.Join(rec.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("launchctl calls:\n%s", strings.Join(rec.calls, "\n"))
	}
}

func TestRunWithoutSocket(t *testing.T) {
	rec := &recorder{}
	execCalled := false
	err := Run(context.Background(), runtimeWith(map[string]string{}, rec, func(context.Context) error {
		execCalled = true
		return nil
	}))
	if err == nil || !strings.Contains(err.Error(), SocketKey) {
		t.Errorf("error = %v", err)
	}
	if execCalled || len(rec.calls) != 0 {
		t.Error("nothing must happen without a launchd socket")
	}
}

func TestRunSkipsUnsetVariablesAndSurvivesSetenvFailure(t *testing.T) {
	rec := &recorder{fail: map[string]error{"setenv SSH_AUTH_SOCK /s": errors.New("boom")}}
	var logged strings.Builder
	execErr := errors.New("protected service failed")
	rt := runtimeWith(map[string]string{SocketKey: "/s"}, rec, func(context.Context) error { return execErr })
	rt.Log = log.New(&logged, "", 0)
	err := Run(context.Background(), rt)
	if !errors.Is(err, execErr) {
		t.Errorf("error = %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0] != "setenv SSH_AUTH_SOCK /s" {
		t.Errorf("calls = %q", rec.calls)
	}
	if !strings.Contains(logged.String(), "boom") {
		t.Errorf("setenv failure not logged: %q", logged.String())
	}
}

func TestJob(t *testing.T) {
	j := Job("/opt/bin/ssh-key-control", RequirePrefer)
	if j.Label != Label || !j.RunAtLoad || !j.KeepAlive || j.KeepAliveOnFailure || j.ThrottleInterval != 10 || j.EnableTransactions {
		t.Errorf("%+v", j)
	}
	if len(j.ProgramArguments) != 2 || j.ProgramArguments[0] != "/opt/bin/ssh-key-control" || j.ProgramArguments[1] != Command {
		t.Errorf("program = %q", j.ProgramArguments)
	}
	if j.EnvironmentVariables[EnvAskpass] != "/opt/bin/ssh-key-control" || j.EnvironmentVariables[EnvRequire] != "prefer" {
		t.Errorf("environment = %v", j.EnvironmentVariables)
	}
	if j.SecureSocket == nil || j.SecureSocket.Name != SocketName || j.SecureSocket.Key != SocketKey {
		t.Errorf("socket = %+v", j.SecureSocket)
	}
	if _, err := j.MarshalPlist(); err != nil {
		t.Error(err)
	}
}

func TestValidRequire(t *testing.T) {
	for v, want := range map[string]bool{"force": true, "prefer": true, "never": false, "": false, "Force": false} {
		if ValidRequire(v) != want {
			t.Errorf("ValidRequire(%q) = %v", v, !want)
		}
	}
}
