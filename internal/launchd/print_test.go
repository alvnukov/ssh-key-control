package launchd

import (
	"context"
	"errors"
	"testing"
)

// appleAgent is `launchctl print gui/501/com.openssh.ssh-agent` on macOS 26.
const appleAgent = `gui/501/com.openssh.ssh-agent = {
	active count = 1
	path = /System/Library/LaunchAgents/com.openssh.ssh-agent.plist
	type = LaunchAgent
	state = running

	program = /usr/bin/ssh-agent
	arguments = {
		/usr/bin/ssh-agent
		-l
	}

	inherited environment = {
		SSH_AUTH_SOCK => /var/run/com.apple.launchd.yR1H3s4Jb5/Listeners
	}

	default environment = {
		PATH => /usr/bin:/bin:/usr/sbin:/sbin
	}

	environment = {
		OSLogRateLimit => 64
		MallocSpaceEfficient => 1
		XPC_SERVICE_NAME => com.openssh.ssh-agent
	}

	domain = gui/501 [100025]
	asid = 100025
	minimum runtime = 10
	exit timeout = 5
	runs = 4
	pid = 9183
	immediate reason = ipc (socket)
	forks = 0
	execs = 1
	initialized = 1
	trampolined = 1
	started suspended = 0
	proxy started suspended = 0
	checked allocations = 0 (queried = 1)
	checked allocations reason = no host
	checked allocations flags = 0x0
	last exit code = 2

	sockets = {
		"Listeners" = {
			type = stream
			path = /var/run/com.apple.launchd.yR1H3s4Jb5/Listeners
			secure key = SSH_AUTH_SOCK
			owner uid = 501
			group id = 0

			sockets = {
				10 (bytes to read)
			}

			active = 1
			passive = 1
			bonjour = 0
			ipv4v6 = 0
		}
	}

	event channels = {
		"com.apple.launchd.unmount" = {
			port = 0x0
			active = 0
			managed = 1
			reset = 0
			hide = 0
			watching = 0
		}
	}

	spawn type = daemon (3)
	properties = keepalive | runatload | inferred program | system service | tle system
}
`

func TestParsePrintAppleAgent(t *testing.T) {
	svc, err := ParsePrint(appleAgent)
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != "gui/501/com.openssh.ssh-agent" || svc.Label != "com.openssh.ssh-agent" {
		t.Errorf("name = %q, label = %q", svc.Name, svc.Label)
	}
	if svc.Path != "/System/Library/LaunchAgents/com.openssh.ssh-agent.plist" {
		t.Errorf("path = %q", svc.Path)
	}
	if svc.State != "running" || svc.PID != 9183 || !svc.Running() {
		t.Errorf("state = %q, pid = %d", svc.State, svc.PID)
	}
	if len(svc.Arguments) != 2 || svc.Arguments[0] != "/usr/bin/ssh-agent" || svc.Arguments[1] != "-l" {
		t.Errorf("arguments = %q", svc.Arguments)
	}
	if svc.InheritedEnvironment["SSH_AUTH_SOCK"] != "/var/run/com.apple.launchd.yR1H3s4Jb5/Listeners" {
		t.Errorf("inherited environment = %v", svc.InheritedEnvironment)
	}
	if svc.Environment["XPC_SERVICE_NAME"] != "com.openssh.ssh-agent" || len(svc.Environment) != 3 {
		t.Errorf("environment = %v", svc.Environment)
	}
	sock, ok := svc.Sockets["Listeners"]
	if !ok || sock.Path != "/var/run/com.apple.launchd.yR1H3s4Jb5/Listeners" || sock.SecureKey != "SSH_AUTH_SOCK" {
		t.Errorf("sockets = %+v", svc.Sockets)
	}
	if svc.LastExitCode != "2" {
		t.Errorf("last exit code = %q", svc.LastExitCode)
	}
}

func TestParsePrintNotRunning(t *testing.T) {
	svc, err := ParsePrint("gui/501/x = {\n\tstate = not running\n\tpath = /p\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	if svc.Running() || svc.State != "not running" || svc.PID != 0 {
		t.Errorf("%+v", svc)
	}
	if svc.Sockets == nil || svc.Environment == nil || svc.InheritedEnvironment == nil {
		t.Error("maps must not be nil")
	}
}

func TestParsePrintGarbage(t *testing.T) {
	if _, err := ParsePrint("Could not find service"); err == nil {
		t.Error("expected an error")
	}
	if _, err := ParsePrint("a = {\n}\nb = {\n}\n"); err == nil {
		t.Error("expected an error for two services")
	}
}

// script is a Runner that answers from a table keyed by the joined arguments.
type script struct {
	answers map[string]string
	errors  map[string]error
	calls   []string
}

func (s *script) Run(_ context.Context, args ...string) (string, error) {
	key := joinArgs(args)
	s.calls = append(s.calls, key)
	if err, ok := s.errors[key]; ok {
		return "", err
	}
	return s.answers[key], nil
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}

func TestClient(t *testing.T) {
	s := &script{
		answers: map[string]string{
			"getenv SSH_AUTH_SOCK":                "/tmp/sock\n",
			"getenv NOPE":                         "\n",
			"print gui/501/com.openssh.ssh-agent": appleAgent,
		},
		errors: map[string]error{
			"print gui/501/missing":   &ExitError{Args: []string{"print"}, Code: 113, Output: "Could not find service"},
			"bootout gui/501/missing": &ExitError{Args: []string{"bootout"}, Code: 3, Output: "No such process"},
			"bootout gui/501/slow":    &ExitError{Args: []string{"bootout"}, Code: 36},
			"bootout gui/501/broken":  &ExitError{Args: []string{"bootout"}, Code: 1},
		},
	}
	c := Client{Runner: s, Domain: "gui/501"}
	ctx := context.Background()

	if v, err := c.Getenv(ctx, "SSH_AUTH_SOCK"); err != nil || v != "/tmp/sock" {
		t.Errorf("Getenv = %q, %v", v, err)
	}
	if v, err := c.Getenv(ctx, "NOPE"); err != nil || v != "" {
		t.Errorf("Getenv unset = %q, %v", v, err)
	}
	if _, err := c.Print(ctx, "missing"); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Print missing: %v", err)
	}
	if svc, err := c.Print(ctx, "com.openssh.ssh-agent"); err != nil || svc.PID != 9183 {
		t.Errorf("Print: %+v, %v", svc, err)
	}
	if err := c.Bootout(ctx, "missing"); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Bootout missing: %v", err)
	}
	if err := c.Bootout(ctx, "slow"); err != nil {
		t.Errorf("Bootout in progress: %v", err)
	}
	var exit *ExitError
	if err := c.Bootout(ctx, "broken"); !errors.As(err, &exit) || exit.Code != 1 {
		t.Errorf("Bootout broken: %v", err)
	}
	if err := c.Setenv(ctx, "K", "v"); err != nil {
		t.Error(err)
	}
	if err := c.Unsetenv(ctx, "K"); err != nil {
		t.Error(err)
	}
	if err := c.Bootstrap(ctx, "/p.plist"); err != nil {
		t.Error(err)
	}
	want := []string{
		"getenv SSH_AUTH_SOCK", "getenv NOPE",
		"print gui/501/missing", "print gui/501/com.openssh.ssh-agent",
		"bootout gui/501/missing", "bootout gui/501/slow", "bootout gui/501/broken",
		"setenv K v", "unsetenv K", "bootstrap gui/501 /p.plist",
	}
	if len(s.calls) != len(want) {
		t.Fatalf("calls = %q", s.calls)
	}
	for i := range want {
		if s.calls[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, s.calls[i], want[i])
		}
	}
}

func TestExitError(t *testing.T) {
	e := &ExitError{Args: []string{"bootout", "gui/501/x"}, Code: 3, Output: "No such process"}
	if e.Error() != "launchctl bootout gui/501/x: exit status 3: No such process" {
		t.Errorf("%q", e.Error())
	}
}

func TestExecRunner(t *testing.T) {
	ctx := context.Background()
	out, err := ExecRunner{Path: "/bin/echo"}.Run(ctx, "hello")
	if err != nil || out != "hello\n" {
		t.Errorf("echo: %q, %v", out, err)
	}
	_, err = ExecRunner{Path: "/bin/sh"}.Run(ctx, "-c", "echo oops >&2; exit 7")
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 7 || exit.Output != "oops" {
		t.Errorf("sh: %v", err)
	}
	if _, err := (ExecRunner{Path: "/nonexistent"}).Run(ctx, "x"); err == nil {
		t.Error("expected an error for a missing binary")
	}
}

func TestUserDomain(t *testing.T) {
	d := UserDomain()
	if len(d) < 5 || d[:4] != "gui/" {
		t.Errorf("UserDomain = %q", d)
	}
	if d.Service("a.b") != string(d)+"/a.b" {
		t.Errorf("Service = %q", d.Service("a.b"))
	}
}
