// Package launchdtest is a scripted stand-in for launchctl, for tests of the
// packages that drive it. It models just enough: the domain environment, one
// loadable service with a launchd-created socket, and Apple's ssh-agent.
package launchdtest

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/alvnukov/ssh-key-control/internal/launchd"
)

// Fake implements launchd.Runner.
type Fake struct {
	// Env is the domain environment.
	Env map[string]string
	// Loaded maps a loaded label to the plist it came from.
	Loaded map[string]string
	// Label is the service the fake models; any other label is unknown.
	Label string
	// Socket is the path launchd "creates" for the service's Listeners socket.
	Socket string
	// StartsIn is how many print calls report "waiting" after a bootstrap.
	StartsIn int
	// JobExports makes the job set SSH_AUTH_SOCK once it starts, like the real agent does.
	JobExports bool
	// Apple is the socket of com.openssh.ssh-agent; "" means it is not loaded.
	Apple string
	// AppleDisabled is the persistent per-user startup policy.
	AppleDisabled bool
	// Program is what print reports as the job's executable.
	Program string
	// CompanionProgram overrides Program for non-agent jobs.
	CompanionProgram string
	// Fail maps a joined argument list to the error it should produce.
	Fail map[string]error
	// Calls records every invocation as a joined argument list.
	Calls []string

	prints int
}

// New returns a fake with Apple's agent loaded and nothing else.
func New(label string) *Fake {
	return &Fake{
		Env:    map[string]string{},
		Loaded: map[string]string{},
		Label:  label,
		Socket: "/private/tmp/launchd-1/Listeners",
		Apple:  "/private/tmp/com.apple.launchd.x/Listeners",
		Fail:   map[string]error{},
	}
}

// Run implements launchd.Runner.
func (f *Fake) Run(_ context.Context, args ...string) (string, error) {
	key := strings.Join(args, " ")
	f.Calls = append(f.Calls, key)
	if err := f.Fail[key]; err != nil {
		return "", err
	}
	switch args[0] {
	case "print-disabled":
		return fmt.Sprintf("disabled services = {\n\t\"com.openssh.ssh-agent\" => %t\n}\n", f.AppleDisabled), nil
	case "setenv":
		f.Env[args[1]] = args[2]
	case "unsetenv":
		delete(f.Env, args[1])
	case "getenv":
		return f.Env[args[1]] + "\n", nil
	case "bootstrap":
		label := strings.TrimSuffix(filepath.Base(args[2]), ".plist")
		f.Loaded[label] = args[2]
		f.prints = 0
	case "bootout":
		label := labelOf(args[1])
		if _, ok := f.Loaded[label]; !ok {
			return "", &launchd.ExitError{Args: args, Code: 3, Output: "No such process"}
		}
		delete(f.Loaded, label)
	case "print":
		return f.print(args)
	}
	return "", nil
}

func labelOf(service string) string {
	return service[strings.LastIndex(service, "/")+1:]
}

func (f *Fake) print(args []string) (string, error) {
	label := labelOf(args[1])
	if label == "com.openssh.ssh-agent" {
		if f.Apple == "" {
			return "", &launchd.ExitError{Args: args, Code: 113, Output: "Could not find service"}
		}
		return fmt.Sprintf("%s = {\n\tstate = running\n\tpid = 7\n\tsockets = {\n\t\t\"Listeners\" = {\n\t\t\tpath = %s\n\t\t\tsecure key = SSH_AUTH_SOCK\n\t\t}\n\t}\n}\n", args[1], f.Apple), nil
	}
	path, ok := f.Loaded[label]
	if !ok {
		return "", &launchd.ExitError{Args: args, Code: 113, Output: "Could not find service"}
	}
	f.prints++
	state, pid := "waiting", ""
	if f.prints > f.StartsIn {
		state, pid = "running", "\tpid = 4242\n"
		if f.JobExports && f.prints == f.StartsIn+1 { // the job's setenv runs once, at start
			f.Env["SSH_AUTH_SOCK"] = f.Socket
		}
	}
	return fmt.Sprintf("%s = {\n\tpath = %s\n\tstate = %s\n%s\targuments = {\n\t\t%s\n\t\tagent\n\t}\n\tsockets = {\n\t\t\"Listeners\" = {\n\t\t\tpath = %s\n\t\t\tsecure key = SSH_KEY_CONTROL_AGENT_SOCKET\n\t\t}\n\t}\n}\n",
		args[1], path, state, pid, f.program(path, label), f.Socket), nil
}

// program is what the fake reports as the job's executable: the plist path
// with ".plist" dropped stands in, unless Program is set by a test.
func (f *Fake) program(plist, label string) string {
	if label != f.Label && f.CompanionProgram != "" {
		return f.CompanionProgram
	}
	if f.Program != "" {
		return f.Program
	}
	return strings.TrimSuffix(plist, ".plist")
}
