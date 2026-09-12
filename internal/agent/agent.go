// Package agent serves a launchd-owned SSH agent socket. Every signature goes
// through the confirmation gate; clients cannot opt out by omitting -c.
package agent

import (
	"context"
	"fmt"
	"log"

	"github.com/alvnukov/ssh-key-control/internal/launchd"
)

const (
	// Label is the launchd service name.
	Label = "io.github.alvnukov.ssh-key-control"
	// SocketName identifies our launchd-managed listening socket.
	SocketName = "Listeners"
	// SocketKey is the variable launchd exports the socket path under.
	SocketKey = "SSH_KEY_CONTROL_AGENT_SOCKET"
	// Program is Apple's ssh-agent, the only one that understands launchd sockets.
	Program = "/usr/bin/ssh-agent"
	// Command is the subcommand of the askpass executable that launchd runs.
	Command = "agent"
)

// Variables the agent exports to the login session.
const (
	EnvAuthSock = "SSH_AUTH_SOCK"
	EnvAskpass  = "SSH_ASKPASS"
	EnvRequire  = "SSH_ASKPASS_REQUIRE"
)

// Require values for SSH_ASKPASS_REQUIRE that make sense here.
const (
	// RequireForce sends every prompt to the dialog, even from a terminal.
	RequireForce = "force"
	// RequirePrefer uses the dialog only when there is no terminal, and for
	// the agent's own confirmations, which never have one.
	RequirePrefer = "prefer"
)

// ValidRequire reports whether value is a supported SSH_ASKPASS_REQUIRE setting.
func ValidRequire(value string) bool {
	return value == RequireForce || value == RequirePrefer
}

// Job describes the launch agent for the askpass executable at exe.
func Job(exe, require string) launchd.Job {
	return launchd.Job{
		Label:            Label,
		ProgramArguments: []string{exe, Command},
		RunAtLoad:        true,
		KeepAlive:        true,
		ThrottleInterval: 10,
		// This Go service does not participate in libproc transactions.
		EnvironmentVariables: map[string]string{
			EnvAskpass: exe,
			EnvRequire: require,
		},
		SecureSocket: &launchd.SecureSocket{Name: SocketName, Key: SocketKey},
	}
}

// Runtime is what Run needs from the process it runs in.
type Runtime struct {
	// SocketLink is the stable IdentityAgent path; empty disables publication.
	SocketLink string
	// Getenv reads the process environment (os.Getenv).
	Getenv func(key string) string
	// Serve runs the protected signing service. It is mandatory: there is no
	// fallback to an unprotected agent if service setup fails.
	Serve func(context.Context) error
	// Launchctl sets variables in the login session.
	Launchctl launchd.Client
	Log       *log.Logger
}

// Run publishes the launchd socket and serves the protected agent in this process.
func Run(ctx context.Context, rt Runtime) error {
	if rt.Serve == nil {
		return fmt.Errorf("protected signing service is required")
	}
	socket := rt.Getenv(SocketKey)
	if socket == "" {
		return fmt.Errorf("%s is not set: this command is meant to be run by launchd from the %s job", SocketKey, Label)
	}
	if rt.SocketLink != "" {
		if err := PublishSocket(rt.SocketLink, socket); err != nil {
			return fmt.Errorf("publishing SSH agent socket: %w", err)
		}
	}
	exports := map[string]string{EnvAuthSock: socket}
	for _, key := range []string{EnvAskpass, EnvRequire} {
		if v := rt.Getenv(key); v != "" {
			exports[key] = v
		}
	}
	// A failed setenv is logged but never stops the agent: an agent without
	// the variables still serves keys, which beats no agent at all.
	for _, key := range []string{EnvAuthSock, EnvAskpass, EnvRequire} {
		v, ok := exports[key]
		if !ok {
			continue
		}
		if err := rt.Launchctl.Setenv(ctx, key, v); err != nil {
			rt.Log.Printf("launchctl setenv %s failed: %v", key, err)
		}
	}
	return rt.Serve(ctx)
}
