// Package cli is the command line of ssh-key-control: the askpass program OpenSSH
// runs, and the commands that install and inspect the launch agent.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/agent"
	"github.com/alvnukov/ssh-key-control/internal/askpass"
	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/history"
	"github.com/alvnukov/ssh-key-control/internal/install"
	"github.com/alvnukov/ssh-key-control/internal/keys"
	"github.com/alvnukov/ssh-key-control/internal/launchd"
	"github.com/alvnukov/ssh-key-control/internal/sshconfig"
	"github.com/alvnukov/ssh-key-control/internal/ui"
	"github.com/alvnukov/ssh-key-control/internal/ui/helper"
)

// Exit statuses. OpenSSH treats anything but 0 as "declined".
const (
	ExitOK      = 0
	ExitFailure = 1
	ExitUsage   = 2
)

// Helper is a running user-interface helper.
type Helper interface {
	ui.Dialogs
	ui.Keychain
	Close() error
}

// App wires the commands to the outside world. Default builds the real one;
// tests replace the pieces.
type App struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Version        string

	// Executable is the absolute, symlink-resolved path of this program.
	Executable func() (string, error)
	// LocateHelper finds the user-interface helper.
	LocateHelper func() (string, error)
	// StartHelper launches it.
	StartHelper func(ctx context.Context, path string) (Helper, error)
	// ActivateSocket acquires the listener owned by launchd, without binding a new socket.
	ActivateSocket func(string) (net.Listener, error)
	// SSHAdd loads private keys into the agent by running OpenSSH's own tool.
	SSHAdd func(ctx context.Context, env, paths []string) (string, error)

	Launchctl  launchd.Client
	FS         install.FS
	PlistDir   string
	SSHConfig  string
	HistoryDir string
	Sleep      func(time.Duration)
}

// Default is the application backed by the real system.
func Default(version string) *App {
	a := &App{
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Getenv:  os.Getenv,
		Version: version,
		Executable: func() (string, error) {
			exe, err := os.Executable()
			if err != nil {
				return "", err
			}
			if resolved, err := filepath.EvalSymlinks(exe); err == nil {
				exe = resolved
			}
			return filepath.Abs(exe)
		},
		LocateHelper: helper.Locate,
		StartHelper: func(ctx context.Context, path string) (Helper, error) {
			return helper.Start(ctx, path)
		},
		ActivateSocket: agent.ActivateSocket,
		SSHAdd:         execSSHAdd,
		Launchctl:      launchd.Client{Runner: launchd.ExecRunner{}, Domain: launchd.UserDomain()},
		FS:             install.OSFS{},
		Sleep:          time.Sleep,
	}
	if home, err := os.UserHomeDir(); err == nil {
		a.HistoryDir = history.DefaultDir(home)
	}
	if dir, err := install.DefaultPlistDir(); err == nil {
		a.PlistDir = dir
	}
	if path, err := sshconfig.DefaultPath(); err == nil {
		a.SSHConfig = path
	}
	return a
}

const usage = `usage: ssh-key-control <prompt>            answer an OpenSSH prompt (run by ssh, not by hand)
       ssh-key-control install [--require force|prefer]
       ssh-key-control uninstall
       ssh-key-control status
       ssh-key-control keys load [key-file...]
       ssh-key-control keys unload [fingerprint...]
       ssh-key-control keys list [--json] [key-file...]
       ssh-key-control system-agent status
       ssh-key-control permissions          open active temporary decisions
       ssh-key-control native-agent-monitor status|disable|enable
       ssh-key-control doctor
       ssh-key-control forget <account>...
       ssh-key-control version

install    register a launch agent that runs ssh-agent with this program as
           its SSH_ASKPASS and exports it to the login session
uninstall  remove the launch agent and return to the system ssh-agent
status     show the agent and the login session's variables
keys       load private keys into the protected agent, list the keys this Mac
           has and which of them the agent holds, or take keys back out of it
doctor     check the installation, this shell and ~/.ssh/config
forget     delete a remembered passphrase (account is the key path or user@host)

--require force   every prompt goes to the dialog, even from a terminal (default)
--require prefer  the dialog only where there is no terminal; agent confirmations always
`

// Run executes args (without the program name) and returns the exit status.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "install":
		return a.exit(a.install(ctx, rest))
	case "uninstall":
		return a.exit(a.uninstall(ctx, rest))
	case "status":
		return a.exit(a.status(ctx, rest))
	case "keys":
		return a.exit(a.keys(ctx, rest))
	case "lifecycle":
		return a.exit(a.lifecycle(ctx, rest))
	case "repair":
		return a.exit(a.repair(ctx, rest))
	case "config-migration":
		return a.exit(a.configMigration(rest))
	case "migrate-config":
		return a.exit(a.migrateConfig(ctx, rest))
	case "stop-menu":
		return a.exit(a.stopMenu(ctx, rest))
	case "permissions":
		return a.exit(a.openTemporaryDecisions(ctx, rest))
	case "native-agent-monitor":
		return a.exit(a.nativeAgentMonitor(rest))
	case "system-agent":
		return a.exit(a.systemAgent(ctx, rest))
	case "doctor":
		return a.doctor(ctx, rest)
	case "forget":
		return a.exit(a.forget(ctx, rest))
	case agent.Command:
		return a.exit(a.agent(ctx, rest))
	case "version", "--version", "-V":
		fmt.Fprintf(a.Stdout, "ssh-key-control %s\n", a.Version)
		return ExitOK
	case "help", "--help", "-h":
		fmt.Fprint(a.Stdout, usage)
		return ExitOK
	}
	if len(args) != 1 || strings.HasPrefix(cmd, "-") {
		fmt.Fprint(a.Stderr, usage)
		return ExitUsage
	}
	return a.askpass(ctx, cmd)
}

// exit turns an error into a status, printing it.
func (a *App) exit(err error) int {
	if err == nil {
		return ExitOK
	}
	var usageErr *usageError
	if errors.As(err, &usageErr) {
		fmt.Fprintf(a.Stderr, "ssh-key-control: %v\n%s", err, usage)
		return ExitUsage
	}
	fmt.Fprintf(a.Stderr, "ssh-key-control: %v\n", err)
	return ExitFailure
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func noArgs(cmd string, args []string) error {
	if len(args) != 0 {
		return &usageError{cmd + " takes no arguments"}
	}
	return nil
}

// askpass answers one OpenSSH prompt through the helper.
func (a *App) askpass(ctx context.Context, prompt string) int {
	p := askpass.Parse(prompt, a.Getenv("SSH_ASKPASS_PROMPT"))
	path, err := a.LocateHelper()
	if err != nil {
		return a.exit(err)
	}
	h, err := a.StartHelper(ctx, path)
	if err != nil {
		return a.exit(err)
	}
	defer h.Close()
	svc := askpass.Service{
		Dialogs:  h,
		Keychain: h,
		Verify:   keys.Verify,
		Log:      log.New(a.Stderr, "ssh-key-control: ", 0),
	}
	answer, err := svc.Answer(ctx, p)
	if errors.Is(err, ui.ErrCancelled) {
		return ExitFailure
	}
	if err != nil {
		return a.exit(err)
	}
	if p.Kind != askpass.Notify {
		fmt.Fprintln(a.Stdout, answer)
	}
	return ExitOK
}

func (a *App) installer() (*install.Installer, error) {
	if a.PlistDir == "" || a.SSHConfig == "" {
		return nil, errors.New("cannot determine the home directory")
	}
	return &install.Installer{
		Launchctl: a.Launchctl, FS: a.FS, PlistDir: a.PlistDir, Sleep: a.Sleep,
		SSHConfig: &sshconfig.ManagedConfig{Path: a.SSHConfig},
	}, nil
}

func (a *App) install(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	require := fs.String("require", agent.RequireForce, "")
	if err := fs.Parse(args); err != nil {
		return &usageError{err.Error()}
	}
	if err := noArgs("install", fs.Args()); err != nil {
		return err
	}
	if !agent.ValidRequire(*require) {
		return &usageError{fmt.Sprintf("--require must be %s or %s", agent.RequireForce, agent.RequirePrefer)}
	}
	if os.Getuid() == 0 && a.Getenv("SUDO_USER") != "" {
		return errors.New("run install as yourself, not under sudo: the agent belongs to your login session")
	}
	inst, err := a.installer()
	if err != nil {
		return err
	}
	exe, err := a.Executable()
	if err != nil {
		return err
	}
	if _, err := a.LocateHelper(); err != nil {
		return fmt.Errorf("%w; install the helper first", err)
	}
	res, err := inst.Install(ctx, exe, *require)
	if err != nil {
		return err
	}
	if err := agent.PublishSocket((sshconfig.ManagedConfig{Path: a.SSHConfig}).SocketPath(), res.Socket); err != nil {
		return fmt.Errorf("publishing SSH agent socket: %w", err)
	}
	fmt.Fprintf(a.Stdout, "Launch agent %s is running (pid %d).\n", agent.Label, res.PID)
	fmt.Fprintf(a.Stdout, "  plist:  %s\n  socket: %s\n", res.PlistPath, res.Socket)
	if res.CompanionManaged {
		fmt.Fprintln(a.Stdout, "The menu bar application is supervised by launchd; crashes restart it and Quit remains deliberate.")
	}
	if !res.Exported {
		fmt.Fprintf(a.Stdout, "\nWarning: the login session's SSH_AUTH_SOCK does not point at the agent yet; `ssh-key-control doctor` shows more.\n")
	}
	fmt.Fprintf(a.Stdout, "SSH key confirmation configured in %s (AddKeysToAgent confirm).\n", a.SSHConfig)
	fmt.Fprint(a.Stdout, `
SSH uses the installed agent through its managed IdentityAgent setting, even in
an existing terminal. Quit and reopen your terminal to update other programs
that use SSH_AUTH_SOCK directly (including ssh-add).
SSH will automatically add keys it loads to the agent with confirmation required
for subsequent agent use. No manual SSH configuration or ssh-add step is needed.
Run "ssh-key-control doctor" to check everything.
`)
	return nil
}

func (a *App) uninstall(ctx context.Context, args []string) error {
	if err := noArgs("uninstall", args); err != nil {
		return err
	}
	inst, err := a.installer()
	if err != nil {
		return err
	}
	if err := inst.Uninstall(ctx); err != nil {
		return err
	}
	if err := agent.RemoveSocket((sshconfig.ManagedConfig{Path: a.SSHConfig}).SocketPath()); err != nil {
		return fmt.Errorf("removing SSH agent socket link: %w", err)
	}
	fmt.Fprintf(a.Stdout, "Launch agent %s removed; the login session uses the system ssh-agent again.\nManaged SSH confirmation settings removed; other settings and backups retained.\nRemembered passphrases stay in the keychain; \"ssh-key-control forget <account>\" deletes them.\n", agent.Label)
	return nil
}

func (a *App) status(ctx context.Context, args []string) error {
	jsonOutput := len(args) == 1 && args[0] == "--json"
	if err := noArgs("status", args); err != nil && !jsonOutput {
		return err
	}
	inst, err := a.installer()
	if err != nil {
		return err
	}
	st, err := inst.Status(ctx)
	if err != nil {
		return err
	}
	if jsonOutput {
		pid := 0
		if st.Service != nil {
			pid = st.Service.PID
		}
		menuPID := 0
		if st.CompanionService != nil {
			menuPID = st.CompanionService.PID
		}
		return json.NewEncoder(a.Stdout).Encode(struct {
			Running                 bool  `json:"running"`
			Installed               bool  `json:"installed"`
			PID                     int   `json:"pid"`
			MenuRunning             bool  `json:"menu_running"`
			MenuConfigured          bool  `json:"menu_configured"`
			MenuPID                 int   `json:"menu_pid"`
			MenuExecutableAvailable *bool `json:"menu_executable_available"`
		}{st.Running(), st.PlistExists, pid, st.CompanionRunning(), st.CompanionPlistExists, menuPID, st.CompanionExecutableAvailable})
	}
	w := a.Stdout
	fmt.Fprintf(w, "agent:    %s\n", agent.Label)
	fmt.Fprintf(w, "plist:    %s (%s)\n", st.PlistPath, presence(st.PlistExists))
	switch {
	case st.Service == nil:
		fmt.Fprintf(w, "service:  not loaded\n")
	case st.Running():
		fmt.Fprintf(w, "service:  running, pid %d\n", st.Service.PID)
	default:
		fmt.Fprintf(w, "service:  loaded, %s (last exit code %s)\n", st.Service.State, orDash(st.Service.LastExitCode))
	}
	if st.Service != nil && len(st.Service.Arguments) > 0 {
		fmt.Fprintf(w, "program:  %s\n", st.Service.Arguments[0])
	}
	fmt.Fprintf(w, "socket:   %s\n", orDash(st.Socket()))
	fmt.Fprintf(w, "menu plist: %s (%s)\n", st.CompanionPlistPath, presence(st.CompanionPlistExists))
	switch {
	case st.CompanionService == nil:
		fmt.Fprintln(w, "menu:     not supervised")
	case st.CompanionRunning():
		fmt.Fprintf(w, "menu:     running, pid %d\n", st.CompanionService.PID)
	default:
		fmt.Fprintf(w, "menu:     deliberately stopped or waiting, %s (last exit code %s)\n", st.CompanionService.State, orDash(st.CompanionService.LastExitCode))
	}
	if st.CompanionExecutable != "" {
		availability := "missing"
		if st.CompanionExecutableAvailable != nil && *st.CompanionExecutableAvailable {
			availability = "present"
		}
		fmt.Fprintf(w, "menu executable: %s (%s)\n", st.CompanionExecutable, availability)
	} else if st.CompanionPlistExists {
		fmt.Fprintln(w, "menu executable: unavailable (configured path could not be verified)")
	}
	fmt.Fprintf(w, "login session:\n")
	for _, key := range []string{agent.EnvAuthSock, agent.EnvAskpass, agent.EnvRequire} {
		fmt.Fprintf(w, "  %-20s %s\n", key, orDash(st.Session[key]))
	}
	return nil
}

func presence(exists bool) string {
	if exists {
		return "present"
	}
	return "missing"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// doctor prints one line per check and fails when anything is broken.
func (a *App) doctor(ctx context.Context, args []string) int {
	if err := noArgs("doctor", args); err != nil {
		return a.exit(err)
	}
	inst, err := a.installer()
	if err != nil {
		return a.exit(err)
	}
	r := &report{w: a.Stdout}

	exe, err := a.Executable()
	if err != nil {
		return a.exit(err)
	}
	if path, err := a.LocateHelper(); err == nil {
		r.ok("UI helper: %s", path)
	} else {
		r.fail("%v", err)
	}

	st, err := inst.Status(ctx)
	if err != nil {
		return a.exit(err)
	}
	if st.PlistExists {
		r.ok("plist: %s", st.PlistPath)
	} else {
		r.fail("plist missing: %s; run \"ssh-key-control install\"", st.PlistPath)
	}
	switch {
	case st.Service == nil:
		r.fail("launch agent %s is not loaded; run \"ssh-key-control install\"", agent.Label)
	case !st.Running():
		r.fail("launch agent %s is loaded but %s (last exit code %s)", agent.Label, st.Service.State, orDash(st.Service.LastExitCode))
	default:
		r.ok("launch agent %s is running (pid %d)", agent.Label, st.Service.PID)
		if prog := st.Service.Arguments; len(prog) > 0 && prog[0] != exe {
			r.warn("the agent runs %s, this program is %s; run \"ssh-key-control install\" again", prog[0], exe)
		}
	}
	if st.Running() {
		if st.Exported() {
			r.ok("login session: SSH_AUTH_SOCK is the agent's socket %s", st.Socket())
		} else {
			r.fail("login session: SSH_AUTH_SOCK is %s, expected %s", orDash(st.Session[agent.EnvAuthSock]), st.Socket())
		}
		if v := st.Session[agent.EnvAskpass]; v == exe {
			r.ok("login session: SSH_ASKPASS is %s", v)
		} else {
			r.warn("login session: SSH_ASKPASS is %s, expected %s", orDash(v), exe)
		}
		if v := st.Session[agent.EnvRequire]; agent.ValidRequire(v) {
			r.ok("login session: SSH_ASKPASS_REQUIRE is %s", v)
		} else {
			r.warn("login session: SSH_ASKPASS_REQUIRE is %s, expected force or prefer", orDash(v))
		}
		if v := a.Getenv(agent.EnvAuthSock); v == st.Socket() {
			r.ok("this shell: SSH_AUTH_SOCK is the agent's socket")
		} else {
			r.warn("this shell: SSH_AUTH_SOCK is %s; it was started before the agent, open a new terminal", orDash(v))
		}
		if v := a.Getenv(agent.EnvAskpass); v != exe {
			r.warn("this shell: SSH_ASKPASS is %s; open a new terminal", orDash(v))
		}
	}

	if a.SSHConfig != "" {
		ws, err := sshconfig.CheckFile(a.SSHConfig)
		switch {
		case err != nil:
			r.warn("%v", err)
		case len(ws) == 0:
			r.ok("%s: nothing in the way", a.SSHConfig)
		default:
			for _, w := range ws {
				r.warn("%s: %s", a.SSHConfig, w)
			}
		}
	}
	if r.failed {
		return ExitFailure
	}
	return ExitOK
}

type report struct {
	w      io.Writer
	failed bool
}

func (r *report) ok(format string, args ...any)   { fmt.Fprintf(r.w, "ok    "+format+"\n", args...) }
func (r *report) warn(format string, args ...any) { fmt.Fprintf(r.w, "warn  "+format+"\n", args...) }
func (r *report) fail(format string, args ...any) {
	r.failed = true
	fmt.Fprintf(r.w, "FAIL  "+format+"\n", args...)
}

func (a *App) forget(ctx context.Context, accounts []string) error {
	if len(accounts) == 0 {
		return &usageError{"forget needs at least one account"}
	}
	path, err := a.LocateHelper()
	if err != nil {
		return err
	}
	h, err := a.StartHelper(ctx, path)
	if err != nil {
		return err
	}
	defer h.Close()
	var errs []error
	for _, account := range accounts {
		switch err := h.Delete(ctx, account); {
		case err == nil:
			fmt.Fprintf(a.Stdout, "Forgot %s.\n", account)
		case errors.Is(err, ui.ErrNotFound):
			fmt.Fprintf(a.Stdout, "Nothing remembered for %s.\n", account)
		default:
			errs = append(errs, fmt.Errorf("%s: %w", account, err))
		}
	}
	return errors.Join(errs...)
}

func (a *App) agent(ctx context.Context, args []string) error {
	if err := noArgs(agent.Command, args); err != nil {
		return err
	}
	if a.SSHConfig == "" {
		return errors.New("cannot determine the home directory")
	}
	if a.Getenv(agent.SocketKey) == "" {
		return fmt.Errorf("%s is not set: agent must be started by launchd", agent.SocketKey)
	}
	listener, err := a.ActivateSocket(agent.SocketName)
	if err != nil {
		return err
	}
	defer listener.Close()
	// This journal is observational: it is never read to authorize a request.
	var journal *history.Store
	if a.HistoryDir != "" {
		journal = history.New(a.HistoryDir, time.Now)
	}
	record := func(event history.Event) {
		if journal == nil {
			return
		}
		if err := journal.Record(event); err != nil {
			log.New(a.Stderr, "ssh-key-control history: ", 0).Print(err)
		}
	}
	record(history.Event{Kind: "agent", Outcome: "started"})
	authorizer := confirmation.NewWithObserver(approvalDialogs{app: a}, time.Now, func(d confirmation.Decision) {
		record(history.Event{Kind: "decision", Outcome: d.Outcome, Source: d.Source,
			KeyFingerprint: d.KeyFingerprint, HostFingerprint: d.HostFingerprint, User: d.User,
			Scope: d.Scope, ExpiresAt: d.ExpiresAt,
			Process: d.Process, ProcessPID: d.ProcessPID, ProcessVersion: d.ProcessVersion})
	})
	management := &temporaryDecisionManager{app: a, authorizer: authorizer, ctx: ctx}
	protected := agent.NewProtectedWithManagement(func(ctx context.Context, req agent.SigningRequest) (bool, error) {
		var destination *confirmation.Destination
		if req.HostKey != "" && req.User != "" {
			destination = &confirmation.Destination{
				Host: confirmation.KnownHostNames(req.HostKey, filepath.Join(filepath.Dir(a.SSHConfig), "known_hosts"), a.SSHConfig),
				User: req.User, HostKey: req.HostKey,
			}
		}
		return authorizer.Authorize(ctx, req.Fingerprint, req.Comment, destination, req.Caller)
	}, management.open)
	return agent.Run(ctx, agent.Runtime{
		SocketLink: (sshconfig.ManagedConfig{Path: a.SSHConfig}).SocketPath(),
		Getenv:     a.Getenv,
		Serve: func(ctx context.Context) error {
			monitorContext, stopMonitor := context.WithCancel(ctx)
			monitorDone := make(chan struct{})
			go func() {
				defer close(monitorDone)
				a.runNativeMonitor(monitorContext, []string{listener.Addr().String(), a.Getenv(agent.SocketKey), (sshconfig.ManagedConfig{Path: a.SSHConfig}).SocketPath()}, record)
			}()
			defer func() { stopMonitor(); <-monitorDone }()
			return agent.ServeListener(ctx, listener, protected)
		},
		Launchctl: a.Launchctl,
		Log:       log.New(a.Stderr, "ssh-key-control agent: ", 0),
	})
}
