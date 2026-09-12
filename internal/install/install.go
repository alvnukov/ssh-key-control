// Package install registers the launch agent for the current user, removes
// it again and reports its state. Nothing here needs root: the plist lives
// in ~/Library/LaunchAgents and the service in the user's GUI domain.
package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/agent"
	"github.com/alvnukov/ssh-key-control/internal/launchd"
)

// AppleAgentLabel is the system ssh-agent whose socket is restored on uninstall.
const AppleAgentLabel = "com.openssh.ssh-agent"

// CompanionLabel is the launchd job that owns the menu bar application.
const CompanionLabel = "io.github.alvnukov.ssh-key-control.menubar"

// FS is the part of the file system the installer touches.
type FS interface {
	MkdirAll(path string, perm os.FileMode) error
	WriteFile(path string, data []byte, perm os.FileMode) error
	Remove(path string) error
	Stat(path string) (os.FileInfo, error)
}

// OSFS is the real file system.
type OSFS struct{}

func (OSFS) MkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (OSFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}
func (OSFS) Remove(path string) error              { return os.Remove(path) }
func (OSFS) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }

// SSHConfig manages the installer's owned SSH settings without replacing
// unrelated user configuration.
type SSHConfig interface {
	Install() error
	CheckUninstall() error
	Uninstall() error
}

// Installer holds what every operation needs.
type Installer struct {
	Launchctl launchd.Client
	FS        FS
	// PlistDir is where the plist goes, normally ~/Library/LaunchAgents.
	PlistDir string
	// SSHConfig configures automatic key confirmation; nil is for service-only callers.
	SSHConfig SSHConfig
	// Sleep pauses while waiting for launchd; tests replace it.
	Sleep func(time.Duration)
}

// DefaultPlistDir is the per-user launch agent directory.
func DefaultPlistDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents"), nil
}

// PlistPath is where the launch agent's plist is written.
func (i *Installer) PlistPath() string {
	return filepath.Join(i.PlistDir, agent.Label+".plist")
}

// CompanionPlistPath is where menu bar supervision is registered.
func (i *Installer) CompanionPlistPath() string {
	return filepath.Join(i.PlistDir, CompanionLabel+".plist")
}

// StopCompanion ends launchd supervision for the current menu process. The
// persisted plist remains available for the next login or explicit repair.
func (i *Installer) StopCompanion(ctx context.Context) error {
	err := i.Launchctl.Bootout(ctx, CompanionLabel)
	if errors.Is(err, launchd.ErrNotLoaded) {
		return nil
	}
	return err
}

// Result is what Install reports back.
type Result struct {
	PlistPath string
	// Socket is the agent socket launchd created.
	Socket string
	// PID is the running ssh-agent.
	PID int
	// Exported reports whether SSH_AUTH_SOCK in the login session already
	// points at Socket, that is, whether the agent's own setup ran.
	Exported bool
	// CompanionManaged reports that launchd owns the menu bar process.
	CompanionManaged bool
}

// Install writes the plist, (re)loads the service and waits for the agent.
func (i *Installer) Install(ctx context.Context, exe, require string) (*Result, error) {
	if !filepath.IsAbs(exe) {
		return nil, fmt.Errorf("executable path must be absolute: %s", exe)
	}
	if !agent.ValidRequire(require) {
		return nil, fmt.Errorf("SSH_ASKPASS_REQUIRE must be %q or %q, not %q", agent.RequireForce, agent.RequirePrefer, require)
	}
	data, err := agent.Job(exe, require).MarshalPlist()
	if err != nil {
		return nil, err
	}
	companion, err := i.companionExecutable(exe)
	if err != nil {
		return nil, err
	}
	var companionData []byte
	if companion != "" {
		companionData, err = (launchd.Job{
			Label:              CompanionLabel,
			ProgramArguments:   []string{companion, "--managed"},
			RunAtLoad:          true,
			KeepAliveOnFailure: true,
			ThrottleInterval:   10,
		}).MarshalPlist()
		if err != nil {
			return nil, err
		}
	}
	if i.SSHConfig != nil {
		if err := i.SSHConfig.Install(); err != nil {
			return nil, fmt.Errorf("configuring SSH confirmation: %w", err)
		}
	}
	if err := i.FS.MkdirAll(i.PlistDir, 0o755); err != nil {
		return nil, err
	}
	path := i.PlistPath()
	if err := i.FS.WriteFile(path, data, 0o644); err != nil {
		return nil, err
	}
	if companion != "" {
		if err := i.FS.WriteFile(i.CompanionPlistPath(), companionData, 0o644); err != nil {
			return nil, err
		}
		if err := i.Launchctl.Bootout(ctx, CompanionLabel); err != nil && !errors.Is(err, launchd.ErrNotLoaded) {
			return nil, fmt.Errorf("unloading the previous menu bar application: %w", err)
		}
	}
	if err := i.Launchctl.Bootout(ctx, agent.Label); err != nil && !errors.Is(err, launchd.ErrNotLoaded) {
		return nil, fmt.Errorf("unloading the previous agent: %w", err)
	}
	if err := i.Launchctl.Bootstrap(ctx, path); err != nil {
		return nil, fmt.Errorf("loading %s: %w", path, err)
	}
	if companion != "" {
		if err := i.Launchctl.Bootstrap(ctx, i.CompanionPlistPath()); err != nil {
			return nil, fmt.Errorf("loading menu bar application: %w", err)
		}
	}
	svc, err := i.waitRunning(ctx, agent.Label)
	if err != nil {
		return nil, err
	}
	if companion != "" {
		if _, err := i.waitRunning(ctx, CompanionLabel); err != nil {
			return nil, err
		}
	}
	res := &Result{PlistPath: path, Socket: svc.Sockets[agent.SocketName].Path, PID: svc.PID, CompanionManaged: companion != ""}
	if res.Socket == "" {
		return nil, fmt.Errorf("launchd did not create the %s socket for %s", agent.SocketName, agent.Label)
	}
	// The agent runs launchctl setenv right after it starts; give it a moment.
	for attempt := 0; attempt < 25; attempt++ {
		sock, err := i.Launchctl.Getenv(ctx, agent.EnvAuthSock)
		if err != nil {
			return nil, err
		}
		if sock == res.Socket {
			res.Exported = true
			break
		}
		i.Sleep(200 * time.Millisecond)
	}
	return res, nil
}

func (i *Installer) companionExecutable(exe string) (string, error) {
	macOSDir := filepath.Dir(exe)
	contentsDir := filepath.Dir(macOSDir)
	bundle := filepath.Dir(contentsDir)
	home := filepath.Dir(filepath.Dir(i.PlistDir))
	if filepath.Base(exe) != "ssh-key-control" || filepath.Base(macOSDir) != "MacOS" ||
		filepath.Base(contentsDir) != "Contents" || filepath.Ext(bundle) != ".app" {
		return "", nil
	}
	parent := filepath.Dir(bundle)
	if parent != "/Applications" && parent != filepath.Join(home, "Applications") {
		return "", fmt.Errorf("application bundle must be installed in /Applications or %s", filepath.Join(home, "Applications"))
	}
	companion := filepath.Join(macOSDir, "ssh-key-control-menubar")
	if _, err := i.FS.Stat(companion); err != nil {
		return "", fmt.Errorf("menu bar executable %s is unavailable: %w", companion, err)
	}
	return companion, nil
}

// waitRunning polls launchd until the service has a process.
func (i *Installer) waitRunning(ctx context.Context, label string) (*launchd.Service, error) {
	var last *launchd.Service
	for attempt := 0; attempt < 25; attempt++ {
		svc, err := i.Launchctl.Print(ctx, label)
		if err != nil {
			return nil, err
		}
		if svc.Running() {
			return svc, nil
		}
		last = svc
		i.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("%s did not start (state %q, last exit code %s)", label, last.State, orDash(last.LastExitCode))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Uninstall unloads the service, deletes the plist and returns the login
// session to the system ssh-agent.
func (i *Installer) Uninstall(ctx context.Context) error {
	// Validate config before external probes; an edited ownership block is
	// never changed, regardless of the state of either service.
	if i.SSHConfig != nil {
		if err := i.SSHConfig.CheckUninstall(); err != nil {
			return fmt.Errorf("checking SSH confirmation settings: %w", err)
		}
	}
	// Removing our routing must not depend on or mutate Apple's startup policy.
	if i.SSHConfig != nil {
		if err := i.SSHConfig.Uninstall(); err != nil {
			return fmt.Errorf("removing SSH confirmation settings: %w", err)
		}
	}
	var errs []error
	if err := i.Launchctl.Bootout(ctx, agent.Label); err != nil && !errors.Is(err, launchd.ErrNotLoaded) {
		errs = append(errs, fmt.Errorf("unloading the agent: %w", err))
	}
	if err := i.FS.Remove(i.PlistPath()); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	if err := i.FS.Remove(i.CompanionPlistPath()); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	for _, key := range []string{agent.EnvAskpass, agent.EnvRequire} {
		if err := i.Launchctl.Unsetenv(ctx, key); err != nil {
			errs = append(errs, err)
		}
	}
	if err := i.restoreAppleSocket(ctx); err != nil {
		errs = append(errs, err)
	}
	// Stop the menu last: when uninstall is launched from the supervised app,
	// bootout terminates that parent process. SSH state must already be safe.
	if err := i.Launchctl.Bootout(ctx, CompanionLabel); err != nil && !errors.Is(err, launchd.ErrNotLoaded) {
		errs = append(errs, fmt.Errorf("unloading the menu bar application: %w", err))
	}
	return errors.Join(errs...)
}

// restoreAppleSocket points SSH_AUTH_SOCK back at the system agent, whose
// socket path launchd reports under its Listeners socket.
func (i *Installer) restoreAppleSocket(ctx context.Context) error {
	svc, err := i.Launchctl.Print(ctx, AppleAgentLabel)
	if err != nil && !errors.Is(err, launchd.ErrNotLoaded) {
		return err
	}
	if svc != nil {
		if path := svc.Sockets[agent.SocketName].Path; path != "" {
			return i.Launchctl.Setenv(ctx, agent.EnvAuthSock, path)
		}
	}
	return i.Launchctl.Unsetenv(ctx, agent.EnvAuthSock)
}

// Status is the observable state of the installation.
type Status struct {
	PlistPath            string
	PlistExists          bool
	CompanionPlistPath   string
	CompanionPlistExists bool
	// Service is nil when launchd does not know the label.
	Service          *launchd.Service
	CompanionService *launchd.Service
	// CompanionExecutable and its availability are known when launchd reports
	// the configured program. Availability is nil when it cannot be determined.
	CompanionExecutable          string
	CompanionExecutableAvailable *bool
	// Session holds SSH_AUTH_SOCK, SSH_ASKPASS and SSH_ASKPASS_REQUIRE of the login session.
	Session map[string]string
}

// Socket is the agent's socket, "" when it is not loaded.
func (s *Status) Socket() string {
	if s.Service == nil {
		return ""
	}
	return s.Service.Sockets[agent.SocketName].Path
}

// Running reports whether the agent process is up.
func (s *Status) Running() bool {
	return s.Service != nil && s.Service.Running()
}

// CompanionRunning reports whether launchd currently owns the menu bar process.
func (s *Status) CompanionRunning() bool {
	return s.CompanionService != nil && s.CompanionService.Running()
}

// Exported reports whether new processes in the login session will reach this agent.
func (s *Status) Exported() bool {
	return s.Running() && s.Session[agent.EnvAuthSock] == s.Socket()
}

// Status gathers the state without changing anything.
func (i *Installer) Status(ctx context.Context) (*Status, error) {
	st := &Status{PlistPath: i.PlistPath(), CompanionPlistPath: i.CompanionPlistPath(), Session: map[string]string{}}
	if _, err := i.FS.Stat(st.PlistPath); err == nil {
		st.PlistExists = true
	}
	if _, err := i.FS.Stat(st.CompanionPlistPath); err == nil {
		st.CompanionPlistExists = true
	}
	svc, err := i.Launchctl.Print(ctx, agent.Label)
	if err != nil && !errors.Is(err, launchd.ErrNotLoaded) {
		return nil, err
	}
	st.Service = svc
	companion, err := i.Launchctl.Print(ctx, CompanionLabel)
	if err != nil && !errors.Is(err, launchd.ErrNotLoaded) {
		return nil, err
	}
	st.CompanionService = companion
	if companion != nil && len(companion.Arguments) > 0 {
		st.CompanionExecutable = companion.Arguments[0]
		_, statErr := i.FS.Stat(st.CompanionExecutable)
		available := statErr == nil
		if statErr != nil && !os.IsNotExist(statErr) {
			return nil, statErr
		}
		st.CompanionExecutableAvailable = &available
	}
	for _, key := range []string{agent.EnvAuthSock, agent.EnvAskpass, agent.EnvRequire} {
		v, err := i.Launchctl.Getenv(ctx, key)
		if err != nil {
			return nil, err
		}
		st.Session[key] = v
	}
	return st, nil
}
