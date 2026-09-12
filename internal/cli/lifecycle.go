package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alvnukov/ssh-key-control/internal/sshconfig"
)

// lifecycleHealth is the bounded, read-only startup contract consumed by the GUI.
type lifecycleHealth struct {
	Healthy       bool   `json:"healthy"`
	AgentReady    bool   `json:"agent_ready"`
	AgentOwned    bool   `json:"agent_owned"`
	SocketReady   bool   `json:"socket_ready"`
	SSHConfigured bool   `json:"ssh_configured"`
	MenuManaged   bool   `json:"menu_managed"`
	MenuOwned     bool   `json:"menu_owned"`
	Detail        string `json:"detail,omitempty"`
}

func (a *App) lifecycle(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] != "--json" {
		return &usageError{"lifecycle requires --json"}
	}
	health, err := a.lifecycleHealth(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(a.Stdout).Encode(health)
}

func (a *App) lifecycleHealth(ctx context.Context) (*lifecycleHealth, error) {
	inst, err := a.installer()
	if err != nil {
		return nil, err
	}
	exe, err := a.Executable()
	if err != nil {
		return nil, err
	}
	st, err := inst.Status(ctx)
	if err != nil {
		return nil, err
	}
	h := &lifecycleHealth{
		AgentReady:  st.Running(),
		MenuManaged: st.CompanionRunning(),
	}
	if st.Service != nil && len(st.Service.Arguments) > 0 {
		h.AgentOwned = st.Service.Arguments[0] == exe
	}
	expectedMenu := filepath.Join(filepath.Dir(exe), "ssh-key-control-menubar")
	h.MenuOwned = st.CompanionExecutable == expectedMenu
	managed := sshconfig.ManagedConfig{Path: a.SSHConfig}
	h.SSHConfigured, err = managed.Installed()
	if err != nil {
		return nil, fmt.Errorf("checking managed SSH settings: %w", err)
	}
	if st.Exported() {
		target, readErr := os.Readlink(managed.SocketPath())
		if readErr == nil {
			h.SocketReady = target == st.Socket()
		} else if !os.IsNotExist(readErr) {
			return nil, fmt.Errorf("checking published SSH agent socket: %w", readErr)
		}
	}
	h.Healthy = h.AgentReady && h.AgentOwned && h.SocketReady && h.SSHConfigured && h.MenuManaged && h.MenuOwned
	if !h.Healthy {
		h.Detail = "SSH Key Control setup is incomplete or its registered processes are not ready"
	}
	return h, nil
}

func (a *App) repair(ctx context.Context, args []string) error {
	if err := noArgs("repair", args); err != nil {
		return err
	}
	if err := a.install(ctx, nil); err != nil {
		return err
	}
	health, err := a.lifecycleHealth(ctx)
	if err != nil {
		return err
	}
	if !health.Healthy {
		return fmt.Errorf("repair completed but startup health is still incomplete (agent ready=%t, owned=%t, socket=%t, SSH config=%t, menu managed=%t, menu owned=%t)",
			health.AgentReady, health.AgentOwned, health.SocketReady, health.SSHConfigured, health.MenuManaged, health.MenuOwned)
	}
	return nil
}

func (a *App) stopMenu(ctx context.Context, args []string) error {
	if err := noArgs("stop-menu", args); err != nil {
		return err
	}
	inst, err := a.installer()
	if err != nil {
		return err
	}
	return inst.StopCompanion(ctx)
}
