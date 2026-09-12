package launchd

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const SystemAgentLabel = "com.openssh.ssh-agent"
const systemAgentPlist = "/System/Library/LaunchAgents/com.openssh.ssh-agent.plist"

// SystemAgentState distinguishes a persistent launch prohibition from removal
// of an already loaded job. SIP may permit the former but reject the latter.
type SystemAgentState struct {
	Disabled       bool `json:"disabled"`
	Loaded         bool `json:"loaded"`
	Running        bool `json:"running"`
	RequiresLogout bool `json:"requiresLogout"`
}

func systemAgentDisabled(output string) (bool, error) {
	if len(output) > 65536 || !strings.Contains(output, "disabled services = {") {
		return false, errors.New("unrecognized launchctl disabled-services response")
	}
	found, disabled := false, false
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=>")
		if !ok || strings.TrimSpace(key) != `"com.openssh.ssh-agent"` {
			continue
		}
		if found {
			return false, errors.New("duplicate system agent disabled state")
		}
		found = true
		switch strings.TrimSpace(value) {
		case "disabled", "true":
			disabled = true
		case "enabled", "false":
			disabled = false
		default:
			return false, errors.New("unknown system agent disabled state")
		}
	}
	return disabled, nil
}

func (c Client) SystemAgentStatus(ctx context.Context) (*SystemAgentState, error) {
	out, err := c.Runner.Run(ctx, "print-disabled", string(c.Domain))
	if err != nil {
		return nil, err
	}
	disabled, err := systemAgentDisabled(out)
	if err != nil {
		return nil, err
	}
	service, err := c.Print(ctx, SystemAgentLabel)
	if err != nil && !errors.Is(err, ErrNotLoaded) {
		return nil, err
	}
	state := &SystemAgentState{Disabled: disabled, Loaded: service != nil}
	state.Running = service != nil && service.Running()
	state.RequiresLogout = state.Disabled == state.Loaded
	return state, nil
}

// SetSystemAgentDisabled changes only Apple's service in this user's domain.
// It never kills processes by name, changes SIP, or modifies system files.
func (c Client) SetSystemAgentDisabled(ctx context.Context, disabled bool) (*SystemAgentState, error) {
	before, err := c.SystemAgentStatus(ctx)
	if err != nil {
		return nil, err
	}
	action := "enable"
	if disabled {
		action = "disable"
	}
	if before.Disabled != disabled {
		if _, err := c.Runner.Run(ctx, action, c.Domain.Service(SystemAgentLabel)); err != nil {
			return nil, err
		}
	}
	state, err := c.SystemAgentStatus(ctx)
	if err != nil {
		return nil, err
	}
	if state.Disabled != disabled {
		return nil, errors.New("launchctl did not apply the requested system agent setting")
	}
	if disabled && state.Loaded {
		err = c.Bootout(ctx, SystemAgentLabel)
	} else if !disabled && !state.Loaded {
		err = c.Bootstrap(ctx, systemAgentPlist)
	}
	// macOS 26 protects bootout of this system job with SIP (exit 150).
	// Keep the requested startup policy, report actual state, and require
	// logout instead of pretending the running job has been stopped.
	if err != nil && !errors.Is(err, ErrNotLoaded) && exitCode(err) != 150 {
		return nil, fmt.Errorf("startup setting changed, but applying it to the current session failed: %w", err)
	}
	state, statusErr := c.SystemAgentStatus(ctx)
	if statusErr != nil {
		return nil, statusErr
	}
	if !disabled && !state.Loaded {
		state.RequiresLogout = true
	}
	return state, nil
}
