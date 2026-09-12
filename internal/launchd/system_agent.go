package launchd

import (
	"context"
	"errors"
	"strings"
)

const SystemAgentLabel = "com.openssh.ssh-agent"
const systemAgentPlist = "/System/Library/LaunchAgents/com.openssh.ssh-agent.plist"

// SystemAgentState reports the current system job without changing its policy.
type SystemAgentState struct {
	Disabled bool `json:"disabled"`
	Loaded   bool `json:"loaded"`
	Running  bool `json:"running"`
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
	return state, nil
}
