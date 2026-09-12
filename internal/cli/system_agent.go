package cli

import (
	"context"
	"encoding/json"
)

// Kept as a read-only compatibility command. Monitoring never changes Apple's
// startup policy; legacy disable/enable requests are deliberately unsupported.
func (a *App) systemAgent(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] != "status" {
		return &usageError{"system-agent only supports status; use native-agent-monitor enable|disable to control monitoring"}
	}
	state, err := a.Launchctl.SystemAgentStatus(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(a.Stdout).Encode(state)
}
