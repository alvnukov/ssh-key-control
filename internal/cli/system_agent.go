package cli

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/alvnukov/ssh-key-control/internal/agent"
	"github.com/alvnukov/ssh-key-control/internal/launchd"
)

func (a *App) systemAgent(ctx context.Context, args []string) error {
	if len(args) != 1 || (args[0] != "status" && args[0] != "disable" && args[0] != "enable") {
		return &usageError{"system-agent requires status, disable or enable"}
	}
	var state *launchd.SystemAgentState
	var err error
	switch args[0] {
	case "status":
		state, err = a.Launchctl.SystemAgentStatus(ctx)
	case "disable":
		// Do not remove the normal agent before our replacement is running.
		service, queryErr := a.Launchctl.Print(ctx, agent.Label)
		if queryErr != nil || service == nil || !service.Running() {
			return errors.New("start the protected SSH Key Control agent before disabling the system agent")
		}
		state, err = a.Launchctl.SetSystemAgentDisabled(ctx, true)
	case "enable":
		state, err = a.Launchctl.SetSystemAgentDisabled(ctx, false)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(a.Stdout).Encode(state)
}
