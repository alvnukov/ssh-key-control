package helper

import (
	"context"
	"errors"

	"github.com/alvnukov/ssh-key-control/internal/ui"
)

func (c *Client) ManageDecisions(ctx context.Context, decisions []ui.TemporaryDecision, message string, activate bool) (ui.DecisionChange, error) {
	if err := ctx.Err(); err != nil {
		return ui.DecisionChange{}, err
	}
	resp, err := c.call(request{Op: "manage-decisions", Decisions: decisions, Message: message, Activate: activate})
	if err != nil {
		return ui.DecisionChange{}, err
	}
	if resp.Change == nil || resp.Answer != "" || resp.Remember || resp.Scope != nil || resp.DurationMinutes != nil || resp.Boundary != nil {
		return ui.DecisionChange{}, errors.New("helper returned an invalid management action")
	}
	change := *resp.Change
	switch change.Action {
	case "close", "refresh":
		if change.ID != "" || change.Minutes != 0 || change.EndOfDay {
			return ui.DecisionChange{}, errors.New("management action has unexpected fields")
		}
	// Revoking by process still names one row. Which other rows go with it is
	// the agent's answer, from the anchor it stored, not the window's.
	case "revoke", "revoke-process", "update":
		if change.ID == "" || len(change.ID) > 128 {
			return ui.DecisionChange{}, errors.New("management action needs an existing decision ID")
		}
	default:
		return ui.DecisionChange{}, errors.New("helper returned an unknown management action")
	}
	return change, nil
}
