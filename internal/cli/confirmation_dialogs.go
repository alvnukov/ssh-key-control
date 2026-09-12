package cli

import (
	"context"

	"github.com/alvnukov/ssh-key-control/internal/ui"
	"github.com/alvnukov/ssh-key-control/internal/ui/helper"
)

// approvalDialogs starts the UI only when an uncached signature needs approval.
// The long-running agent, not the helper subprocess, owns approval lifetimes.
type approvalDialogs struct{ app *App }

func (d approvalDialogs) Confirm(ctx context.Context, req ui.ConfirmRequest) (bool, error) {
	req.Destination = ""
	answer, err := d.ConfirmScoped(ctx, req)
	return answer.Allowed, err
}

func (d approvalDialogs) ConfirmScoped(ctx context.Context, req ui.ConfirmRequest) (ui.Confirmation, error) {
	// The signing gate must not accept a helper from the environment.
	path, err := helper.LocateInstalled()
	if err != nil {
		return ui.Confirmation{}, err
	}
	helper, err := d.app.StartHelper(ctx, path)
	if err != nil {
		return ui.Confirmation{}, err
	}
	defer helper.Close()
	if scoped, ok := helper.(ui.ScopedDialogs); ok {
		return scoped.ConfirmScoped(ctx, req)
	}
	allowed, err := helper.Confirm(ctx, req)
	return ui.Confirmation{Allowed: allowed, Scope: ui.GrantOnce}, err
}
