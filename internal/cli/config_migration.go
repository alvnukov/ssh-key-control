package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/alvnukov/ssh-key-control/internal/sshconfig"
)

type configMigrationStatus struct {
	State      string `json:"state"`
	Path       string `json:"path"`
	BackupPath string `json:"backup_path,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

func (a *App) configMigration(args []string) error {
	if len(args) != 1 || args[0] != "--json" {
		return &usageError{"config-migration requires --json"}
	}
	managed := sshconfig.ManagedConfig{Path: a.SSHConfig}
	status := configMigrationStatus{State: "none", Path: a.SSHConfig}
	needed, err := managed.LegacyMigrationNeeded()
	if err != nil {
		status.State = "unknown"
		status.Detail = err.Error()
	} else if needed {
		status.State = "legacy"
		status.BackupPath = managed.MigrationBackupPath()
	} else if installed, installErr := managed.Installed(); installErr != nil {
		status.State = "unknown"
		status.Detail = installErr.Error()
	} else if installed {
		status.State = "current"
	}
	return json.NewEncoder(a.Stdout).Encode(status)
}

func (a *App) migrateConfig(ctx context.Context, args []string) error {
	if err := noArgs("migrate-config", args); err != nil {
		return err
	}
	managed := sshconfig.ManagedConfig{Path: a.SSHConfig}
	if err := managed.MigrateLegacy(); err != nil {
		return fmt.Errorf("migrating previous managed SSH settings: %w", err)
	}
	if err := a.repair(ctx, nil); err != nil {
		return fmt.Errorf("SSH settings were updated and backed up at %s, but setup is not healthy yet: %w", managed.MigrationBackupPath(), err)
	}
	fmt.Fprintf(a.Stdout, "Previous managed SSH settings updated. Backup retained at %s.\n", managed.MigrationBackupPath())
	return nil
}
